package dev.sbomscope.export;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Set;

import org.apache.poi.common.usermodel.HyperlinkType;
import org.apache.poi.ss.usermodel.BorderStyle;
import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.CellStyle;
import org.apache.poi.ss.usermodel.CreationHelper;
import org.apache.poi.ss.usermodel.FillPatternType;
import org.apache.poi.ss.usermodel.Font;
import org.apache.poi.ss.usermodel.Hyperlink;
import org.apache.poi.ss.usermodel.IndexedColors;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.ss.usermodel.Sheet;
import org.apache.poi.ss.usermodel.Workbook;
import org.apache.poi.ss.util.CellRangeAddress;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.springframework.stereotype.Component;

import dev.sbomscope.diff.DiffRow;
import dev.sbomscope.diff.DiffRow.Change;
import dev.sbomscope.diff.DiffRow.Side;
import dev.sbomscope.diff.DiffService;
import dev.sbomscope.scanner.FindingQuery;
import dev.sbomscope.scanner.FindingQuery.SeverityBand;
import dev.sbomscope.scanner.SbomSeverity;
import dev.sbomscope.sbom.StoredSbom;

/** Writes an SBOM comparison and the facts needed to account for it to a real .xlsx. */
@Component
public class DiffExcelExporter {

    private static final List<String> HEADERS = List.of(
            "Change", "Group", "Artifact", "Left version", "Right version",
            "CVEs gained", "CVEs lost", "Left findings", "Right findings");
    private static final int[] WIDTHS = {18, 28, 30, 20, 20, 36, 36, 55, 55};
    private static final DateTimeFormatter TIMESTAMP =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.systemDefault());

    /**
     * @param leftRisk  the left document's own band counts, with the scanned-component count
     *                  that qualifies them. Passed in rather than derived from the rows,
     *                  because a {@code visible} export narrows the rows and these totals
     *                  describe the documents — the same distinction the summary already draws
     */
    public byte[] export(StoredSbom left, StoredSbom right,
                         SbomSeverity leftRisk, SbomSeverity rightRisk,
                         DiffService.DiffResult comparison, boolean visibleScope,
                         String filter, boolean regex, boolean negate) throws IOException {
        return export(left, right, leftRisk, rightRisk, comparison, visibleScope,
                filter, regex, negate, DiffService.DiffSort.COORDINATES, true);
    }

    public byte[] export(StoredSbom left, StoredSbom right,
                         SbomSeverity leftRisk, SbomSeverity rightRisk,
                         DiffService.DiffResult comparison, boolean visibleScope,
                         String filter, boolean regex, boolean negate,
                         DiffService.DiffSort sort, boolean ascending) throws IOException {
        List<DiffRow> rows = visibleScope
                ? comparison.rows().stream().filter(row -> row.change() != Change.UNCHANGED).toList()
                : comparison.rows();

        try (Workbook workbook = new XSSFWorkbook();
             ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            writeComparisonSheet(workbook, rows);
            writeAboutSheet(workbook, left, right, leftRisk, rightRisk, rows.size(),
                    comparison.summary(), visibleScope, filter, regex, negate, sort, ascending);
            workbook.write(out);
            return out.toByteArray();
        }
    }

    private void writeComparisonSheet(Workbook workbook, List<DiffRow> rows) {
        Sheet sheet = workbook.createSheet("Comparison");
        CreationHelper helper = workbook.getCreationHelper();
        CellStyle headerStyle = headerStyle(workbook);
        CellStyle linkStyle = linkStyle(workbook);

        Row header = sheet.createRow(0);
        for (int index = 0; index < HEADERS.size(); index++) {
            Cell cell = header.createCell(index);
            cell.setCellValue(HEADERS.get(index));
            cell.setCellStyle(headerStyle);
            sheet.setColumnWidth(index, WIDTHS[index] * 256);
        }

        int rowIndex = 1;
        for (DiffRow entry : rows) {
            Row row = sheet.createRow(rowIndex++);
            RegistryLinks.Links leftLinks = links(entry.left());
            RegistryLinks.Links rightLinks = links(entry.right());
            String artifactUrl = leftLinks.artifactUrl() != null
                    ? leftLinks.artifactUrl() : rightLinks.artifactUrl();

            writeText(row, 0, changeLabel(entry.change()));
            writeText(row, 1, entry.group());
            writeLinked(row, 2, entry.name(), artifactUrl, helper, linkStyle);
            writeLinked(row, 3, version(entry.left()), leftLinks.versionUrl(), helper, linkStyle);
            writeLinked(row, 4, version(entry.right()), rightLinks.versionUrl(), helper, linkStyle);
            writeText(row, 5, String.join(", ", gained(entry)));
            writeText(row, 6, String.join(", ", lost(entry)));
            writeText(row, 7, findings(entry.left()));
            writeText(row, 8, findings(entry.right()));
        }

        sheet.createFreezePane(0, 1);
        if (!rows.isEmpty()) {
            sheet.setAutoFilter(new CellRangeAddress(0, rows.size(), 0, HEADERS.size() - 1));
        }
    }

    private void writeAboutSheet(Workbook workbook, StoredSbom left, StoredSbom right,
                                 SbomSeverity leftRisk, SbomSeverity rightRisk,
                                 int exportedRows, DiffService.Summary summary,
                                 boolean visibleScope, String filter, boolean regex,
                                 boolean negate, DiffService.DiffSort sort, boolean ascending) {
        Sheet sheet = workbook.createSheet("About this export");
        CellStyle labelStyle = boldStyle(workbook);
        sheet.setColumnWidth(0, 34 * 256);
        sheet.setColumnWidth(1, 90 * 256);

        int row = 0;
        row = writePair(sheet, row, labelStyle, "Left document", left.filename());
        row = writePair(sheet, row, labelStyle, "Left uploaded", TIMESTAMP.format(left.uploadedAt()));
        row = writePair(sheet, row, labelStyle, "Left id", left.id().toString());
        row = writePair(sheet, row, labelStyle, "Right document", right.filename());
        row = writePair(sheet, row, labelStyle, "Right uploaded", TIMESTAMP.format(right.uploadedAt()));
        row = writePair(sheet, row, labelStyle, "Right id", right.id().toString());
        row = writePair(sheet, row, labelStyle, "Scope", visibleScope
                ? "visible — text filter applied; unchanged rows excluded"
                : "all — text filter ignored; unchanged rows included");
        row = writePair(sheet, row, labelStyle, "Rows in this export", String.valueOf(exportedRows));
        row = writePair(sheet, row, labelStyle, "Text filter", describedFilter(filter, visibleScope));
        row = writePair(sheet, row, labelStyle, "Filter mode",
                regex ? "regular expression (case-insensitive)" : "literal (case-insensitive)");
        row = writePair(sheet, row, labelStyle, "Filter negated", negate ? "yes" : "no");
        row = writePair(sheet, row, labelStyle, "Sort",
                "%s, %s".formatted(sort == DiffService.DiffSort.COORDINATES
                        ? "Coordinates" : "Change", ascending ? "ascending" : "descending"));
        row = writePair(sheet, row, labelStyle, "Summary covers",
                "the whole comparison, not only the exported rows");
        for (Change change : Change.values()) {
            row = writePair(sheet, row, labelStyle,
                    changeLabel(change) + " (whole comparison)",
                    String.valueOf(summary.changes().getOrDefault(change, 0)));
        }
        row = writePair(sheet, row, labelStyle, "CVEs gained (whole comparison)",
                String.valueOf(summary.cveIdsGained()));
        row = writePair(sheet, row, labelStyle, "CVEs lost (whole comparison)",
                String.valueOf(summary.cveIdsLost()));

        // The same block the page shows above the table. It describes the two *documents*
        // rather than the compared rows, which is why every label says so — a reader who
        // exported a narrowed view must not read these as counts of what is in the sheet.
        row = writePair(sheet, row, labelStyle, "Components (both documents)",
                delta(left.componentCount(), right.componentCount()));
        row = writePair(sheet, row, labelStyle, "Vulnerabilities (both documents)",
                vulnerabilityDelta(leftRisk, rightRisk));
        for (SeverityBand band : FindingQuery.vulnerableBands()) {
            row = writePair(sheet, row, labelStyle, "  " + band.label() + " (both documents)",
                    bandDelta(leftRisk, rightRisk, band));
        }
        row = writePair(sheet, row, labelStyle, "Exported", TIMESTAMP.format(Instant.now()));
        writePair(sheet, row, labelStyle, "Produced by", "SBOMscope");
    }

    /** {@code 73 → 61 (-12)}, as one cell — a spreadsheet reader sorts on the text, not on it. */
    private String delta(int before, int after) {
        int change = after - before;
        return "%d → %d (%s)".formatted(before, after, change == 0 ? "±0" : "%+d".formatted(change));
    }

    /**
     * The vulnerability totals, or a statement that one side was never checked.
     *
     * <p>Never a number where {@code scannedComponents} is zero. Band counts alone cannot tell
     * a document that came back clean from one nobody scanned — both report zero — and a
     * subtraction between them would turn that ambiguity into a confident delta printed in a
     * spreadsheet somebody forwards.
     */
    private String vulnerabilityDelta(SbomSeverity leftRisk, SbomSeverity rightRisk) {
        if (leftRisk.scannedComponents() == 0 || rightRisk.scannedComponents() == 0) {
            return unscannedNote(leftRisk, rightRisk);
        }
        return delta(vulnerabilityTotal(leftRisk), vulnerabilityTotal(rightRisk));
    }

    private String bandDelta(SbomSeverity leftRisk, SbomSeverity rightRisk, SeverityBand band) {
        if (leftRisk.scannedComponents() == 0 || rightRisk.scannedComponents() == 0) {
            return unscannedNote(leftRisk, rightRisk);
        }
        return delta(leftRisk.counts().getOrDefault(band, 0), rightRisk.counts().getOrDefault(band, 0));
    }

    private String unscannedNote(SbomSeverity leftRisk, SbomSeverity rightRisk) {
        if (leftRisk.scannedComponents() == 0 && rightRisk.scannedComponents() == 0) {
            return "neither document has been scanned";
        }
        return leftRisk.scannedComponents() == 0
                ? "the left document has not been scanned"
                : "the right document has not been scanned";
    }

    /** Every vulnerable band, so the parts printed below always add up to this line. */
    private int vulnerabilityTotal(SbomSeverity risk) {
        return FindingQuery.vulnerableBands().stream()
                .mapToInt(band -> risk.counts().getOrDefault(band, 0))
                .sum();
    }

    private String describedFilter(String filter, boolean visibleScope) {
        if (filter == null || filter.isBlank()) {
            return "none";
        }
        return visibleScope ? filter : filter + " (not applied)";
    }

    private List<String> gained(DiffRow row) {
        Set<String> left = row.left() == null ? Set.of() : Set.copyOf(row.left().cveIds());
        return row.right() == null ? List.of() : row.right().cveIds().stream()
                .filter(id -> !left.contains(id)).toList();
    }

    private List<String> lost(DiffRow row) {
        Set<String> right = row.right() == null ? Set.of() : Set.copyOf(row.right().cveIds());
        return row.left() == null ? List.of() : row.left().cveIds().stream()
                .filter(id -> !right.contains(id)).toList();
    }

    private String findings(Side side) {
        if (side == null) {
            return "";
        }
        return java.util.Arrays.stream(SeverityBand.values())
                .filter(band -> side.counts().getOrDefault(band, 0) > 0)
                .map(band -> band.label() + " " + side.counts().get(band))
                .collect(java.util.stream.Collectors.joining(", "));
    }

    private RegistryLinks.Links links(Side side) {
        return side == null ? RegistryLinks.Links.NONE : RegistryLinks.forPurl(side.purl());
    }

    private String version(Side side) {
        return side == null ? "" : side.version();
    }

    private String changeLabel(Change change) {
        return switch (change) {
            case ADDED -> "Added";
            case REMOVED -> "Removed";
            case VERSION_CHANGED -> "Version changed";
            case UNCHANGED -> "Unchanged";
        };
    }

    private int writePair(Sheet sheet, int rowIndex, CellStyle labelStyle,
                          String label, String value) {
        Row row = sheet.createRow(rowIndex);
        Cell labelCell = row.createCell(0);
        labelCell.setCellValue(label);
        labelCell.setCellStyle(labelStyle);
        row.createCell(1).setCellValue(value == null ? "" : value);
        return rowIndex + 1;
    }

    private void writeText(Row row, int column, String value) {
        row.createCell(column).setCellValue(value == null ? "" : value);
    }

    private void writeLinked(Row row, int column, String text, String url,
                             CreationHelper helper, CellStyle linkStyle) {
        Cell cell = row.createCell(column);
        cell.setCellValue(text == null ? "" : text);
        if (url == null || url.isBlank()) {
            return;
        }
        Hyperlink link = helper.createHyperlink(HyperlinkType.URL);
        link.setAddress(url);
        cell.setHyperlink(link);
        cell.setCellStyle(linkStyle);
    }

    private CellStyle headerStyle(Workbook workbook) {
        Font font = workbook.createFont();
        font.setBold(true);
        CellStyle style = workbook.createCellStyle();
        style.setFont(font);
        style.setFillForegroundColor(IndexedColors.GREY_25_PERCENT.getIndex());
        style.setFillPattern(FillPatternType.SOLID_FOREGROUND);
        style.setBorderBottom(BorderStyle.THIN);
        return style;
    }

    private CellStyle boldStyle(Workbook workbook) {
        Font font = workbook.createFont();
        font.setBold(true);
        CellStyle style = workbook.createCellStyle();
        style.setFont(font);
        return style;
    }

    private CellStyle linkStyle(Workbook workbook) {
        Font font = workbook.createFont();
        font.setUnderline(Font.U_SINGLE);
        font.setColor(IndexedColors.BLUE.getIndex());
        CellStyle style = workbook.createCellStyle();
        style.setFont(font);
        return style;
    }
}
