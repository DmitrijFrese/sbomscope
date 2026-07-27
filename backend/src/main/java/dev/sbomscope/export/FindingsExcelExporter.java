package dev.sbomscope.export;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.List;

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

import dev.sbomscope.scanner.FindingRow;
import dev.sbomscope.sbom.StoredSbom;

/**
 * Writes findings to a real .xlsx workbook.
 *
 * <p>The point of this feature is that the export is genuinely usable: hyperlinks that
 * work, a frozen header, an autofilter, and sensible column widths, so nobody has to
 * clean it up before sending it on. Provenance is written into a second sheet rather
 * than crammed above the table, which would break sorting and filtering.
 */
@Component
public class FindingsExcelExporter {

    /** Things that happened on this machine: the reader's own clock is the right one. */
    private static final DateTimeFormatter TIMESTAMP =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm").withZone(ZoneId.systemDefault());

    /**
     * An advisory's publication date. UTC, and a date rather than a timestamp.
     *
     * <p>Not the same kind of value as the timestamps above, and formatting it like one was
     * wrong in a way that only showed up off-centre. OSV publishes real times —
     * {@code GHSA-5gvw-p9qm-jgwh} is {@code 2026-07-21T22:00:43Z} — so rendering in the local
     * zone moved the date across midnight for anyone east of UTC: in Berlin that advisory
     * read 22 July, one day after the record it links to on osv.dev. It would have looked
     * like bad data rather than a formatting choice, and only for advisories filed near
     * midnight.
     *
     * <p>The time of day an advisory was filed carries nothing for triage either, where the
     * question is how old it is, so dropping it costs nothing and removes the whole class of
     * off-by-one-day disagreement with the source.
     */
    private static final DateTimeFormatter ADVISORY_DATE =
            DateTimeFormatter.ofPattern("yyyy-MM-dd").withZone(ZoneOffset.UTC);

    public byte[] export(StoredSbom sbom, List<FindingRow> rows, Instant lastScannedAt,
                         List<ExportColumn> columns, ExportDescription description)
            throws IOException {

        try (Workbook workbook = new XSSFWorkbook();
             ByteArrayOutputStream out = new ByteArrayOutputStream()) {

            writeFindingsSheet(workbook, rows, columns);
            writeAboutSheet(workbook, sbom, rows, lastScannedAt, description);

            workbook.write(out);
            return out.toByteArray();
        }
    }

    private void writeFindingsSheet(Workbook workbook, List<FindingRow> rows,
                                    List<ExportColumn> columns) {
        Sheet sheet = workbook.createSheet("Findings");
        CreationHelper helper = workbook.getCreationHelper();

        CellStyle headerStyle = headerStyle(workbook);
        CellStyle linkStyle = linkStyle(workbook);

        Row header = sheet.createRow(0);
        for (int index = 0; index < columns.size(); index++) {
            ExportColumn column = columns.get(index);
            Cell cell = header.createCell(index);
            cell.setCellValue(column.label());
            cell.setCellStyle(headerStyle);
            sheet.setColumnWidth(index, column.widthInCharacters() * 256);
        }

        int rowIndex = 1;
        for (FindingRow entry : rows) {
            Row row = sheet.createRow(rowIndex++);
            for (int index = 0; index < columns.size(); index++) {
                write(row, index, columns.get(index), entry, helper, linkStyle);
            }
        }

        sheet.createFreezePane(0, 1);
        if (rowIndex > 1) {
            sheet.setAutoFilter(new CellRangeAddress(0, rowIndex - 1, 0, columns.size() - 1));
        }
    }

    /**
     * One cell.
     *
     * <p>Advisory destinations come from {@link AdvisoryLinks} and component destinations
     * from {@link RegistryLinks} — the same code the API sends to the browser, so a link
     * here cannot point somewhere else than the one in the table this came from.
     */
    private void write(Row row, int index, ExportColumn column, FindingRow entry,
                       CreationHelper helper, CellStyle linkStyle) {

        switch (column) {
            case COMPONENT -> writeLinked(row, index, entry.coordinates(),
                    RegistryLinks.forPurl(entry.purl()), helper, linkStyle);

            case VERSION -> writeText(row, index, entry.version());

            // "root" rather than "application" for the one component the document describes:
            // it is an application component, but the distinction is worth keeping visible.
            case SCOPE -> writeText(row, index,
                    entry.root() ? "root" : entry.scope().name().toLowerCase());

            // A component with nothing known against it says so, rather than leaving a run
            // of blank cells that reads as missing data.
            case OSV_ID -> {
                if (entry.hasFinding()) {
                    writeLinked(row, index, entry.osvId(),
                            AdvisoryLinks.osvUrl(entry.osvId()), helper, linkStyle);
                } else {
                    writeText(row, index, "no known vulnerabilities");
                }
            }

            case GHSA_RATING -> writeText(row, index, entry.severityRating());

            case CVE_ID -> {
                if (entry.cveId() != null) {
                    writeLinked(row, index, entry.cveId(),
                            AdvisoryLinks.cveUrl(entry.cveId()), helper, linkStyle);
                } else {
                    writeText(row, index, "");
                }
            }

            // Written as a number, not text: as text "10.0" sorts below "6.5" in Excel,
            // which is exactly what makes an exported vulnerability list untrustworthy.
            case SEVERITY -> {
                if (entry.severityScore() != null) {
                    row.createCell(index).setCellValue(entry.severityScore().doubleValue());
                } else {
                    writeText(row, index, "");
                }
            }

            case CVSS_VERSION -> writeText(row, index, entry.cvssVersion() == null
                    ? "" : entry.cvssVersion().replace("CVSS_", "CVSS "));

            case CVSS_VECTOR -> writeText(row, index, entry.cvssVector());

            case FIXED_VERSION -> writeText(row, index,
                    entry.hasFinding() ? (entry.fixedVersion() == null ? "no fix" : entry.fixedVersion()) : "");

            case PUBLISHED -> writeText(row, index,
                    entry.publishedAt() == null ? "" : ADVISORY_DATE.format(entry.publishedAt()));

            case SUMMARY -> writeText(row, index, entry.summary());

            case PURL -> writeText(row, index, entry.purl());
        }
    }

    /**
     * Provenance on its own sheet: what was scanned, when, how fresh the answer is — and
     * what was selected, so a filtered export can account for its own size.
     */
    private void writeAboutSheet(Workbook workbook, StoredSbom sbom, List<FindingRow> rows,
                                 Instant lastScannedAt, ExportDescription description) {
        Sheet sheet = workbook.createSheet("About this export");
        CellStyle labelStyle = boldStyle(workbook);

        sheet.setColumnWidth(0, 28 * 256);
        sheet.setColumnWidth(1, 80 * 256);

        int row = 0;
        row = writePair(sheet, row, labelStyle, "SBOM", sbom.filename());
        row = writePair(sheet, row, labelStyle, "Uploaded", TIMESTAMP.format(sbom.uploadedAt()));
        row = writePair(sheet, row, labelStyle, "CycloneDX version", sbom.specVersion());
        row = writePair(sheet, row, labelStyle, "Components", String.valueOf(sbom.componentCount()));
        row = writePair(sheet, row, labelStyle, "Workspace",
                sbom.workspacePath() == null ? "not set" : sbom.workspacePath());

        long vulnerabilities = rows.stream().filter(FindingRow::hasFinding).count();
        row = writePair(sheet, row, labelStyle, "Rows in this export", String.valueOf(rows.size()));
        row = writePair(sheet, row, labelStyle, "Of which vulnerabilities", String.valueOf(vulnerabilities));

        if (description != null) {
            row = writePair(sheet, row, labelStyle, "Scope", description.scope());
            row = writePair(sheet, row, labelStyle, "Sorted by", description.sortedBy());
            row = writePair(sheet, row, labelStyle, "Severity filter", description.severityFilter());
            row = writePair(sheet, row, labelStyle, "Text filter", description.textFilter());
            row = writePair(sheet, row, labelStyle, "Columns", description.columns());
        }

        row = writePair(sheet, row, labelStyle, "Last scanned",
                lastScannedAt == null ? "never" : TIMESTAMP.format(lastScannedAt));
        row = writePair(sheet, row, labelStyle, "Exported", TIMESTAMP.format(Instant.now()));
        row = writePair(sheet, row, labelStyle, "Vulnerability data", "OSV.dev, via OSV-Scanner");
        writePair(sheet, row, labelStyle, "Produced by", "SBOMscope");
    }

    private int writePair(Sheet sheet, int rowIndex, CellStyle labelStyle, String label, String value) {
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
