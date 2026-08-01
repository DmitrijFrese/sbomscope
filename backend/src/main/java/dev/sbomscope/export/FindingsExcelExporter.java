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

import dev.sbomscope.exploit.ExploitFeedService;
import dev.sbomscope.exploit.KevEntry;
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

    /**
     * @param feeds the exploitation feeds' own as-of dates, for the About sheet. A KEV column in
     *              an undated workbook cannot distinguish "not exploited" from "our copy of the
     *              catalogue predates the listing", which is the same defect the filter lines on
     *              that sheet exist to prevent
     */
    public byte[] export(StoredSbom sbom, List<FindingRow> rows, Instant lastScannedAt,
                         List<ExportColumn> columns, ExportDescription description,
                         List<ExploitFeedService.FeedStatus> feeds)
            throws IOException {

        try (Workbook workbook = new XSSFWorkbook();
             ByteArrayOutputStream out = new ByteArrayOutputStream()) {

            writeFindingsSheet(workbook, rows, columns);
            writeAboutSheet(workbook, sbom, rows, lastScannedAt, description, feeds);

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
     * here cannot point somewhere else than the one in the table this came from. That
     * includes the split into two destinations: the component name carries the artifact
     * page, which resolves whenever the artifact exists, and the version cell carries the
     * version-specific page, which for a vendor-patched build may not exist at all. Linking
     * only one of the two here would be exactly the drift sharing this class prevents.
     */
    private void write(Row row, int index, ExportColumn column, FindingRow entry,
                       CreationHelper helper, CellStyle linkStyle) {

        switch (column) {
            case COMPONENT -> writeLinked(row, index, entry.coordinates(),
                    RegistryLinks.forPurl(entry.purl()).artifactUrl(), helper, linkStyle);

            case VERSION -> writeLinked(row, index, entry.version(),
                    RegistryLinks.forPurl(entry.purl()).versionUrl(), helper, linkStyle);

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

            // A positive mark or nothing. Deliberately not "No": absence from CISA's catalogue
            // means it is not listed, which is not the same as somebody having established that
            // the flaw is not exploited, and a column of "No" would read as exactly that
            // clearance. The blank is qualified on the About sheet, where the feed's as-of date
            // says how current the catalogue behind it is.
            case KEV -> {
                if (entry.signals().kevListed()) {
                    writeLinked(row, index,
                            entry.signals().kevRansomware() ? "Yes — ransomware" : "Yes",
                            KevEntry.catalogUrl(entry.cveId()), helper, linkStyle);
                } else {
                    writeText(row, index, "");
                }
            }

            case KEV_LISTED -> writeText(row, index, entry.signals().kevDateAdded() == null
                    ? "" : entry.signals().kevDateAdded().toString());

            // Numbers, not text, for the reason SEVERITY is: as text "0.9" sorts above "0.11"
            // and the one thing anybody does with this column in a spreadsheet is sort it.
            case EPSS -> {
                if (entry.signals().epssScore() != null) {
                    row.createCell(index).setCellValue(entry.signals().epssScore());
                } else {
                    writeText(row, index, "");
                }
            }

            case EPSS_PERCENTILE -> {
                if (entry.signals().epssPercentile() != null) {
                    row.createCell(index).setCellValue(entry.signals().epssPercentile());
                } else {
                    writeText(row, index, "");
                }
            }

            case SUMMARY -> writeText(row, index, entry.summary());

            case PURL -> writeText(row, index, entry.purl());
        }
    }

    /**
     * Provenance on its own sheet: what was scanned, when, how fresh the answer is — and
     * what was selected, so a filtered export can account for its own size.
     */
    private void writeAboutSheet(Workbook workbook, StoredSbom sbom, List<FindingRow> rows,
                                 Instant lastScannedAt, ExportDescription description,
                                 List<ExploitFeedService.FeedStatus> feeds) {
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
            row = writePair(sheet, row, labelStyle, "Scope filter", description.scopeFilter());
            row = writePair(sheet, row, labelStyle, "Text filter", description.textFilter());
            row = writePair(sheet, row, labelStyle, "Columns", description.columns());
        }

        row = writePair(sheet, row, labelStyle, "Last scanned",
                lastScannedAt == null ? "never" : TIMESTAMP.format(lastScannedAt));
        row = writePair(sheet, row, labelStyle, "Exported", TIMESTAMP.format(Instant.now()));
        row = writePair(sheet, row, labelStyle, "Vulnerability data", "OSV.dev, via OSV-Scanner");
        row = writeFeedProvenance(sheet, row, labelStyle, feeds);
        writePair(sheet, row, labelStyle, "Produced by", "SBOMscope");
    }

    /**
     * Each feed's own as-of date, and what it says when there is none.
     *
     * <p>"not downloaded" rather than a blank, because a blank here and a blank in every KEV cell
     * would be the same absence twice with nothing to connect them — the reader would have no way
     * to tell an unexploited spreadsheet from one produced on a machine that never fetched the
     * catalogue. Written even when nothing was downloaded, for exactly that reason.
     *
     * <p>The version travels with the date because the two answer different questions: for EPSS
     * a score is only comparable with another from the same model, and a model change moves every
     * score at once.
     */
    private int writeFeedProvenance(Sheet sheet, int rowIndex, CellStyle labelStyle,
                                    List<ExploitFeedService.FeedStatus> feeds) {
        if (feeds == null) {
            return rowIndex;
        }
        int row = rowIndex;
        for (ExploitFeedService.FeedStatus feed : feeds) {
            String value;
            // hasData, not loaded: the workbook is describing the data that produced its cells,
            // and that data outlives the file it came from. The same distinction the findings
            // notice needed.
            if (!feed.hasData() || feed.asOf() == null) {
                value = "not downloaded — this column is empty on every row";
            } else {
                value = "%s, as of %s".formatted(
                        feed.version() == null ? feed.label() : feed.label() + " " + feed.version(),
                        ADVISORY_DATE.format(feed.asOf()));
            }
            row = writePair(sheet, row, labelStyle, feed.feed() + " data", value);
        }
        return row;
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
