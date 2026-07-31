package dev.sbomscope.export;

import java.io.ByteArrayInputStream;
import java.math.BigDecimal;
import java.time.Instant;
import java.util.EnumSet;
import java.util.List;
import java.util.UUID;

import org.apache.poi.ss.usermodel.Sheet;
import org.apache.poi.ss.usermodel.Workbook;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.junit.jupiter.api.Test;

import dev.sbomscope.sbom.DependencyScope;
import dev.sbomscope.sbom.StoredSbom;
import dev.sbomscope.scanner.FindingQuery;
import dev.sbomscope.scanner.FindingRow;

import static org.assertj.core.api.Assertions.assertThat;

class FindingsExcelExporterTest {

    // Indices into the full column set, which matches the table's order:
    // Component, Version, Scope, OSV ID, GHSA rating, CVE ID, Severity, CVSS version,
    // CVSS vector, Fixed in, Published, Summary, Package URL.
    private static final int COMPONENT = 0;
    private static final int VERSION = 1;
    private static final int SCOPE = 2;
    private static final int OSV_ID = 3;
    private static final int GHSA_RATING = 4;
    private static final int CVE_ID = 5;
    private static final int SEVERITY = 6;
    private static final int CVSS_VECTOR = 8;
    private static final int FIXED_IN = 9;
    private static final int PUBLISHED = 10;
    private static final int SUMMARY = 11;

    private final FindingsExcelExporter exporter = new FindingsExcelExporter();

    private final StoredSbom sbom = new StoredSbom(
            UUID.randomUUID(), "maven-sbomscope.cdx.json", Instant.parse("2026-07-27T10:00:00Z"),
            null, "1.6", 61);

    private final FindingRow withCve = new FindingRow(
            "pkg:maven/tools.jackson.core/jackson-databind@3.1.4?type=jar",
            "tools.jackson.core:jackson-databind", "3.1.4", false, DependencyScope.DIRECT,
            "GHSA-5gvw-p9qm-jgwh", "CVE-2026-59889", "a summary",
            new BigDecimal("6.5"), "MODERATE", "CVSS:3.1/AV:N", "CVSS_V3", "3.1.5",
            Instant.parse("2026-07-21T22:00:43Z"));

    private final FindingRow withoutCve = new FindingRow(
            "pkg:npm/left-pad@1.0.0", "left-pad", "1.0.0", false, DependencyScope.TRANSITIVE,
            "GHSA-aaaa-bbbb-cccc", null, "no cve here",
            null, null, null, null, null, null);

    /** A component with nothing known against it - no advisory at all. */
    private final FindingRow clean = new FindingRow(
            "pkg:maven/org.example/safe-lib@2.0.0", "org.example:safe-lib", "2.0.0", false, DependencyScope.DIRECT,
            null, null, null, null, null, null, null, null, null);

    private Workbook open(byte[] bytes) throws Exception {
        return new XSSFWorkbook(new ByteArrayInputStream(bytes));
    }

    /** The default export: every column, described as a whole-inventory run. */
    private byte[] exportAll(List<FindingRow> rows, Instant lastScannedAt) throws Exception {
        return exporter.export(sbom, rows, lastScannedAt, ExportColumn.all(),
                ExportDescription.of(false, FindingQuery.everything(), ExportColumn.all()));
    }

    @Test
    void producesAReadableWorkbookWithBothSheets() throws Exception {
        try (Workbook workbook = open(exportAll(List.of(withCve), Instant.now()))) {
            assertThat(workbook.getSheet("Findings")).isNotNull();
            assertThat(workbook.getSheet("About this export")).isNotNull();
        }
    }

    @Test
    void writesTheCveAsAWorkingHyperlinkToNvd() throws Exception {
        try (Workbook workbook = open(exportAll(List.of(withCve), Instant.now()))) {
            var cveCell = workbook.getSheet("Findings").getRow(1).getCell(CVE_ID);

            assertThat(cveCell.getStringCellValue()).isEqualTo("CVE-2026-59889");
            assertThat(cveCell.getHyperlink().getAddress())
                    .isEqualTo("https://nvd.nist.gov/vuln/detail/CVE-2026-59889");
        }
    }

    @Test
    void writesTheComponentAndTheVersionAsLinksToDifferentDepths() throws Exception {
        // The name reaches the artifact page, which resolves whenever the artifact exists;
        // the version cell carries the version-specific page, which for a vendor-patched
        // build may not exist at all. Splitting them is the whole point of B2, and the
        // export shares RegistryLinks with the view precisely so it cannot be split in
        // only one of the two.
        try (Workbook workbook = open(exportAll(List.of(withCve), Instant.now()))) {
            var row = workbook.getSheet("Findings").getRow(1);

            assertThat(row.getCell(COMPONENT).getStringCellValue())
                    .isEqualTo("tools.jackson.core:jackson-databind");
            assertThat(row.getCell(COMPONENT).getHyperlink().getAddress())
                    .isEqualTo("https://central.sonatype.com/artifact/tools.jackson.core/jackson-databind");
            assertThat(row.getCell(VERSION).getHyperlink().getAddress())
                    .isEqualTo("https://central.sonatype.com/artifact/tools.jackson.core/jackson-databind/3.1.4");
        }
    }

    @Test
    void linksNpmComponentsToNpmjs() throws Exception {
        FindingRow npmRow = new FindingRow(
                "pkg:npm/react-router@7.18.1", "react-router", "7.18.1", false, DependencyScope.DIRECT,
                "GHSA-qwww-vcr4-c8h2", "CVE-2026-1234", "summary",
                new BigDecimal("7.1"), "HIGH", null, "CVSS_V3", "8.3.0", null);

        try (Workbook workbook = open(exportAll(List.of(npmRow), Instant.now()))) {
            var row = workbook.getSheet("Findings").getRow(1);

            assertThat(row.getCell(COMPONENT).getHyperlink().getAddress())
                    .isEqualTo("https://www.npmjs.com/package/react-router");
            assertThat(row.getCell(VERSION).getHyperlink().getAddress())
                    .isEqualTo("https://www.npmjs.com/package/react-router/v/7.18.1");
        }
    }

    @Test
    void leavesBothCellsUnlinkedWhereThePurlNamesAPrivateRepository() throws Exception {
        // No link beats a wrong one: Central would 404 for a vendor build, and a private
        // host is unreachable for whoever reads the spreadsheet. The text still stands.
        FindingRow vendorRow = new FindingRow(
                "pkg:maven/com.acme/internal-billing@1.2.3.acme-4"
                        + "?repository_url=https://artifactory.acme.internal/libs-release",
                "com.acme:internal-billing", "1.2.3.acme-4", false, DependencyScope.TRANSITIVE,
                "GHSA-aaaa-bbbb-cccc", null, "summary", null, null, null, null, null, null);

        try (Workbook workbook = open(exportAll(List.of(vendorRow), Instant.now()))) {
            var row = workbook.getSheet("Findings").getRow(1);

            assertThat(row.getCell(COMPONENT).getStringCellValue()).isEqualTo("com.acme:internal-billing");
            assertThat(row.getCell(COMPONENT).getHyperlink()).isNull();
            assertThat(row.getCell(VERSION).getStringCellValue()).isEqualTo("1.2.3.acme-4");
            assertThat(row.getCell(VERSION).getHyperlink()).isNull();
        }
    }

    @Test
    void writesThePublicationDateInUtc() throws Exception {
        // 2026-07-21T22:00:43Z is 22 July in any zone east of UTC+2, so formatting it with
        // the machine's own clock printed a date one day after the advisory it links to —
        // and printed a 00:00 that looked like a missing time rather than a shifted date.
        // The date is also all that matters here: the minute an advisory was filed says
        // nothing about how urgent it is.
        try (Workbook workbook = open(exportAll(List.of(withCve), Instant.now()))) {
            assertThat(workbook.getSheet("Findings").getRow(1).getCell(PUBLISHED).getStringCellValue())
                    .isEqualTo("2026-07-21");
        }
    }

    @Test
    void advisoryAndCveColumnsLinkToDifferentPlaces() throws Exception {
        // Two columns pointing at the same page would waste one of them: the OSV record
        // carries affected ranges and ecosystem detail that the NVD page does not.
        try (Workbook workbook = open(exportAll(List.of(withCve), Instant.now()))) {
            var row = workbook.getSheet("Findings").getRow(1);

            assertThat(row.getCell(OSV_ID).getHyperlink().getAddress())
                    .isEqualTo("https://osv.dev/vulnerability/GHSA-5gvw-p9qm-jgwh");
            assertThat(row.getCell(CVE_ID).getHyperlink().getAddress())
                    .isEqualTo("https://nvd.nist.gov/vuln/detail/CVE-2026-59889");
        }
    }

    @Test
    void writesTheSeverityAsANumberSoItSortsCorrectly() throws Exception {
        // Written as text, "10.0" would sort below "6.5" in Excel - the exact mistake
        // that makes an exported vulnerability list untrustworthy.
        try (Workbook workbook = open(exportAll(List.of(withCve), Instant.now()))) {
            assertThat(workbook.getSheet("Findings").getRow(1).getCell(SEVERITY).getNumericCellValue())
                    .isEqualTo(6.5);
        }
    }

    @Test
    void keepsTheGhsaRatingApartFromTheScore() throws Exception {
        // Different scales from different sources: GitHub calls 6.5 MODERATE where CVSS
        // calls it Medium. They sit in separate columns so neither reads as the other's label.
        try (Workbook workbook = open(exportAll(List.of(withCve), Instant.now()))) {
            var row = workbook.getSheet("Findings").getRow(1);

            assertThat(row.getCell(GHSA_RATING).getStringCellValue()).isEqualTo("MODERATE");
            assertThat(row.getCell(SEVERITY).getNumericCellValue()).isEqualTo(6.5);
        }
    }

    @Test
    void carriesTheSummaryAndVectorTheTableHasNoRoomFor() throws Exception {
        // Both are held but were never written out. A spreadsheet has the width the table
        // does not, and a description of each finding is what makes the export readable.
        try (Workbook workbook = open(exportAll(List.of(withCve), Instant.now()))) {
            var row = workbook.getSheet("Findings").getRow(1);

            assertThat(row.getCell(SUMMARY).getStringCellValue()).isEqualTo("a summary");
            assertThat(row.getCell(CVSS_VECTOR).getStringCellValue()).isEqualTo("CVSS:3.1/AV:N");
        }
    }

    @Test
    void handlesAdvisoriesWithNoCveAndNoFix() throws Exception {
        try (Workbook workbook = open(exportAll(List.of(withoutCve), Instant.now()))) {
            var row = workbook.getSheet("Findings").getRow(1);

            assertThat(row.getCell(OSV_ID).getStringCellValue()).isEqualTo("GHSA-aaaa-bbbb-cccc");
            assertThat(row.getCell(CVE_ID).getStringCellValue()).isEmpty();
            assertThat(row.getCell(FIXED_IN).getStringCellValue()).isEqualTo("no fix");
        }
    }

    @Test
    void statesExplicitlyWhenAComponentHasNoKnownVulnerability() throws Exception {
        // Left blank, such a row would look like missing data rather than a clean result.
        try (Workbook workbook = open(exportAll(List.of(clean), Instant.now()))) {
            var row = workbook.getSheet("Findings").getRow(1);

            assertThat(row.getCell(COMPONENT).getStringCellValue()).isEqualTo("org.example:safe-lib");
            assertThat(row.getCell(OSV_ID).getStringCellValue()).isEqualTo("no known vulnerabilities");
            assertThat(row.getCell(SCOPE).getStringCellValue()).isEqualTo("direct");
            // "no fix" would be a claim about an advisory this row does not have.
            assertThat(row.getCell(FIXED_IN).getStringCellValue()).isEmpty();
        }
    }

    // --- column selection ------------------------------------------------------------

    @Test
    void writesOnlyTheRequestedColumnsInTheCanonicalOrder() throws Exception {
        // Ticked in a deliberately jumbled order: the sheet must follow the table's order,
        // not the order the ids happened to arrive in.
        List<ExportColumn> chosen = ExportColumn.parse(List.of("severity", "component", "cveId"));

        try (Workbook workbook = open(exporter.export(sbom, List.of(withCve), Instant.now(),
                chosen, ExportDescription.of(true, FindingQuery.defaults(), chosen)))) {
            var header = workbook.getSheet("Findings").getRow(0);

            assertThat(header.getCell(0).getStringCellValue()).isEqualTo("Component");
            assertThat(header.getCell(1).getStringCellValue()).isEqualTo("CVE ID");
            assertThat(header.getCell(2).getStringCellValue()).isEqualTo("Severity");
            assertThat(header.getCell(3)).isNull();
        }
    }

    @Test
    void fallsBackToEveryColumnRatherThanExportingNone() throws Exception {
        // A malformed request should produce a complete spreadsheet, never a blank one:
        // silently omitting findings is the worse failure.
        assertThat(ExportColumn.parse(List.of("nonsense", "alsoNotAColumn")))
                .isEqualTo(ExportColumn.all());
        assertThat(ExportColumn.parse(List.of())).isEqualTo(ExportColumn.all());
        assertThat(ExportColumn.parse(null)).isEqualTo(ExportColumn.all());
    }

    // --- provenance ------------------------------------------------------------------

    @Test
    void countsVulnerabilitiesSeparatelyFromRows() throws Exception {
        // A mixed export contains clean components too, so "rows" and "vulnerabilities"
        // are different numbers and both belong in the provenance sheet.
        try (Workbook workbook = open(exportAll(List.of(withCve, clean), Instant.now()))) {
            String about = about(workbook.getSheet("About this export"));

            assertThat(about).contains("Rows in this export");
            assertThat(about).contains("Of which vulnerabilities");
        }
    }

    @Test
    void recordsProvenanceIncludingWhenItWasScanned() throws Exception {
        Instant scannedAt = Instant.parse("2026-07-27T18:07:36Z");
        try (Workbook workbook = open(exportAll(List.of(withCve), scannedAt))) {
            String contents = about(workbook.getSheet("About this export"));

            assertThat(contents).contains("maven-sbomscope.cdx.json");
            assertThat(contents).contains("Last scanned");
            assertThat(contents).contains("OSV.dev");
        }
    }

    @Test
    void recordsWhatWasSelectedSoAFilteredExportCanExplainItsOwnSize() throws Exception {
        // Without this, a workbook holding 40 of 600 findings looks identical to a complete
        // one, and the reader has no way to tell a slice from the whole picture.
        FindingQuery narrowed = new FindingQuery(
                FindingQuery.SortField.COMPONENT, true, "jackson", false, false,
                EnumSet.of(FindingQuery.SeverityBand.CRITICAL, FindingQuery.SeverityBand.HIGH),
                EnumSet.of(DependencyScope.DIRECT), 20, 0);

        try (Workbook workbook = open(exporter.export(sbom, List.of(withCve), Instant.now(),
                ExportColumn.all(), ExportDescription.of(true, narrowed, ExportColumn.all())))) {
            String about = about(workbook.getSheet("About this export"));

            assertThat(about).contains("Current view");
            assertThat(about).contains("Component, ascending");
            assertThat(about).contains("Critical, High");
            assertThat(about).contains("jackson");
            // A workbook narrowed to one scope holds a fraction of the findings and would
            // otherwise look identical to a complete one.
            assertThat(about).contains("Scope filter");
            assertThat(about).contains("Direct");
        }
    }

    @Test
    void saysPlainlyWhenNothingWasFilteredOut() throws Exception {
        try (Workbook workbook = open(exportAll(List.of(withCve), Instant.now()))) {
            String about = about(workbook.getSheet("About this export"));

            assertThat(about).contains("every band");
            assertThat(about).contains("none");
            assertThat(about).contains("all");
        }
    }

    @Test
    void exportsAnEmptyListWithoutFailing() throws Exception {
        try (Workbook workbook = open(exportAll(List.of(), null))) {
            Sheet sheet = workbook.getSheet("Findings");

            assertThat(sheet.getRow(0)).isNotNull();      // header still written
            assertThat(sheet.getRow(1)).isNull();          // no data rows
            assertThat(about(workbook.getSheet("About this export"))).contains("never");
        }
    }

    private String about(Sheet sheet) {
        StringBuilder text = new StringBuilder();
        sheet.forEach(row -> row.forEach(cell -> {
            if (cell.getCellType() == org.apache.poi.ss.usermodel.CellType.STRING) {
                text.append(cell.getStringCellValue()).append('\n');
            }
        }));
        return text.toString();
    }
}
