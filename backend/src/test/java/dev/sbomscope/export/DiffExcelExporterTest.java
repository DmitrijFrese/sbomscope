package dev.sbomscope.export;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.ss.usermodel.Sheet;
import org.apache.poi.ss.usermodel.Workbook;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.annotation.Transactional;

import dev.sbomscope.diff.DiffRow;
import dev.sbomscope.diff.DiffRow.Change;
import dev.sbomscope.diff.DiffRow.Side;
import dev.sbomscope.diff.DiffService;
import dev.sbomscope.sbom.CycloneDxParser;
import dev.sbomscope.sbom.ParsedSbom;
import dev.sbomscope.sbom.ParsedSbom.ParsedComponent;
import dev.sbomscope.sbom.StoredSbom;
import dev.sbomscope.scanner.FindingQuery.SeverityBand;
import dev.sbomscope.scanner.SbomSeverity;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@Transactional
class DiffExcelExporterTest {

    private static final List<String> HEADERS = List.of(
            "Change", "Group", "Artifact", "Left version", "Right version",
            "CVEs gained", "CVEs lost", "Left findings", "Right findings");

    @Autowired
    private DiffExcelExporter exporter;

    @Autowired
    private DiffService diffs;

    @Autowired
    private CycloneDxParser parser;

    @Autowired
    private JdbcTemplate jdbc;

    @BeforeEach
    void isolateFindingCache() {
        jdbc.update("DELETE FROM vulnerability_finding");
        jdbc.update("DELETE FROM vulnerability_scan");
    }

    @Test
    void writesTheHeaderAndEveryEngineRowInEngineOrder() throws Exception {
        StoredSbom left = seed("maven-sbomscope.cdx.json", "baseline.cdx.json");
        StoredSbom right = seed("npm-frontend.cdx.json", "new-state.cdx.json");
        DiffService.DiffResult result = diffs.compare(left.id(), right.id(), null, false, false);

        try (Workbook workbook = open(exportWith(
                left, right, result, false, null, false, false))) {
            Sheet sheet = workbook.getSheet("Comparison");
            assertThat(cells(sheet.getRow(0))).containsExactlyElementsOf(HEADERS);
            assertThat(sheet.getLastRowNum()).isEqualTo(result.rows().size());

            for (int index = 0; index < result.rows().size(); index++) {
                DiffRow expected = result.rows().get(index);
                Row actual = sheet.getRow(index + 1);
                assertThat(actual.getCell(1).getStringCellValue()).isEqualTo(nullToEmpty(expected.group()));
                assertThat(actual.getCell(2).getStringCellValue()).isEqualTo(expected.name());
            }
        }
    }

    @Test
    void visibleExcludesUnchangedWhileAllIncludesItAndBothScopesExplainThemselves()
            throws Exception {
        StoredSbom left = seed("maven-sbomscope.cdx.json", "baseline.cdx.json");
        StoredSbom right = seed("maven-sbomscope.cdx.json", "new-state.cdx.json");
        UUID removed = jdbc.queryForObject(
                "SELECT id FROM component WHERE sbom_id = ? AND is_root = FALSE LIMIT 1",
                UUID.class, right.id());
        jdbc.update("DELETE FROM component WHERE id = ?", removed);
        DiffService.DiffResult result = diffs.compare(left.id(), right.id(), null, false, false);
        long changed = result.rows().stream().filter(row -> row.change() != Change.UNCHANGED).count();

        try (Workbook visible = open(exportWith(
                     left, right, result, true, null, false, false));
             Workbook all = open(exportWith(
                     left, right, result, false, null, false, false))) {
            assertThat(visible.getSheet("Comparison").getLastRowNum()).isEqualTo((int) changed);
            assertThat(all.getSheet("Comparison").getLastRowNum()).isEqualTo(result.rows().size());
            assertThat(about(visible)).containsEntry(
                    "Scope", "visible — text filter applied; unchanged rows excluded");
            assertThat(about(all)).containsEntry(
                    "Scope", "all — text filter ignored; unchanged rows included");
        }
    }

    @Test
    void linksTheArtifactAndEachAvailableVersionFromThatSidesOwnPurl() throws Exception {
        StoredSbom left = document("baseline.cdx.json");
        StoredSbom right = document("new-state.cdx.json");
        String leftPurl = "pkg:maven/org.example/library@1.0.0";
        String rightPurl = "pkg:maven/org.example/library@2.0.0";
        Side leftSide = new Side(leftPurl, "1.0.0", Map.of(SeverityBand.CLEAN, 1), List.of());
        Side rightSide = new Side(rightPurl, "2.0.0", Map.of(SeverityBand.HIGH, 1),
                List.of("CVE-2026-0002"));
        DiffRow row = new DiffRow("org.example:library", "org.example", "library",
                leftSide, rightSide, Change.VERSION_CHANGED);
        DiffRow missingPurl = new DiffRow("org.example:other", "org.example", "other",
                new Side(null, "1.0.0", Map.of(), List.of()),
                new Side("pkg:maven/org.example/other@2.0.0", "2.0.0", Map.of(), List.of()),
                Change.VERSION_CHANGED);

        try (Workbook workbook = open(exportWith(left, right, result(row, missingPurl),
                false, null, false, false))) {
            Row written = workbook.getSheet("Comparison").getRow(1);
            RegistryLinks.Links leftLinks = RegistryLinks.forPurl(leftPurl);
            RegistryLinks.Links rightLinks = RegistryLinks.forPurl(rightPurl);

            assertThat(written.getCell(2).getHyperlink().getAddress()).isEqualTo(leftLinks.artifactUrl());
            assertThat(written.getCell(3).getHyperlink().getAddress()).isEqualTo(leftLinks.versionUrl());
            assertThat(written.getCell(4).getHyperlink().getAddress()).isEqualTo(rightLinks.versionUrl());
            assertThat(written.getCell(7).getStringCellValue()).isEqualTo("Clean 1");
            assertThat(written.getCell(8).getStringCellValue()).isEqualTo("High 1");

            Row noPurlWritten = workbook.getSheet("Comparison").getRow(2);
            assertThat(noPurlWritten.getCell(3).getStringCellValue()).isEqualTo("1.0.0");
            assertThat(noPurlWritten.getCell(3).getHyperlink()).isNull();
            assertThat(noPurlWritten.getCell(4).getHyperlink()).isNotNull();
        }
    }

    @Test
    void writesEachRowsOwnGainedAndLostCvesAsPlainText() throws Exception {
        StoredSbom left = document("baseline.cdx.json");
        StoredSbom right = document("new-state.cdx.json");
        DiffRow row = new DiffRow("org.example:library", "org.example", "library",
                new Side("pkg:maven/org.example/library@1", "1", Map.of(),
                        List.of("CVE-2026-0001", "CVE-2026-0002")),
                new Side("pkg:maven/org.example/library@2", "2", Map.of(),
                        List.of("CVE-2026-0002", "CVE-2026-0003")),
                Change.VERSION_CHANGED);

        try (Workbook workbook = open(exportWith(left, right, result(row),
                false, null, false, false))) {
            Row written = workbook.getSheet("Comparison").getRow(1);
            assertThat(written.getCell(5).getStringCellValue()).isEqualTo("CVE-2026-0003");
            assertThat(written.getCell(6).getStringCellValue()).isEqualTo("CVE-2026-0001");
            assertThat(written.getCell(5).getHyperlink()).isNull();
            assertThat(written.getCell(6).getHyperlink()).isNull();
        }
    }

    @Test
    void provenanceNamesBothSidesFilterModeAndWholeComparisonSummary() throws Exception {
        StoredSbom left = document("baseline.cdx.json");
        StoredSbom right = document("new-state.cdx.json");
        DiffService.Summary summary = new DiffService.Summary(Map.of(
                Change.ADDED, 1,
                Change.REMOVED, 2,
                Change.VERSION_CHANGED, 3,
                Change.UNCHANGED, 4), 5, 6);

        try (Workbook workbook = open(exportWith(left, right,
                new DiffService.DiffResult(List.of(), summary), true,
                "^org\\.example", true, true, DiffService.DiffSort.CHANGE, false))) {
            Map<String, String> about = about(workbook);
            assertThat(about)
                    .containsEntry("Left document", left.filename())
                    .containsEntry("Left id", left.id().toString())
                    .containsEntry("Right document", right.filename())
                    .containsEntry("Right id", right.id().toString())
                    .containsEntry("Text filter", "^org\\.example")
                    .containsEntry("Filter mode", "regular expression (case-insensitive)")
                    .containsEntry("Filter negated", "yes")
                    .containsEntry("Sort", "Change, descending")
                    .containsEntry("Summary covers", "the whole comparison, not only the exported rows")
                    .containsEntry("Added (whole comparison)", "1")
                    .containsEntry("Removed (whole comparison)", "2")
                    .containsEntry("Version changed (whole comparison)", "3")
                    .containsEntry("Unchanged (whole comparison)", "4")
                    .containsEntry("CVEs gained (whole comparison)", "5")
                    .containsEntry("CVEs lost (whole comparison)", "6");
        }
    }

    @Test
    void anEmptyDiffStillHasAHeaderAndProvenanceSheet() throws Exception {
        StoredSbom left = document("empty-left.cdx.json");
        StoredSbom right = document("empty-right.cdx.json");
        DiffService.Summary summary = new DiffService.Summary(Map.of(
                Change.ADDED, 0,
                Change.REMOVED, 0,
                Change.VERSION_CHANGED, 0,
                Change.UNCHANGED, 0), 0, 0);

        try (Workbook workbook = open(exportWith(left, right,
                new DiffService.DiffResult(List.of(), summary), false, null, false, false))) {
            Sheet comparison = workbook.getSheet("Comparison");
            assertThat(comparison.getLastRowNum()).isZero();
            assertThat(cells(comparison.getRow(0))).containsExactlyElementsOf(HEADERS);
            assertThat(workbook.getSheet("About this export")).isNotNull();
        }
    }

    @Test
    void carriesBothDocumentsTotalsAndTheirSeverityBreakdown() throws Exception {
        // The block the page shows above the table. The export exists to reproduce the screen,
        // so a summary the reader can see and the workbook cannot is a defect rather than a
        // scoping choice — and the per-band lines have to add up to the total above them.
        StoredSbom left = document("baseline.cdx.json");
        StoredSbom right = document("new-state.cdx.json");

        try (Workbook workbook = open(exporter.export(left, right,
                scanned(Map.of(SeverityBand.CRITICAL, 2, SeverityBand.HIGH, 3, SeverityBand.NONE, 1)),
                scanned(Map.of(SeverityBand.CRITICAL, 0, SeverityBand.HIGH, 1, SeverityBand.LOW, 4)),
                result(), false, null, false, false))) {
            Map<String, String> about = about(workbook);

            assertThat(about).containsEntry("Vulnerabilities (both documents)", "6 → 5 (-1)");
            assertThat(about).containsEntry("  Critical (both documents)", "2 → 0 (-2)");
            assertThat(about).containsEntry("  High (both documents)", "3 → 1 (-2)");
            assertThat(about).containsEntry("  Medium (both documents)", "0 → 0 (±0)");
            assertThat(about).containsEntry("  Low (both documents)", "0 → 4 (+4)");
            assertThat(about).containsEntry("  Unscored (both documents)", "1 → 0 (-1)");
            assertThat(about).containsKey("Components (both documents)");
        }
    }

    @Test
    void refusesToSubtractCountsFromADocumentNobodyScanned() throws Exception {
        // Zero findings and never looked are different statements. A delta between them would
        // be a confident number in a file somebody forwards.
        StoredSbom left = document("baseline.cdx.json");
        StoredSbom right = document("new-state.cdx.json");

        try (Workbook workbook = open(exporter.export(left, right,
                SbomSeverity.notScanned(), scanned(Map.of(SeverityBand.HIGH, 4)),
                result(), false, null, false, false))) {
            Map<String, String> about = about(workbook);

            assertThat(about).containsEntry(
                    "Vulnerabilities (both documents)", "the left document has not been scanned");
            assertThat(about).containsEntry(
                    "  High (both documents)", "the left document has not been scanned");
            // The component counts are a fact about the documents either way, so they stay.
            assertThat(about.get("Components (both documents)")).contains("→");
        }
    }

    /**
     * The export, with two scanned documents whose totals are not what the test is about.
     * Tests that care about the document totals pass their own {@link SbomSeverity}.
     */
    private byte[] exportWith(StoredSbom left, StoredSbom right, DiffService.DiffResult comparison,
                              boolean visibleScope, String filter, boolean regex, boolean negate)
            throws Exception {
        return exportWith(left, right, comparison, visibleScope, filter, regex, negate,
                DiffService.DiffSort.COORDINATES, true);
    }

    private byte[] exportWith(StoredSbom left, StoredSbom right, DiffService.DiffResult comparison,
                              boolean visibleScope, String filter, boolean regex, boolean negate,
                              DiffService.DiffSort sort, boolean ascending)
            throws Exception {
        return exporter.export(left, right, scanned(Map.of()), scanned(Map.of()),
                comparison, visibleScope, filter, regex, negate, sort, ascending);
    }

    /** A document that was checked, carrying the given bands and zero everywhere else. */
    private SbomSeverity scanned(Map<SeverityBand, Integer> counts) {
        Map<SeverityBand, Integer> bands = SbomSeverity.zeroedBands();
        bands.putAll(counts);
        return new SbomSeverity(1, bands);
    }

    private DiffService.DiffResult result(DiffRow... rows) {
        List<DiffRow> rowList = List.of(rows);
        return new DiffService.DiffResult(rowList, new DiffService.Summary(Map.of(
                Change.ADDED, count(rowList, Change.ADDED),
                Change.REMOVED, count(rowList, Change.REMOVED),
                Change.VERSION_CHANGED, count(rowList, Change.VERSION_CHANGED),
                Change.UNCHANGED, count(rowList, Change.UNCHANGED)), 0, 0));
    }

    private int count(List<DiffRow> rows, Change change) {
        return (int) rows.stream().filter(row -> row.change() == change).count();
    }

    private StoredSbom seed(String fixture, String filename) throws Exception {
        ParsedSbom parsed = fixture(fixture);
        StoredSbom sbom = new StoredSbom(UUID.randomUUID(), filename,
                Instant.parse("2026-09-05T12:34:56Z"), null,
                parsed.specVersion(), parsed.components().size());
        jdbc.update("INSERT INTO sbom (id, filename, uploaded_at, spec_version, component_count)"
                        + " VALUES (?, ?, ?, ?, ?)",
                sbom.id(), sbom.filename(), OffsetDateTime.ofInstant(sbom.uploadedAt(), ZoneOffset.UTC),
                sbom.specVersion(), sbom.componentCount());
        for (ParsedComponent component : parsed.components()) {
            jdbc.update("INSERT INTO component (id, sbom_id, bom_ref, group_name, name, version,"
                            + " purl, component_type, is_root, dependency_scope)"
                            + " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    UUID.randomUUID(), sbom.id(), component.bomRef(), component.group(), component.name(),
                    component.version(), component.purl(), component.type(), component.root(),
                    component.scope().name());
        }
        return sbom;
    }

    private StoredSbom document(String filename) {
        return new StoredSbom(UUID.randomUUID(), filename,
                Instant.parse("2026-09-05T12:34:56Z"), null, "1.6", 1);
    }

    private ParsedSbom fixture(String name) throws Exception {
        try (InputStream stream = getClass().getResourceAsStream("/sboms/" + name)) {
            assertThat(stream).as("fixture %s", name).isNotNull();
            return parser.parse(stream);
        }
    }

    private Workbook open(byte[] bytes) throws Exception {
        return new XSSFWorkbook(new ByteArrayInputStream(bytes));
    }

    private List<String> cells(Row row) {
        return java.util.stream.IntStream.range(0, row.getLastCellNum())
                .mapToObj(index -> row.getCell(index).getStringCellValue())
                .toList();
    }

    private Map<String, String> about(Workbook workbook) {
        Map<String, String> values = new LinkedHashMap<>();
        for (Row row : workbook.getSheet("About this export")) {
            values.put(row.getCell(0).getStringCellValue(), row.getCell(1).getStringCellValue());
        }
        return values;
    }

    private String nullToEmpty(String value) {
        return value == null ? "" : value;
    }
}
