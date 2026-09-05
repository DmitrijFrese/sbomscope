package dev.sbomscope.diff;

import java.io.InputStream;
import java.math.BigDecimal;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.annotation.Transactional;

import dev.sbomscope.diff.DiffRow.Change;
import dev.sbomscope.diff.DiffService.DiffSort;
import dev.sbomscope.sbom.CycloneDxParser;
import dev.sbomscope.sbom.ParsedSbom;
import dev.sbomscope.sbom.ParsedSbom.ParsedComponent;
import dev.sbomscope.scanner.FindingQuery;
import dev.sbomscope.scanner.InvalidFilterPatternException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@SpringBootTest
@Transactional
class DiffServiceTest {

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
    void anSbomAgainstItselfIsEntirelyUnchanged() throws Exception {
        UUID sbomId = seed("maven-sbomscope.cdx.json");

        DiffService.DiffResult result = diffs.compare(sbomId, sbomId, null, false, false);

        assertThat(result.rows()).isNotEmpty().allMatch(row -> row.change() == Change.UNCHANGED);
        assertThat(result.summary().changes().get(Change.UNCHANGED)).isEqualTo(result.rows().size());
        assertThat(result.summary().changes().get(Change.ADDED)).isZero();
        assertThat(result.summary().changes().get(Change.REMOVED)).isZero();
        assertThat(result.summary().changes().get(Change.VERSION_CHANGED)).isZero();
        assertThat(result.summary().cveIdsGained()).isZero();
        assertThat(result.summary().cveIdsLost()).isZero();
    }

    @Test
    void disjointEcosystemsAreOnlyAddedAndRemoved() throws Exception {
        UUID maven = seed("maven-sbomscope.cdx.json");
        UUID npm = seed("npm-frontend.cdx.json");

        DiffService.DiffResult result = diffs.compare(maven, npm, null, false, false);

        assertThat(result.rows()).isNotEmpty()
                .allMatch(row -> row.change() == Change.ADDED || row.change() == Change.REMOVED);
        assertThat(result.rows()).noneMatch(row -> row.change() == Change.VERSION_CHANGED);
        assertThat(result.summary().changes().get(Change.ADDED)).isPositive();
        assertThat(result.summary().changes().get(Change.REMOVED)).isPositive();
        assertThat(result.summary().changes().get(Change.VERSION_CHANGED)).isZero();
        assertThat(result.summary().changes().get(Change.UNCHANGED)).isZero();
    }

    @Test
    void oneVersionOnEachSideBecomesOneVersionChange() throws Exception {
        UUID left = seed("vuln-multi-module.cdx.json");
        UUID right = seed("vuln-multi-module.cdx.json");
        keepOnlyVersion(left, "org.keycloak", "keycloak-core", "4.8.3.Final");
        keepOnlyVersion(right, "org.keycloak", "keycloak-core", "9.0.3");

        List<DiffRow> keycloak = diffs.compare(left, right, "keycloak-core", false, false).rows();

        assertThat(keycloak).singleElement().satisfies(row -> {
            assertThat(row.change()).isEqualTo(Change.VERSION_CHANGED);
            assertThat(row.left().version()).isEqualTo("4.8.3.Final");
            assertThat(row.right().version()).isEqualTo("9.0.3");
        });
    }

    @Test
    void severalVersionsAreNeverGuessedIntoAVersionChange() throws Exception {
        UUID left = seed("vuln-multi-module.cdx.json");
        UUID right = seed("vuln-multi-module.cdx.json");
        jdbc.update("DELETE FROM component WHERE sbom_id = ? AND group_name = ?"
                        + " AND name = ? AND version = ?",
                right, "org.keycloak", "keycloak-core", "4.8.3.Final");

        List<DiffRow> keycloak = diffs.compare(left, right, "keycloak-core", false, false).rows();

        assertThat(keycloak).hasSize(2);
        assertThat(keycloak).extracting(row -> row.left() != null
                        ? row.left().version() : row.right().version())
                .containsExactly("4.8.3.Final", "9.0.3");
        assertThat(keycloak).extracting(DiffRow::change)
                .containsExactly(Change.REMOVED, Change.UNCHANGED)
                .doesNotContain(Change.VERSION_CHANGED);
    }

    @Test
    void versionsAreSortedWithVersionOrder() throws Exception {
        UUID left = seed("vuln-multi-module.cdx.json");
        UUID right = seed("vuln-multi-module.cdx.json");
        jdbc.update("DELETE FROM component WHERE sbom_id = ?", right);
        jdbc.update("DELETE FROM component WHERE sbom_id = ?"
                + " AND NOT (group_name = 'org.keycloak' AND name = 'keycloak-core')", left);
        jdbc.update("UPDATE component SET version = '1.9.0' WHERE sbom_id = ? AND version = ?",
                left, "4.8.3.Final");
        jdbc.update("UPDATE component SET version = '1.10.0' WHERE sbom_id = ? AND version = ?",
                left, "9.0.3");

        List<DiffRow> rows = diffs.compare(left, right, null, false, false,
                DiffSort.COORDINATES, false).rows();

        assertThat(rows).extracting(row -> row.left().version())
                .containsExactly("1.9.0", "1.10.0");
    }

    @Test
    void rightVersionsBreakEqualCoordinatesAfterTheLeftVersionKey() throws Exception {
        UUID left = seed("vuln-multi-module.cdx.json");
        UUID right = seed("vuln-multi-module.cdx.json");
        jdbc.update("DELETE FROM component WHERE sbom_id = ?", left);
        jdbc.update("DELETE FROM component WHERE sbom_id = ?"
                + " AND NOT (group_name = 'org.keycloak' AND name = 'keycloak-core')", right);
        jdbc.update("UPDATE component SET version = '1.9.0' WHERE sbom_id = ? AND version = ?",
                right, "4.8.3.Final");
        jdbc.update("UPDATE component SET version = '1.10.0' WHERE sbom_id = ? AND version = ?",
                right, "9.0.3");

        List<DiffRow> rows = diffs.compare(left, right, null, false, false,
                DiffSort.COORDINATES, false).rows();

        assertThat(rows).extracting(row -> row.right().version())
                .containsExactly("1.9.0", "1.10.0");
    }

    @Test
    void coordinatesAscendingKeepsTheExistingOrderAndDescendingReversesOnlyCoordinates()
            throws Exception {
        UUID left = seed("maven-sbomscope.cdx.json");
        UUID right = seed("maven-sbomscope.cdx.json");

        List<DiffRow> defaultRows = diffs.compare(left, right, null, false, false).rows();
        List<DiffRow> ascending = diffs.compare(left, right, null, false, false,
                DiffSort.COORDINATES, true).rows();
        List<DiffRow> descending = diffs.compare(left, right, null, false, false,
                DiffSort.COORDINATES, false).rows();

        assertThat(ascending).isEqualTo(defaultRows);
        assertCoordinatesAscending(ascending);
        assertThat(descending).isSortedAccordingTo(Comparator.comparing(DiffRow::group,
                        Comparator.nullsLast(String.CASE_INSENSITIVE_ORDER.reversed()))
                .thenComparing(DiffRow::name,
                        Comparator.nullsLast(String.CASE_INSENSITIVE_ORDER.reversed())));
    }

    @Test
    void changeSortKeepsCoordinatesAscendingWithinEveryChangeGroup() throws Exception {
        UUID left = seed("maven-sbomscope.cdx.json");
        UUID right = seed("maven-sbomscope.cdx.json");
        List<String> purls = jdbc.queryForList("""
                SELECT DISTINCT purl FROM component
                WHERE sbom_id = ? AND purl IS NOT NULL
                ORDER BY purl LIMIT 3
                """, String.class, left);

        jdbc.update("DELETE FROM component WHERE sbom_id = ? AND purl = ?", right, purls.get(0));
        jdbc.update("DELETE FROM component WHERE sbom_id = ? AND purl = ?", left, purls.get(1));
        jdbc.update("UPDATE component SET version = '999.0.0' WHERE sbom_id = ? AND purl = ?",
                left, purls.get(2));

        List<DiffRow> ascending = diffs.compare(left, right, null, false, false,
                DiffSort.CHANGE, true).rows();
        List<DiffRow> descending = diffs.compare(left, right, null, false, false,
                DiffSort.CHANGE, false).rows();

        assertThat(ascending).extracting(DiffRow::change)
                .isSortedAccordingTo(Comparator.comparingInt((Change change) -> change.ordinal()));
        assertThat(descending).extracting(DiffRow::change)
                .isSortedAccordingTo(Comparator.comparingInt((Change change) -> change.ordinal()).reversed());
        assertCoordinatesAscendingWithinChange(ascending);
        assertCoordinatesAscendingWithinChange(descending);
    }

    @Test
    void sendsACveToNvdAndAnOsvOnlyAdvisoryToOsvDev() throws Exception {
        // The diff's cells link the same way the findings table's do, so both destinations come
        // from AdvisoryLinks rather than from a template written beside either caller. An
        // OSV-only advisory has no NVD page at all, so getting this wrong is not a cosmetic
        // difference — it is a link to a page that does not exist.
        UUID left = seed("vuln-multi-module.cdx.json");
        UUID right = seed("vuln-multi-module.cdx.json");
        ParsedComponent component = component("vuln-multi-module.cdx.json",
                "org.keycloak", "keycloak-core", "4.8.3.Final");
        finding(component.purl(), "OSV-ONLY-2026", null, new BigDecimal("7.5"));
        ParsedComponent withCve = component("vuln-multi-module.cdx.json",
                "org.keycloak", "keycloak-core", "9.0.3");
        finding(withCve.purl(), "GHSA-with-cve", "CVE-2026-4242", new BigDecimal("5.0"));

        List<DiffRow> rows = diffs.compare(left, right, "keycloak-core", false, false).rows();

        assertThat(rows).anySatisfy(row -> assertThat(row.left().advisoryUrls())
                .containsEntry("OSV-ONLY-2026", "https://osv.dev/vulnerability/OSV-ONLY-2026"));
        assertThat(rows).anySatisfy(row -> assertThat(row.left().advisoryUrls())
                .containsEntry("CVE-2026-4242", "https://nvd.nist.gov/vuln/detail/CVE-2026-4242"));
        // The identifier list is unchanged by this — it is what the filter searches and what the
        // workbook prints, and both still see plain ids.
        assertThat(rows).anySatisfy(row -> assertThat(row.left().cveIds()).contains("CVE-2026-4242"));
    }

    @Test
    void literalRegexAndNegatedFiltersMatchWholeRows() throws Exception {
        UUID left = seed("vuln-multi-module.cdx.json");
        UUID right = seed("vuln-multi-module.cdx.json");
        ParsedComponent component = component("vuln-multi-module.cdx.json",
                "org.keycloak", "keycloak-core", "4.8.3.Final");
        finding(component.purl(), "OSV-ONLY-2026", null, new BigDecimal("7.5"));

        List<DiffRow> literal = diffs.compare(left, right, "osv-only-2026", false, false).rows();
        List<DiffRow> regex = diffs.compare(left, right, "^4\\.8\\.3\\.Final$", true, false).rows();
        List<DiffRow> negated = diffs.compare(left, right, "keycloak-core", false, true).rows();

        assertThat(literal).singleElement().satisfies(row -> {
            assertThat(row.left().cveIds()).containsExactly("OSV-ONLY-2026");
            assertThat(row.left().counts().get(FindingQuery.SeverityBand.HIGH)).isEqualTo(1);
            assertThat(row.right().cveIds()).containsExactly("OSV-ONLY-2026");
        });
        assertThat(regex).isNotEmpty()
                .allSatisfy(row -> assertThat(row.left().version()).isEqualTo("4.8.3.Final"));
        assertThat(negated).noneMatch(row -> row.coordinates().contains("keycloak-core"));
        assertThat(negated).hasSizeGreaterThan(literal.size());
    }

    @Test
    void invalidRegexIsReportedBeforeQuerying() throws Exception {
        UUID left = seed("maven-sbomscope.cdx.json");
        UUID right = seed("npm-frontend.cdx.json");

        assertThatThrownBy(() -> diffs.compare(left, right, "^(spring", true, false))
                .isInstanceOf(InvalidFilterPatternException.class);
    }

    private UUID seed(String fixture) throws Exception {
        ParsedSbom parsed = fixture(fixture);
        UUID id = UUID.randomUUID();
        jdbc.update("INSERT INTO sbom (id, filename, uploaded_at, spec_version, component_count)"
                        + " VALUES (?, ?, ?, ?, ?)",
                id, fixture, OffsetDateTime.now(ZoneOffset.UTC),
                parsed.specVersion(), parsed.components().size());

        for (ParsedComponent component : parsed.components()) {
            jdbc.update("INSERT INTO component (id, sbom_id, bom_ref, group_name, name, version,"
                            + " purl, component_type, is_root, dependency_scope)"
                            + " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    UUID.randomUUID(), id, component.bomRef(), component.group(), component.name(),
                    component.version(), component.purl(), component.type(), component.root(),
                    component.scope().name());
        }
        return id;
    }

    private void keepOnlyVersion(UUID sbomId, String group, String name, String version) {
        jdbc.update("DELETE FROM component WHERE sbom_id = ? AND group_name = ?"
                        + " AND name = ? AND version <> ?",
                sbomId, group, name, version);
    }

    private ParsedComponent component(String fixture, String group, String name, String version)
            throws Exception {
        return fixture(fixture).components().stream()
                .filter(candidate -> Objects.equals(group, candidate.group()))
                .filter(candidate -> name.equals(candidate.name()))
                .filter(candidate -> version.equals(candidate.version()))
                .findFirst()
                .orElseThrow();
    }

    private void finding(String purl, String osvId, String cveId, BigDecimal severity) {
        jdbc.update("MERGE INTO vulnerability_scan (purl, scanned_at, scanner_version)"
                        + " KEY (purl) VALUES (?, ?, ?)",
                purl, OffsetDateTime.now(ZoneOffset.UTC), "test");
        jdbc.update("INSERT INTO vulnerability_finding"
                        + " (id, purl, osv_id, cve_id, severity_score) VALUES (?, ?, ?, ?, ?)",
                UUID.randomUUID(), purl, osvId, cveId, severity);
    }

    private void assertCoordinatesAscending(List<DiffRow> rows) {
        assertThat(rows).isSortedAccordingTo(Comparator.comparing(DiffRow::group,
                        Comparator.nullsLast(String.CASE_INSENSITIVE_ORDER))
                .thenComparing(DiffRow::name, Comparator.nullsLast(String.CASE_INSENSITIVE_ORDER)));
    }

    private void assertCoordinatesAscendingWithinChange(List<DiffRow> rows) {
        for (Change change : Change.values()) {
            assertCoordinatesAscending(rows.stream().filter(row -> row.change() == change).toList());
        }
    }

    private ParsedSbom fixture(String name) throws Exception {
        try (InputStream stream = getClass().getResourceAsStream("/sboms/" + name)) {
            assertThat(stream).as("fixture %s", name).isNotNull();
            return parser.parse(stream);
        }
    }
}
