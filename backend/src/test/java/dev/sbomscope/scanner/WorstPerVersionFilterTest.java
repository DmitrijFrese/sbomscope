package dev.sbomscope.scanner;

import java.io.InputStream;
import java.math.BigDecimal;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.annotation.Transactional;

import dev.sbomscope.sbom.CycloneDxParser;
import dev.sbomscope.sbom.ParsedSbom;
import dev.sbomscope.sbom.ParsedSbom.ParsedComponent;

import static org.assertj.core.api.Assertions.assertThat;

/** One representative finding per exact purl, against the real multi-version fixture. */
@SpringBootTest
@Transactional
class WorstPerVersionFilterTest {

    @Autowired
    private VulnerabilityRepository repository;

    @Autowired
    private CycloneDxParser parser;

    @Autowired
    private JdbcTemplate jdbc;

    private final UUID sbomId = UUID.randomUUID();
    private ParsedSbom parsed;

    @BeforeEach
    void seed() throws Exception {
        try (InputStream stream = getClass().getResourceAsStream("/sboms/vuln-multi-module.cdx.json")) {
            assertThat(stream).as("the adversarial multi-module fixture").isNotNull();
            parsed = parser.parse(stream);
        }

        jdbc.update("INSERT INTO sbom (id, filename, uploaded_at, spec_version, component_count)"
                        + " VALUES (?, ?, ?, ?, ?)",
                sbomId, "vuln-multi-module.cdx.json", OffsetDateTime.now(ZoneOffset.UTC),
                parsed.specVersion(), parsed.components().size());
        for (ParsedComponent component : parsed.components()) {
            jdbc.update("INSERT INTO component (id, sbom_id, bom_ref, group_name, name, version,"
                            + " purl, component_type, is_root, dependency_scope)"
                            + " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    UUID.randomUUID(), sbomId, component.bomRef(), component.group(), component.name(),
                    component.version(), component.purl(), component.type(), component.root(),
                    component.scope().name());
        }

        finding("org.keycloak", "keycloak-core", "4.8.3.Final", "TEST-LATER",
                "CVE-2026-2002", "9.5", "2021-01-01T00:00:00Z");
        finding("org.keycloak", "keycloak-core", "4.8.3.Final", "TEST-EARLIER",
                "CVE-2026-2001", "9.5", "2020-01-01T00:00:00Z");
        finding("org.keycloak", "keycloak-core", "4.8.3.Final", "TEST-LOW",
                "CVE-2026-2000", "3.0", "2019-01-01T00:00:00Z");
        finding("org.keycloak", "keycloak-core", "9.0.3", "TEST-HIGH",
                "CVE-2026-3000", "7.5", "2022-01-01T00:00:00Z");
    }

    private void finding(String group, String name, String version, String osvId,
                         String cveId, String score, String publishedAt) {
        ParsedComponent component = parsed.components().stream()
                .filter(candidate -> Objects.equals(group, candidate.group()))
                .filter(candidate -> name.equals(candidate.name()))
                .filter(candidate -> version.equals(candidate.version()))
                .findFirst()
                .orElseThrow();
        jdbc.update("MERGE INTO vulnerability_scan (purl, scanned_at, scanner_version)"
                        + " KEY (purl) VALUES (?, ?, ?)",
                component.purl(), OffsetDateTime.now(ZoneOffset.UTC), "test");
        jdbc.update("INSERT INTO vulnerability_finding"
                        + " (id, purl, osv_id, cve_id, severity_score, published_at)"
                        + " VALUES (?, ?, ?, ?, ?, ?)",
                UUID.randomUUID(), component.purl(), osvId, cveId, new BigDecimal(score),
                OffsetDateTime.parse(publishedAt));
    }

    private FindingQuery query(String filter, EnumSet<FindingQuery.SeverityBand> severities,
                               boolean worstPerVersion, Integer limit) {
        return new FindingQuery(FindingQuery.SortField.SEVERITY, false, filter, false, false,
                severities, null, false, worstPerVersion, limit, 0);
    }

    private FindingQuery worst() {
        return query(null, EnumSet.allOf(FindingQuery.SeverityBand.class), true, null);
    }

    @Test
    void appliesTheCollapseToRowsFindingsAndBothTotals() {
        FindingQuery worst = worst();
        List<FindingRow> rows = repository.rowsForSbom(sbomId, worst);
        List<VulnerabilityFinding> findings = repository.findingsForSbom(sbomId, worst);

        assertThat(repository.countRows(sbomId, worst)).isEqualTo(rows.size());
        assertThat(repository.countFindings(sbomId, worst)).isEqualTo(findings.size());
        assertThat(repository.countRows(sbomId, worst))
                .isLessThan(repository.countRows(sbomId, query(null,
                        EnumSet.allOf(FindingQuery.SeverityBand.class), false, null)));
        assertThat(repository.countFindings(sbomId, worst))
                .isLessThan(repository.countFindings(sbomId, query(null,
                        EnumSet.allOf(FindingQuery.SeverityBand.class), false, null)));

        FindingQuery firstPage = query(null, EnumSet.allOf(FindingQuery.SeverityBand.class), true, 1);
        assertThat(repository.rowsForSbom(sbomId, firstPage)).hasSize(1);
        assertThat(repository.countRows(sbomId, firstPage)).isEqualTo(rows.size());
        assertThat(repository.findingsForSbom(sbomId, firstPage)).hasSize(1);
        assertThat(repository.countFindings(sbomId, firstPage)).isEqualTo(findings.size());
    }

    @Test
    void keepsCleanComponentsAndEachVersionOfTheSameLibrary() {
        List<FindingRow> rows = repository.rowsForSbom(sbomId, worst());

        assertThat(rows).anySatisfy(row -> {
            assertThat(row.coordinates()).isEqualTo("org.apache.pdfbox:pdfbox");
            assertThat(row.hasFinding()).isFalse();
        });
        assertThat(rows)
                .filteredOn(row -> row.coordinates().equals("org.keycloak:keycloak-core"))
                .extracting(FindingRow::version)
                .containsExactlyInAnyOrder("4.8.3.Final", "9.0.3");
    }

    @Test
    void breaksEqualSeverityByEarliestPublicationDate() {
        assertThat(repository.rowsForSbom(sbomId, worst()))
                .filteredOn(row -> row.coordinates().equals("org.keycloak:keycloak-core"))
                .filteredOn(row -> row.version().equals("4.8.3.Final"))
                .singleElement()
                .extracting(FindingRow::osvId)
                .isEqualTo("TEST-EARLIER");
    }

    @Test
    void collapseHappensAfterTheTextFilter() {
        assertThat(repository.rowsForSbom(sbomId, query("TEST-LOW",
                EnumSet.allOf(FindingQuery.SeverityBand.class), true, null)))
                .singleElement()
                .extracting(FindingRow::osvId)
                .isEqualTo("TEST-LOW");
    }

    @Test
    void filteredBandCountsMoveWithTextButIgnoreTheSeveritySelection() {
        FindingQuery criticalUnticked = query("keycloak-core",
                EnumSet.of(FindingQuery.SeverityBand.HIGH), true, null);

        Map<FindingQuery.SeverityBand, Integer> counts =
                repository.filteredCountsByBand(sbomId, criticalUnticked);

        assertThat(counts.get(FindingQuery.SeverityBand.CRITICAL)).isEqualTo(1);
        assertThat(counts.get(FindingQuery.SeverityBand.HIGH)).isEqualTo(1);
        assertThat(counts.get(FindingQuery.SeverityBand.CLEAN)).isZero();
        assertThat(repository.countRows(sbomId, criticalUnticked)).isEqualTo(1);
    }

    @Test
    void selectionSurvivesPagingAndTextFilterRemoval() {
        FindingQuery query = query("keycloak", EnumSet.of(FindingQuery.SeverityBand.HIGH), true, 20);

        assertThat(query.withoutPaging().worstPerVersion()).isTrue();
        assertThat(query.unfiltered().worstPerVersion()).isTrue();
    }
}
