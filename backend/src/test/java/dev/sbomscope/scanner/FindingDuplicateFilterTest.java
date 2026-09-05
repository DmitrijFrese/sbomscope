package dev.sbomscope.scanner;

import java.io.InputStream;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

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

/** The multi-version component filter, against the real adversarial Maven fixture. */
@SpringBootTest
@Transactional
class FindingDuplicateFilterTest {

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

        // One Keycloak version deliberately stays clean. Its presence must still qualify the
        // vulnerable sibling, because duplication belongs to the component inventory rather
        // than to whichever advisories survive the other filters.
        finding("org.keycloak", "keycloak-core", "4.8.3.Final");
        finding("io.netty", "netty-all", "4.1.42.Final");
        finding("io.netty", "netty-all", "4.1.68.Final");
    }

    private void finding(String group, String name, String version) {
        ParsedComponent component = parsed.components().stream()
                .filter(candidate -> Objects.equals(group, candidate.group()))
                .filter(candidate -> name.equals(candidate.name()))
                .filter(candidate -> version.equals(candidate.version()))
                .findFirst()
                .orElseThrow();

        jdbc.update("INSERT INTO vulnerability_scan (purl, scanned_at, scanner_version)"
                        + " VALUES (?, ?, ?)",
                component.purl(), OffsetDateTime.now(ZoneOffset.UTC), "test");
        jdbc.update("INSERT INTO vulnerability_finding"
                        + " (id, purl, osv_id, cve_id, severity_score) VALUES (?, ?, ?, ?, ?)",
                UUID.randomUUID(), component.purl(), "TEST-" + name + "-" + version,
                "CVE-2026-1000", new java.math.BigDecimal("7.5"));
    }

    private FindingQuery query(boolean duplicatesOnly, String filter) {
        return new FindingQuery(FindingQuery.SortField.COMPONENT, true, filter, false, false,
                EnumSet.allOf(FindingQuery.SeverityBand.class), null,
                duplicatesOnly, false, null, null);
    }

    private record Identity(String group, String name) {}

    private Identity identity(FindingRow row) {
        return new Identity(row.group(), row.name());
    }

    @Test
    void returnsEveryVersionOfOnlyTheRepeatedLibraryIdentities() {
        Map<Identity, Set<String>> versions = parsed.components().stream()
                .collect(Collectors.groupingBy(
                        component -> new Identity(component.group(), component.name()),
                        Collectors.mapping(ParsedComponent::version, Collectors.toSet())));

        List<FindingRow> rows = repository.rowsForSbom(sbomId, query(true, null));

        assertThat(rows).allSatisfy(row ->
                assertThat(versions.get(identity(row))).hasSizeGreaterThanOrEqualTo(2));
        assertThat(rows)
                .filteredOn(row -> row.coordinates().equals("org.keycloak:keycloak-core"))
                .extracting(FindingRow::version)
                .containsExactlyInAnyOrder("4.8.3.Final", "9.0.3");
        assertThat(rows)
                .filteredOn(row -> row.coordinates().equals("io.netty:netty-all"))
                .extracting(FindingRow::version)
                .containsExactlyInAnyOrder("4.1.42.Final", "4.1.68.Final");
        assertThat(rows).noneMatch(row -> row.coordinates().equals("org.apache.pdfbox:pdfbox"));

        assertThat(rows)
                .filteredOn(row -> row.coordinates().equals("org.keycloak:keycloak-core"))
                .filteredOn(row -> row.version().equals("9.0.3"))
                .singleElement()
                .satisfies(row -> assertThat(row.hasFinding()).isFalse());
    }

    @Test
    void bothCountsAgreeWithTheRowsTheirQueriesReturn() {
        FindingQuery query = query(true, null);
        List<FindingRow> rows = repository.rowsForSbom(sbomId, query);
        List<VulnerabilityFinding> findings = repository.findingsForSbom(sbomId, query);

        assertThat(repository.countRows(sbomId, query)).isEqualTo(rows.size());
        assertThat(repository.countFindings(sbomId, query)).isEqualTo(findings.size());
        assertThat(rows).hasSizeGreaterThan(findings.size());
    }

    @Test
    void composesWithTheTextFilter() {
        assertThat(repository.rowsForSbom(sbomId, query(true, "keycloak-core")))
                .allMatch(row -> row.coordinates().equals("org.keycloak:keycloak-core"))
                .extracting(FindingRow::version)
                .containsExactlyInAnyOrder("4.8.3.Final", "9.0.3");
    }

    @Test
    void leavingTheFilterOffPreservesTheExistingResult() {
        List<FindingRow> existing = repository.rowsForSbom(sbomId, FindingQuery.everything());
        List<FindingRow> explicitlyOff = repository.rowsForSbom(sbomId, query(false, null));

        assertThat(explicitlyOff).containsExactlyInAnyOrderElementsOf(existing);
        assertThat(explicitlyOff).anyMatch(row -> row.coordinates().equals("org.apache.pdfbox:pdfbox"));
    }

    @Test
    void selectionSurvivesPagingAndTextFilterRemoval() {
        FindingQuery query = query(true, "keycloak");

        assertThat(query.withoutPaging().duplicatesOnly()).isTrue();
        assertThat(query.unfiltered().duplicatesOnly()).isTrue();
    }
}
