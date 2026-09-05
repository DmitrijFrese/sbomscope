package dev.sbomscope.sbom;

import java.io.InputStream;
import java.time.Instant;
import java.util.EnumSet;
import java.util.List;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.annotation.Transactional;

import dev.sbomscope.scanner.FindingQuery;
import dev.sbomscope.scanner.FindingRow;
import dev.sbomscope.scanner.VersionOrder;
import dev.sbomscope.scanner.VulnerabilityRepository;

import static org.assertj.core.api.Assertions.assertThat;

/** Component version sort-key storage, repair and findings-table ordering. */
@SpringBootTest
@Transactional
class ComponentVersionSortTest {

    @Autowired
    private CycloneDxParser parser;

    @Autowired
    private SbomRepository sboms;

    @Autowired
    private VulnerabilityRepository findings;

    @Autowired
    private JdbcTemplate jdbc;

    private ParsedSbom fixture(String name) {
        InputStream stream = getClass().getResourceAsStream("/sboms/" + name);
        assertThat(stream).as("fixture %s should exist", name).isNotNull();
        return parser.parse(stream);
    }

    private UUID sbom(String filename, int componentCount) {
        UUID id = UUID.randomUUID();
        sboms.insertSbom(new StoredSbom(id, filename, Instant.now(), null, "1.6", componentCount));
        return id;
    }

    private void legacyComponent(UUID sbomId, String name, String version, String sortKey) {
        String purl = "pkg:maven/dev.sbomscope.test/%s@%s".formatted(name, version);
        jdbc.update("""
                INSERT INTO component
                    (id, sbom_id, bom_ref, group_name, name, version, version_sort, purl,
                     component_type, is_root, dependency_scope)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                UUID.randomUUID(), sbomId, purl, "dev.sbomscope.test", name, version, sortKey,
                purl, "library", false, DependencyScope.DIRECT.name());
    }

    private FindingQuery versionQuery(boolean ascending) {
        return new FindingQuery(
                FindingQuery.SortField.VERSION,
                ascending,
                null,
                false,
                false,
                EnumSet.allOf(FindingQuery.SeverityBand.class),
                null,
                false,
                false,
                null,
                null);
    }

    @Test
    void importWritesKeysFromVersionOrdersOwnParseAcrossTheCycloneDxFixtures() {
        for (String filename : List.of(
                "maven-sbomscope.cdx.json", "npm-frontend.cdx.json", "vuln-multi-module.cdx.json")) {
            ParsedSbom parsed = fixture(filename);
            UUID sbomId = sbom(filename, parsed.components().size());
            sboms.insertComponents(sbomId, parsed.components());

            List<String[]> stored = jdbc.query(
                    "SELECT version, version_sort FROM component WHERE sbom_id = ?",
                    (rs, row) -> new String[] {rs.getString("version"), rs.getString("version_sort")},
                    sbomId);

            assertThat(stored).hasSize(parsed.components().size()).allSatisfy(component ->
                    assertThat(component[1]).isEqualTo(VersionOrder.sortKey(component[0])));
        }
    }

    @Test
    void backfillFillsPreV13RowsAndLeavesFilledRowsAlone() {
        UUID sbomId = sbom("pre-v13.cdx.json", 2);
        legacyComponent(sbomId, "missing-key", "1.9.0", null);
        legacyComponent(sbomId, "already-filled", "1.10.0", "already-written");

        new ComponentVersionSortBackfill(sboms).backfill();

        assertThat(jdbc.queryForObject(
                "SELECT version_sort FROM component WHERE sbom_id = ? AND name = 'missing-key'",
                String.class, sbomId)).isEqualTo(VersionOrder.sortKey("1.9.0"));
        assertThat(jdbc.queryForObject(
                "SELECT version_sort FROM component WHERE sbom_id = ? AND name = 'already-filled'",
                String.class, sbomId)).isEqualTo("already-written");
        assertThat(sboms.backfillVersionSortKeys()).isZero();
    }

    @Test
    void versionOrderingIsNumericAndLeavesAnAbsentKeyLastInBothDirections() {
        UUID sbomId = sbom("version-order.cdx.json", 3);
        legacyComponent(sbomId, "one-nine", "1.9.0", VersionOrder.sortKey("1.9.0"));
        legacyComponent(sbomId, "one-ten", "1.10.0", VersionOrder.sortKey("1.10.0"));
        legacyComponent(sbomId, "no-key", "2.0.0", null);

        assertThat(findings.rowsForSbom(sbomId, versionQuery(true)))
                .extracting(FindingRow::name)
                .containsExactly("one-nine", "one-ten", "no-key");
        assertThat(findings.rowsForSbom(sbomId, versionQuery(false)))
                .extracting(FindingRow::name)
                .containsExactly("one-ten", "one-nine", "no-key");
    }
}
