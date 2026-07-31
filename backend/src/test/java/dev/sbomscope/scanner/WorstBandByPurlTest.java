package dev.sbomscope.scanner;

import java.math.BigDecimal;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;

import dev.sbomscope.scanner.FindingQuery.SeverityBand;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The worst band per component, as the Component Inspector's finder marks it.
 *
 * <p>The property worth protecting is not "the highest score wins" but the one the schema was
 * shaped around: <b>a component nobody has scanned must not be reported as clean</b>. It is
 * absent from the map entirely, so the caller has to decide what to do about it rather than
 * receiving a reassuring answer by default.
 */
@SpringBootTest
class WorstBandByPurlTest {

    @Autowired
    private VulnerabilityRepository repository;

    @Autowired
    private JdbcTemplate jdbc;

    private final UUID sbomId = UUID.randomUUID();
    private final String tag = UUID.randomUUID().toString().substring(0, 8);

    @BeforeEach
    void seed() {
        jdbc.update("INSERT INTO sbom (id, filename, uploaded_at, spec_version, component_count)"
                        + " VALUES (?, ?, ?, ?, ?)",
                sbomId, "bands.cdx.json", OffsetDateTime.now(ZoneOffset.UTC), "1.6", 0);
    }

    private String purlFor(String name) {
        return "pkg:maven/dev.sbomscope.test/%s-%s@1.0.0".formatted(name, tag);
    }

    /** A component row, with a scan record only when {@code scanned}. */
    private String component(String name, boolean scanned) {
        String purl = purlFor(name);
        jdbc.update("INSERT INTO component (id, sbom_id, bom_ref, group_name, name, version, purl,"
                        + " dependency_scope) VALUES (?, ?, ?, ?, ?, ?, ?, 'DIRECT')",
                UUID.randomUUID(), sbomId, purl, "dev.sbomscope.test", name, "1.0.0", purl);
        if (scanned) {
            jdbc.update("INSERT INTO vulnerability_scan (purl, scanned_at, scanner_version)"
                            + " VALUES (?, ?, ?)",
                    purl, OffsetDateTime.now(ZoneOffset.UTC), "test");
        }
        return purl;
    }

    private void finding(String purl, String osvId, BigDecimal score) {
        jdbc.update("INSERT INTO vulnerability_finding (id, purl, osv_id, cve_id, severity_score)"
                        + " VALUES (?, ?, ?, ?, ?)",
                UUID.randomUUID(), purl, osvId, null, score);
    }

    @Test
    void takesTheWorstOfSeveralFindings() {
        String purl = component("many", true);
        finding(purl, "GHSA-a", new BigDecimal("4.2"));
        finding(purl, "GHSA-b", new BigDecimal("9.5"));
        finding(purl, "GHSA-c", new BigDecimal("7.1"));

        assertThat(repository.worstBandByPurl(sbomId)).containsEntry(purl, SeverityBand.CRITICAL);
    }

    @Test
    void aScannedComponentWithNothingAgainstItIsClean() {
        String purl = component("quiet", true);

        assertThat(repository.worstBandByPurl(sbomId)).containsEntry(purl, SeverityBand.CLEAN);
    }

    @Test
    void aComponentNobodyHasScannedIsAbsentRatherThanClean() {
        // The whole reason this returns a map with holes in it instead of a total function.
        // Defaulting the missing case to CLEAN somewhere downstream would make an unscanned
        // SBOM render as a clean one, which is the failure the vulnerability_scan table exists
        // to make impossible.
        String purl = component("unchecked", false);

        assertThat(repository.worstBandByPurl(sbomId)).doesNotContainKey(purl);
    }

    @Test
    void anUnscoredAdvisoryIsNoneAndNeverClean() {
        // "We don't know how bad this is" and "this is fine" must not render alike.
        String purl = component("unscored", true);
        finding(purl, "GHSA-unscored", null);

        assertThat(repository.worstBandByPurl(sbomId)).containsEntry(purl, SeverityBand.NONE);
    }

    @Test
    void aScoredFindingOutranksAnUnscoredOneOnTheSameComponent() {
        // Follows the ranking orderBy already uses — scored, then unscored, then clean — rather
        // than inventing a second opinion about where an unknown severity sits.
        String purl = component("mixed", true);
        finding(purl, "GHSA-unscored", null);
        finding(purl, "GHSA-low", new BigDecimal("2.0"));

        assertThat(repository.worstBandByPurl(sbomId)).containsEntry(purl, SeverityBand.LOW);
    }

    @Test
    void reportsEachComponentSeparately() {
        String critical = component("crit", true);
        finding(critical, "GHSA-crit", new BigDecimal("9.9"));
        String clean = component("fine", true);
        String unscanned = component("nobody", false);

        Map<String, SeverityBand> worst = repository.worstBandByPurl(sbomId);

        assertThat(worst).containsEntry(critical, SeverityBand.CRITICAL)
                .containsEntry(clean, SeverityBand.CLEAN)
                .doesNotContainKey(unscanned);
    }
}
