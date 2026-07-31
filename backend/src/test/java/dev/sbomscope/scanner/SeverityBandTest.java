package dev.sbomscope.scanner;

import java.math.BigDecimal;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.EnumSet;
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
 * Band boundaries, against the real Flyway-built schema.
 *
 * <p>The filter and the summary counts read one SQL expression, so the number shown beside
 * "High" describes exactly the rows that ticking High produces. That is the property worth
 * protecting here — the two agreeing by construction is easy to break by editing one of
 * them, and the failure would be silent.
 *
 * <p>Scores are placed either side of every threshold rather than in the middle of each
 * band, because a comparison flipped from {@code >=} to {@code >} only shows up at the edge.
 */
@SpringBootTest
class SeverityBandTest {

    @Autowired
    private VulnerabilityRepository repository;

    @Autowired
    private JdbcTemplate jdbc;

    /** Unique per run, so these rows cannot collide with another test's fixture. */
    private final UUID sbomId = UUID.randomUUID();

    private int purlCounter;

    @BeforeEach
    void seed() {
        jdbc.update("INSERT INTO sbom (id, filename, uploaded_at, spec_version, component_count)"
                + " VALUES (?, ?, ?, ?, ?)",
                sbomId, "bands.cdx.json", OffsetDateTime.now(ZoneOffset.UTC), "1.6", 0);

        // Either side of each threshold, plus the two cases that are not scores at all.
        finding(new BigDecimal("10.0"));
        finding(new BigDecimal("9.0"));
        finding(new BigDecimal("8.9"));
        finding(new BigDecimal("7.0"));
        finding(new BigDecimal("6.9"));
        finding(new BigDecimal("4.0"));
        finding(new BigDecimal("3.9"));
        finding(new BigDecimal("0.0"));
        finding(null);
        clean();
    }

    /** A component carrying one vulnerability at the given score; null means unscored. */
    private void finding(BigDecimal score) {
        String purl = component();
        jdbc.update("INSERT INTO vulnerability_finding (id, purl, osv_id, cve_id, severity_score)"
                        + " VALUES (?, ?, ?, ?, ?)",
                UUID.randomUUID(), purl, "GHSA-test-" + purlCounter, "CVE-2026-" + purlCounter, score);
    }

    /** A component that was scanned and had nothing found against it. */
    private void clean() {
        component();
    }

    private String component() {
        // Scans and findings are keyed by purl across every SBOM — that shared cache is the
        // point of the design — so the fixture has to be unique per test instance rather
        // than per SBOM, or the second test method collides with the first.
        String purl = "pkg:maven/dev.sbomscope.test/lib-%s-%d@1.0.0"
                .formatted(sbomId.toString().substring(0, 8), purlCounter++);
        jdbc.update("INSERT INTO component (id, sbom_id, bom_ref, group_name, name, version, purl)"
                        + " VALUES (?, ?, ?, ?, ?, ?, ?)",
                UUID.randomUUID(), sbomId, purl, "dev.sbomscope.test", "lib-" + purlCounter, "1.0.0", purl);
        jdbc.update("INSERT INTO vulnerability_scan (purl, scanned_at, scanner_version) VALUES (?, ?, ?)",
                purl, OffsetDateTime.now(ZoneOffset.UTC), "test");
        return purl;
    }

    private int rowsIn(SeverityBand band) {
        return repository.countRows(sbomId,
                new FindingQuery(FindingQuery.SortField.SEVERITY, false, null, false, false,
                        EnumSet.of(band), null, null, null));
    }

    @Test
    void placesScoresInTheBandTheirThresholdSays() {
        Map<SeverityBand, Integer> counts = repository.countsByBand(sbomId);

        assertThat(counts.get(SeverityBand.CRITICAL)).as("10.0 and 9.0").isEqualTo(2);
        assertThat(counts.get(SeverityBand.HIGH)).as("8.9 and 7.0").isEqualTo(2);
        assertThat(counts.get(SeverityBand.MEDIUM)).as("6.9 and 4.0").isEqualTo(2);
        assertThat(counts.get(SeverityBand.LOW)).as("3.9 and 0.0").isEqualTo(2);
        assertThat(counts.get(SeverityBand.NONE)).as("the unscored advisory").isEqualTo(1);
    }

    @Test
    void countsAndFilterDescribeTheSameRows() {
        // The counts are rendered on the filter chips themselves, so a number that did not
        // match what clicking it produces would be worse than showing no number at all.
        Map<SeverityBand, Integer> counts = repository.countsByBand(sbomId);

        for (SeverityBand band : SeverityBand.values()) {
            assertThat(rowsIn(band))
                    .as("filtering to %s must return exactly what the summary claims", band)
                    .isEqualTo(counts.get(band));
        }
    }

    @Test
    void theVulnerableBandsAddUpToTheHeadlineCount() {
        // The headline sits beside these numbers, so a discrepancy would be visible and would
        // undermine both figures. CLEAN is excluded from the sum on purpose: it counts
        // components with nothing against them, not vulnerabilities.
        Map<SeverityBand, Integer> counts = repository.countsByBand(sbomId);
        int summed = FindingQuery.vulnerableBands().stream()
                .mapToInt(band -> counts.get(band))
                .sum();

        assertThat(summed).isEqualTo(repository.countFindings(sbomId, FindingQuery.defaults()))
                .isEqualTo(9);
    }

    @Test
    void countsCleanComponentsToo() {
        // The count appears on the "No vulnerabilities" filter chip, so it has to exist and
        // has to mean what selecting that chip shows.
        assertThat(repository.countsByBand(sbomId).get(SeverityBand.CLEAN))
                .isEqualTo(rowsIn(SeverityBand.CLEAN))
                .isEqualTo(1);
    }

    @Test
    void aZeroScoreIsLowRatherThanInvisible() {
        // It previously matched neither LOW (which required > 0) nor NONE (which requires no
        // score at all), so the row existed but no filter selection could display it.
        assertThat(repository.countsByBand(sbomId).get(SeverityBand.LOW)).isEqualTo(2);
        assertThat(rowsIn(SeverityBand.LOW)).isEqualTo(2);
    }

    @Test
    void unscoredAndCleanStayDistinct() {
        // The distinction the whole schema is built around: "we do not know how bad this is"
        // must never render as "there is nothing wrong".
        assertThat(rowsIn(SeverityBand.NONE)).as("a real advisory with no score").isEqualTo(1);
        assertThat(rowsIn(SeverityBand.CLEAN)).as("a component with no advisory").isEqualTo(1);
    }

    // --- the same counts, batched for the SBOM list -----------------------------------

    @Test
    void theBatchedSummaryAgreesWithThePerSbomOne() {
        // The sidebar counts every SBOM in one grouped query rather than calling the
        // per-SBOM path per card. Two implementations of one number are only safe while
        // something holds them together, and a card disagreeing with the page it opens
        // would discredit both.
        SbomSeverity batched = repository.severityBySbom().get(sbomId);

        assertThat(batched).isNotNull();
        assertThat(batched.counts()).isEqualTo(repository.countsByBand(sbomId));
        assertThat(batched.scannedComponents()).isEqualTo(repository.scannedComponentCount(sbomId));
    }

    @Test
    void anUnscannedSbomIsDistinguishableFromACleanOne() {
        // Its components land in CLEAN, because nothing is known against them — which is
        // exactly why the band counts cannot be read alone. Only scannedComponents
        // separates "we checked and found nothing" from "nobody has looked", and a card
        // showing zero criticals for an unexamined document would be the worst thing this
        // list could say.
        UUID unscanned = UUID.randomUUID();
        String purl = "pkg:maven/dev.sbomscope.test/never-scanned-%s@1.0.0"
                .formatted(unscanned.toString().substring(0, 8));

        jdbc.update("INSERT INTO sbom (id, filename, uploaded_at, spec_version, component_count)"
                        + " VALUES (?, ?, ?, ?, ?)",
                unscanned, "unscanned.cdx.json", OffsetDateTime.now(ZoneOffset.UTC), "1.6", 1);
        jdbc.update("INSERT INTO component (id, sbom_id, bom_ref, group_name, name, version, purl)"
                        + " VALUES (?, ?, ?, ?, ?, ?, ?)",
                UUID.randomUUID(), unscanned, purl, "dev.sbomscope.test", "never-scanned", "1.0.0", purl);

        SbomSeverity summary = repository.severityBySbom().get(unscanned);

        assertThat(summary).isNotNull();
        assertThat(summary.scannedComponents()).as("nothing has been checked").isZero();
        assertThat(summary.counts().get(SeverityBand.CLEAN))
                .as("and yet it counts as clean, which is why the two are shown together")
                .isEqualTo(1);
    }
}
