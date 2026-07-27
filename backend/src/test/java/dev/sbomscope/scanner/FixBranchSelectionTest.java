package dev.sbomscope.scanner;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.Test;
import tools.jackson.databind.ObjectMapper;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Choosing the fix that belongs to the component's own release branch.
 *
 * <p>Built from a real advisory that lists four parallel branches of one package. Before
 * this, the parser returned whichever fix appeared first in the file, so a user on 19.2.17
 * was told to upgrade to 22.0.1 — three majors away, on a branch their advisory never
 * mentions. An upgrade target that looks authoritative and is wrong is worse than none.
 */
class FixBranchSelectionTest {

    private final OsvReportParser parser = new OsvReportParser(new ObjectMapper());

    private String report(String version) throws Exception {
        try (InputStream stream = getClass().getResourceAsStream("/sboms/osv-report-npm-branches.json")) {
            assertThat(stream).as("fixture should exist").isNotNull();
            // The fixture pins 19.2.17; the other branches are exercised by substituting it.
            return new String(stream.readAllBytes(), StandardCharsets.UTF_8)
                    .replace("\"version\": \"19.2.17\"", "\"version\": \"" + version + "\"");
        }
    }

    private VulnerabilityFinding findingFor(String version) throws Exception {
        List<VulnerabilityFinding> findings = parser.parse(report(version),
                key -> key.name().equals("@angular/common")
                        ? Optional.of("pkg:npm/%40angular/common@" + version)
                        : Optional.empty());

        assertThat(findings).as("the advisory must be reported for %s", version).hasSize(1);
        return findings.getFirst();
    }

    @Test
    void reportsNoFixWhenTheComponentsOwnBranchHasNone() throws Exception {
        // The 19.x entry ends in last_affected: the advisory offers nothing on that line.
        // Null here is a real answer about this version, not missing data.
        assertThat(findingFor("19.2.17").fixedVersion()).isNull();
    }

    @Test
    void takesTheFixFromTheBranchTheVersionSitsOn() throws Exception {
        assertThat(findingFor("20.1.0").fixedVersion()).isEqualTo("20.3.25");
        assertThat(findingFor("21.0.5").fixedVersion()).isEqualTo("21.2.17");
        assertThat(findingFor("22.0.0").fixedVersion()).isEqualTo("22.0.1");
    }

    @Test
    void placesAPreReleaseOnTheBranchItLeadsInto() throws Exception {
        // 21.0.0-next.4 is introduced by the 21.x range, not by the 19.x one that ends at
        // 19.2.25 — the ordering has to put a pre-release below its own release.
        assertThat(findingFor("21.0.0-next.4").fixedVersion()).isEqualTo("21.2.17");
    }

    @Test
    void stillFindsTheAdvisoryItself() throws Exception {
        // Branch selection decides the upgrade target; it must never affect whether the
        // vulnerability is reported at all.
        VulnerabilityFinding finding = findingFor("19.2.17");

        assertThat(finding.osvId()).isEqualTo("GHSA-48r7-hpm6-gfxm");
        assertThat(finding.cveId()).isEqualTo("CVE-2026-54268");
        assertThat(finding.severityScore()).isEqualByComparingTo(new java.math.BigDecimal("7.5"));
    }

    // --- the ordering underneath it ---------------------------------------------------

    @Test
    void ordersReleasesNumericallyRatherThanAsText() {
        assertThat(VersionOrder.INSTANCE.compare("19.2.17", "19.2.9")).isPositive();
        assertThat(VersionOrder.INSTANCE.compare("9.0.0", "10.0.0")).isNegative();
        assertThat(VersionOrder.INSTANCE.compare("1.2", "1.2.0")).isZero();
    }

    @Test
    void sortsAPreReleaseBelowItsRelease() {
        assertThat(VersionOrder.INSTANCE.compare("22.0.0-next.0", "22.0.0")).isNegative();
        assertThat(VersionOrder.INSTANCE.compare("22.0.0-next.0", "19.2.17")).isPositive();
    }

    @Test
    void ignoresBuildMetadata() {
        assertThat(VersionOrder.INSTANCE.compare("1.0.0+build.5", "1.0.0")).isZero();
    }
}
