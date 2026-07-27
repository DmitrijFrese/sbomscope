package dev.sbomscope.scanner;

import java.io.InputStream;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Parser tests run against a report produced by the real osv-scanner (v2.4.0) scanning
 * SBOMscope's own SBOM, rather than a hand-written sample.
 */
class OsvReportParserTest {

    private static final String JACKSON_PURL =
            "pkg:maven/tools.jackson.core/jackson-databind@3.1.4?type=jar";

    private final OsvReportParser parser = new OsvReportParser(new ObjectMapper());

    private String realReport() throws Exception {
        return fixture("/sboms/osv-report-maven.json");
    }

    private String fixture(String path) throws Exception {
        try (InputStream stream = getClass().getResourceAsStream(path)) {
            assertThat(stream).as("fixture should exist").isNotNull();
            return new String(stream.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    /** Resolves the one package the report contains; anything else is unknown. */
    private Optional<String> resolve(OsvReportParser.PackageKey key) {
        return key.name().equals("tools.jackson.core:jackson-databind")
                ? Optional.of(JACKSON_PURL)
                : Optional.empty();
    }

    @Test
    void parsesTheRealReport() throws Exception {
        List<VulnerabilityFinding> findings = parser.parse(realReport(), this::resolve);

        assertThat(findings).hasSize(1);
        VulnerabilityFinding finding = findings.getFirst();

        assertThat(finding.purl()).isEqualTo(JACKSON_PURL);
        assertThat(finding.osvId()).isEqualTo("GHSA-5gvw-p9qm-jgwh");
        assertThat(finding.cveId()).isEqualTo("CVE-2026-59889");
        assertThat(finding.severityScore()).isEqualByComparingTo(new BigDecimal("6.5"));
        assertThat(finding.cvssVersion()).isEqualTo("CVSS_V3");
        assertThat(finding.severityRating()).isEqualTo("MODERATE");
        assertThat(finding.publishedAt()).isNotNull();
    }

    @Test
    void choosesTheFixOnOurOwnVersionBranch() throws Exception {
        // The advisory lists fixes for several coordinates and branches — 2.21.5, 2.18.9
        // and 2.22.1 among them. Only 3.1.5 applies to the artifact we actually depend on,
        // and offering any of the others would send someone to a version that does not
        // exist for their library.
        List<VulnerabilityFinding> findings = parser.parse(realReport(), this::resolve);

        assertThat(findings.getFirst().fixedVersion()).isEqualTo("3.1.5");
    }

    @Test
    void linksToNvdWhenACveExists() throws Exception {
        List<VulnerabilityFinding> findings = parser.parse(realReport(), this::resolve);

        assertThat(findings.getFirst().referenceUrl())
                .isEqualTo("https://nvd.nist.gov/vuln/detail/CVE-2026-59889");
    }

    @Test
    void fallsBackToOsvDevWhenThereIsNoCve() {
        VulnerabilityFinding ghsaOnly = new VulnerabilityFinding(
                "pkg:maven/example/lib@1.0.0", "GHSA-aaaa-bbbb-cccc", null, "summary",
                null, null, null, null, null, null);

        assertThat(ghsaOnly.referenceUrl())
                .isEqualTo("https://osv.dev/vulnerability/GHSA-aaaa-bbbb-cccc");
    }

    @Test
    void dropsFindingsThatCannotBeTiedToAComponent() throws Exception {
        // A finding we cannot map back to a stored component is skipped rather than
        // stored against a guessed identity.
        List<VulnerabilityFinding> findings = parser.parse(realReport(), key -> Optional.empty());

        assertThat(findings).isEmpty();
    }

    @Test
    void packageKeyNormalisesCasingOnBothSides() {
        // The scanner echoes back whatever casing the SBOM used; both sides of the
        // lookup must agree or every finding would silently fail to match.
        assertThat(new OsvReportParser.PackageKey("Maven", "Com.Example:Lib", "1.0"))
                .isEqualTo(new OsvReportParser.PackageKey("maven", "com.example:lib", "1.0"));
    }

    @Test
    void toleratesAnEmptyReport() {
        assertThat(parser.parse("{\"results\":[]}", this::resolve)).isEmpty();
    }

    // --- groups whose members disagree about severity --------------------------------

    private static final String CLICKHOUSE_PURL =
            "pkg:maven/com.clickhouse/clickhouse-client@0.4.5?type=jar";

    private List<VulnerabilityFinding> aliasedGroupFindings() throws Exception {
        return parser.parse(fixture("/sboms/osv-report-aliased-group.json"),
                key -> key.name().equals("com.clickhouse:clickhouse-client")
                        ? Optional.of(CLICKHOUSE_PURL)
                        : Optional.empty());
    }

    @Test
    void keepsTheWorstCaseScoreWhenAGroupsMembersDisagree() throws Exception {
        // max_severity is the highest across the whole group. Lowering it to whichever
        // advisory happens to be listed first would understate the risk, which is the one
        // direction a vulnerability tool must not err in.
        List<VulnerabilityFinding> findings = aliasedGroupFindings();

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severityScore()).isEqualByComparingTo(new BigDecimal("8.8"));
    }

    @Test
    void omitsTheVectorWhenItCannotBeAttributedToTheScore() throws Exception {
        // The two advisories carry different vectors, so the one belonging to the named
        // advisory is not the one that produced 8.8. Printing them together would assert a
        // relationship that does not hold, so the vector is dropped and the score stands.
        VulnerabilityFinding finding = aliasedGroupFindings().getFirst();

        assertThat(finding.cvssVector()).isNull();
        assertThat(finding.cvssVersion()).isNull();
    }

    @Test
    void describesTheNamedAdvisoryAndNoOther() throws Exception {
        // Everything other than the score comes from the advisory whose id is displayed,
        // so the row cannot become a blend of two records that a reader would then be
        // unable to verify against either one.
        VulnerabilityFinding finding = aliasedGroupFindings().getFirst();

        assertThat(finding.osvId()).isEqualTo("GHSA-g8ph-74m6-8m7r");
        assertThat(finding.summary()).contains("client certificate password exposure");
        assertThat(finding.severityRating()).isEqualTo("MODERATE");
        assertThat(finding.publishedAt()).isEqualTo(Instant.parse("2023-05-12T20:18:51Z"));
        assertThat(finding.cveId()).isEqualTo("CVE-2024-23689");
    }

    @Test
    void keepsTheVectorWhenTheGroupHasOnlyOneAdvisory() throws Exception {
        // The overwhelmingly common case must be untouched by the rule above: with nothing
        // to disagree with, the vector is unambiguously the one behind the score.
        VulnerabilityFinding finding = parser.parse(realReport(), this::resolve).getFirst();

        assertThat(finding.cvssVector()).isEqualTo("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
        assertThat(finding.cvssVersion()).isEqualTo("CVSS_V3");
    }

    // --- one purl, reported more than once --------------------------------------------

    /**
     * The real report with its package entry listed a second time, optionally under a
     * different name.
     *
     * <p>Both spellings of this condition are ones the scanner genuinely produces. A
     * document can carry the same library at two bom-refs — npm installs a package at
     * several paths, an aggregate Maven BOM spans several modules — and a component is
     * deliberately indexed under every name a generator might use for it. The data stays
     * the real scanner's; only the repetition is arranged.
     */
    private String reportWithASecondEntry(String nameForTheCopy) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        JsonNode report = mapper.readTree(realReport());
        ArrayNode packages = (ArrayNode) report.get("results").get(0).get("packages");

        ObjectNode copy = (ObjectNode) packages.get(0).deepCopy();
        if (nameForTheCopy != null) {
            ((ObjectNode) copy.get("package")).put("name", nameForTheCopy);
        }
        packages.add(copy);

        return mapper.writeValueAsString(report);
    }

    @Test
    void collapsesOneAdvisoryReportedTwiceForTheSameComponent() throws Exception {
        // Storing this straight through violates UNIQUE (purl, osv_id) and fails the whole
        // scan — the entire import, since it runs in one transaction. One advisory says one
        // thing about one component however many times the document mentions it.
        List<VulnerabilityFinding> findings = parser.parse(reportWithASecondEntry(null), this::resolve);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().osvId()).isEqualTo("GHSA-5gvw-p9qm-jgwh");
    }

    @Test
    void collapsesTwoPackageSpellingsResolvingToOnePurl() throws Exception {
        // The other route to a duplicate, and the one that is a consequence of a deliberate
        // design: a component is registered under several names so a scoped npm package is
        // not missed, which means two report entries can resolve to a single purl.
        String report = reportWithASecondEntry("tools.jackson.core/jackson-databind");

        List<VulnerabilityFinding> findings = parser.parse(report, key -> Optional.of(JACKSON_PURL));

        assertThat(findings).hasSize(1);
    }

    @Test
    void keepsTheFullyDescribedFindingWhenDuplicatesDisagree() throws Exception {
        // The copy is renamed, so its fix version cannot be resolved against the advisory's
        // affected entries and comes back null. Keeping the first entry means the surviving
        // row is the completely described one rather than whichever arrived last — the
        // reason this is collapsed here and not by a last-one-wins MERGE in the database.
        String report = reportWithASecondEntry("tools.jackson.core/jackson-databind");

        VulnerabilityFinding finding =
                parser.parse(report, key -> Optional.of(JACKSON_PURL)).getFirst();

        assertThat(finding.fixedVersion()).isEqualTo("3.1.5");
    }

    @Test
    void findingsAreIdentifiedByComponentAndAdvisoryTogether() {
        // Mirrors uq_finding_per_component. Same advisory against a different component is a
        // different finding, and must not be collapsed with it.
        VulnerabilityFinding.Key first = new VulnerabilityFinding.Key("pkg:maven/a/lib@1.0", "GHSA-x");
        VulnerabilityFinding.Key sameComponent = new VulnerabilityFinding.Key("pkg:maven/a/lib@1.0", "GHSA-y");
        VulnerabilityFinding.Key sameAdvisory = new VulnerabilityFinding.Key("pkg:maven/b/lib@1.0", "GHSA-x");

        assertThat(first).isNotEqualTo(sameComponent).isNotEqualTo(sameAdvisory);
        assertThat(first).isEqualTo(new VulnerabilityFinding.Key("pkg:maven/a/lib@1.0", "GHSA-x"));
    }
}
