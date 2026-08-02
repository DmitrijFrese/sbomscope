package dev.sbomscope.scanner;

import java.math.BigDecimal;
import java.util.List;
import java.util.UUID;

import org.junit.jupiter.api.Test;

import dev.sbomscope.sbom.ComponentGraph;
import dev.sbomscope.sbom.DependencyScope;
import dev.sbomscope.sbom.GraphNode;
import dev.sbomscope.sbom.StoredComponent;

import dev.sbomscope.scanner.UpgradeAdvice.Remedy;
import dev.sbomscope.scanner.UpgradeAdvice.RemedyKind;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * What to change, and where.
 *
 * <p>The property under test throughout is that a remedy names something the reader can put
 * in a file. "Upgrade to 3.1.5" for a library they do not declare is a true statement and an
 * unusable one, and the earlier design of this phase produced nothing else.
 */
class UpgradeAdviceTest {

    private final UpgradeAdviceService service = new UpgradeAdviceService();

    /** No archive on disk — the target cannot be checked, which is not "the target is clean". */
    private static final UpgradeAdviceService.TargetEvaluator NO_ARCHIVE =
            UpgradeAdviceService.TargetEvaluator.unavailable();

    /** An archive that reports exactly these advisories against whatever it is asked about. */
    private static UpgradeAdviceService.TargetEvaluator archiveReporting(
            OsvArchiveMatcher.AdvisoryHit... hits) {
        return version -> java.util.Optional.of(List.of(hits));
    }

    private static final String PURL = "pkg:maven/tools.jackson.core/jackson-databind@3.1.4?type=jar";

    private StoredComponent maven(DependencyScope scope) {
        return new StoredComponent(UUID.randomUUID(), "ref", "tools.jackson.core",
                "jackson-databind", "3.1.4", PURL, "library", false, scope);
    }

    private FindingRow finding(String osvId, String fixedVersion, String score) {
        return new FindingRow(PURL, "tools.jackson.core:jackson-databind", "3.1.4", false,
                DependencyScope.TRANSITIVE, osvId, "CVE-x", "summary",
                score == null ? null : new BigDecimal(score), "MODERATE", null, "CVSS_V3",
                fixedVersion, null);
    }

    /** backend → spring-boot-starter-json → jackson-databind. */
    private ComponentGraph graphWithDeclarer(String declarer) {
        GraphNode module = new GraphNode("m", "dev.sbomscope:sbomscope-backend", "1.0", null,
                false, DependencyScope.APPLICATION, false);
        GraphNode middle = new GraphNode("d", declarer, "4.1.0", null, false,
                DependencyScope.DIRECT, false);
        GraphNode target = new GraphNode("t", "tools.jackson.core:jackson-databind", "3.1.4",
                PURL, false, DependencyScope.TRANSITIVE, true);

        return new ComponentGraph(
                List.of(new ComponentGraph.ModuleRoutes(
                        module, List.of(List.of(module, middle, target)), 1, false)),
                1, false, null);
    }

    private ComponentGraph noGraph() {
        return new ComponentGraph(List.of(), 1, false, null);
    }

    private ComponentGraph mixedDirectAndTransitiveGraph() {
        GraphNode moduleA = new GraphNode("ma", "dev.sbomscope:module-a", "1.0", null,
                false, DependencyScope.APPLICATION, false);
        GraphNode moduleB = new GraphNode("mb", "dev.sbomscope:module-b", "1.0", null,
                false, DependencyScope.APPLICATION, false);
        GraphNode ancestor = new GraphNode("a", "org.example:starter", "2.0", null,
                false, DependencyScope.DIRECT, false);
        GraphNode target = new GraphNode("t", "tools.jackson.core:jackson-databind", "3.1.4",
                PURL, false, DependencyScope.DIRECT, true);
        return new ComponentGraph(List.of(
                new ComponentGraph.ModuleRoutes(moduleA, List.of(List.of(moduleA, target)), 1, false),
                new ComponentGraph.ModuleRoutes(moduleB, List.of(List.of(moduleB, ancestor, target)), 1, false)),
                2, false, null);
    }

    private Remedy remedy(UpgradeAdvice advice, RemedyKind kind) {
        return advice.remedies().stream().filter(r -> r.kind() == kind).findFirst().orElseThrow();
    }

    @Test
    void aDeclaredDependencyIsUpgraded() {
        UpgradeAdvice advice = service.adviseFor(
                maven(DependencyScope.DIRECT), List.of(finding("GHSA-a", "3.1.5", "6.5")), noGraph(), NO_ARCHIVE);

        assertThat(advice.suggested()).isEqualTo(RemedyKind.UPGRADE);
        Remedy upgrade = remedy(advice, RemedyKind.UPGRADE);
        assertThat(upgrade.available()).isTrue();
        assertThat(upgrade.target()).isEqualTo("3.1.5");
        assertThat(upgrade.snippet()).contains("<version>3.1.5</version>");
    }

    @Test
    void anUndeclaredDependencyIsPinnedInstead() {
        // The case the earlier design had no answer for. "Upgrade to 3.1.5" is unusable when
        // the manifest has never mentioned jackson; a pin is precise and works regardless of
        // what the ancestor does.
        UpgradeAdvice advice = service.adviseFor(
                maven(DependencyScope.TRANSITIVE), List.of(finding("GHSA-a", "3.1.5", "6.5")),
                graphWithDeclarer("org.springframework.boot:spring-boot-starter-json"), NO_ARCHIVE);

        assertThat(advice.suggested()).isEqualTo(RemedyKind.PIN);

        Remedy upgrade = remedy(advice, RemedyKind.UPGRADE);
        assertThat(upgrade.available()).as("nothing in the manifest to change").isFalse();
        assertThat(upgrade.note()).contains("do not declare");

        Remedy pin = remedy(advice, RemedyKind.PIN);
        assertThat(pin.available()).isTrue();
        assertThat(pin.snippet()).contains("<dependencyManagement>").contains("3.1.5");
    }

    @Test
    void aGlobalDirectScopeDoesNotHideTheModuleWhereTheComponentIsTransitive() {
        UpgradeAdvice advice = service.adviseFor(
                maven(DependencyScope.DIRECT), List.of(finding("GHSA-a", "3.1.5", "6.5")),
                mixedDirectAndTransitiveGraph(), NO_ARCHIVE);

        Remedy upgrade = remedy(advice, RemedyKind.UPGRADE);
        assertThat(upgrade.available()).isTrue();
        assertThat(upgrade.note()).contains("module-a").contains("module-b").contains("not affected");
        assertThat(upgrade.moduleImpacts())
                .extracting(impact -> impact.module() + ":" + impact.coverage())
                .containsExactly("dev.sbomscope:module-a:COMPLETE", "dev.sbomscope:module-b:UNAFFECTED");

        Remedy bump = remedy(advice, RemedyKind.BUMP_ANCESTOR);
        assertThat(bump.target()).isEqualTo("org.example:starter");
        assertThat(bump.moduleImpacts()).singleElement().satisfies(impact -> {
            assertThat(impact.module()).isEqualTo("dev.sbomscope:module-b");
            assertThat(impact.routesCovered()).isEqualTo(1);
            assertThat(impact.routesTotal()).isEqualTo(1);
        });

        assertThat(advice.suggested()).as("the direct upgrade is incomplete across modules")
                .isEqualTo(RemedyKind.PIN);
    }

    @Test
    void aTransitiveFindingNamesWhoDeclaresIt() {
        // "Transitive" alone tells a reader they cannot fix it without telling them who can.
        UpgradeAdvice advice = service.adviseFor(
                maven(DependencyScope.TRANSITIVE), List.of(finding("GHSA-a", "3.1.5", "6.5")),
                graphWithDeclarer("org.springframework.boot:spring-boot-starter-json"), NO_ARCHIVE);

        assertThat(advice.declaredBy())
                .containsExactly("org.springframework.boot:spring-boot-starter-json");

        // The names belong in declaredBy, which the panel prints above the remedies. Naming
        // them again inside the note produced a sentence with three coordinates in it.
        Remedy bump = remedy(advice, RemedyKind.BUMP_ANCESTOR);
        assertThat(bump.target()).isEqualTo("org.springframework.boot:spring-boot-starter-json");
        assertThat(bump.note()).contains("cannot be determined offline");
    }

    @Test
    void onePinAddressesEveryAdvisoryByTakingTheHighestFix() {
        // Taking the lowest would leave the others in place.
        UpgradeAdvice advice = service.adviseFor(
                maven(DependencyScope.TRANSITIVE),
                List.of(finding("GHSA-a", "3.1.5", "6.5"),
                        finding("GHSA-b", "3.2.1", "9.1"),
                        finding("GHSA-c", "3.0.9", "4.0")),
                noGraph(), NO_ARCHIVE);

        assertThat(advice.pinTarget()).isEqualTo("3.2.1");
        assertThat(remedy(advice, RemedyKind.PIN).clears())
                .containsExactlyInAnyOrder("GHSA-a", "GHSA-b", "GHSA-c");
    }

    @Test
    void anAdvisoryWithNoFixIsReportedAsLeftBehind() {
        // A real state, not missing data: the advisory offers nothing on this branch.
        UpgradeAdvice advice = service.adviseFor(
                maven(DependencyScope.TRANSITIVE),
                List.of(finding("GHSA-a", "3.1.5", "6.5"), finding("GHSA-nofix", null, "7.5")),
                noGraph(), NO_ARCHIVE);

        Remedy pin = remedy(advice, RemedyKind.PIN);
        assertThat(pin.clears()).containsExactly("GHSA-a");
        assertThat(pin.leaves()).containsExactly("GHSA-nofix");
    }

    @Test
    void nothingIsSuggestedWhenNoAdvisoryNamesAFix() {
        UpgradeAdvice advice = service.adviseFor(
                maven(DependencyScope.TRANSITIVE), List.of(finding("GHSA-nofix", null, "7.5")), noGraph(), NO_ARCHIVE);

        assertThat(advice.pinTarget()).isNull();
        assertThat(advice.suggested()).isNull();
        assertThat(remedy(advice, RemedyKind.PIN).available()).isFalse();
        assertThat(remedy(advice, RemedyKind.PIN).note()).contains("nothing to pin it to");
    }

    @Test
    void exclusionIsNeverOfferedWithoutUsageData() {
        // Recommending the removal of a dependency the code turns out to use is worse than
        // recommending nothing. Phase 9 is what makes this answerable.
        UpgradeAdvice advice = service.adviseFor(
                maven(DependencyScope.TRANSITIVE), List.of(finding("GHSA-a", "3.1.5", "6.5")), noGraph(), NO_ARCHIVE);

        Remedy exclude = remedy(advice, RemedyKind.EXCLUDE);
        assertThat(exclude.available()).isFalse();
        assertThat(exclude.note()).contains("does not use this library");
        assertThat(advice.suggested()).isNotEqualTo(RemedyKind.EXCLUDE);
    }

    @Test
    void yourOwnCodeGetsNoRemedyAtAll() {
        UpgradeAdvice advice = service.adviseFor(
                maven(DependencyScope.APPLICATION), List.of(finding("GHSA-a", "3.1.5", "6.5")), noGraph(), NO_ARCHIVE);

        assertThat(advice.suggested()).isNull();
        assertThat(remedy(advice, RemedyKind.UPGRADE).note()).contains("your own code");
    }

    @Test
    void npmForcesAVersionWithOverridesAndKeepsTheScope() {
        StoredComponent scoped = new StoredComponent(UUID.randomUUID(), "ref", "@angular",
                "common", "19.2.17", "pkg:npm/%40angular/common@19.2.17", "library", false,
                DependencyScope.TRANSITIVE);

        UpgradeAdvice advice = service.adviseFor(
                scoped,
                List.of(new FindingRow("pkg:npm/%40angular/common@19.2.17", "@angular:common",
                        "19.2.17", false, DependencyScope.TRANSITIVE, "GHSA-x", null, null,
                        new BigDecimal("7.5"), null, null, null, "19.2.18", null)),
                noGraph(), NO_ARCHIVE);

        assertThat(remedy(advice, RemedyKind.PIN).snippet())
                .contains("\"overrides\"")
                .contains("\"@angular/common\": \"19.2.18\"");
    }

    // --- what the target itself carries -------------------------------------------------

    @Test
    void withNoArchiveTheTargetIsReportedAsUnchecked() {
        // Knowing 3.1.5 fixes this advisory is not knowing 3.1.5 is clean, and with nothing
        // to check against the honest answer is that nobody looked.
        UpgradeAdvice advice = service.adviseFor(
                maven(DependencyScope.TRANSITIVE), List.of(finding("GHSA-a", "3.1.5", "6.5")),
                noGraph(), NO_ARCHIVE);

        assertThat(advice.targetEvaluated()).isFalse();
        assertThat(advice.targetAdvisories()).isEmpty();
    }

    @Test
    void aCheckedAndCleanTargetIsDistinctFromAnUncheckedOne() {
        // The distinction the whole schema is built around, one level further in: an empty
        // list means "clean" only when targetEvaluated says somebody looked.
        UpgradeAdvice advice = service.adviseFor(
                maven(DependencyScope.TRANSITIVE), List.of(finding("GHSA-a", "3.1.5", "6.5")),
                noGraph(), archiveReporting());

        assertThat(advice.targetEvaluated()).isTrue();
        assertThat(advice.targetAdvisories()).isEmpty();
    }

    @Test
    void aTargetThatCarriesItsOwnAdvisoriesSaysSo() {
        // The case that makes the matcher worth building: the fix version named by one
        // advisory is itself affected by another, and pinning there trades one problem for
        // a second nobody mentioned.
        UpgradeAdvice advice = service.adviseFor(
                maven(DependencyScope.TRANSITIVE), List.of(finding("GHSA-a", "3.1.5", "6.5")),
                noGraph(),
                archiveReporting(new OsvArchiveMatcher.AdvisoryHit("GHSA-later", "CVE-2", "HIGH")));

        assertThat(advice.targetEvaluated()).isTrue();
        assertThat(advice.targetAdvisories())
                .extracting(OsvArchiveMatcher.AdvisoryHit::osvId)
                .containsExactly("GHSA-later");
    }

    @Test
    void theTargetIsNotCheckedWhenThereIsNoTarget() {
        // Nothing to ask about, so the evaluator is never called and the answer is "not
        // checked" rather than "clean".
        UpgradeAdvice advice = service.adviseFor(
                maven(DependencyScope.TRANSITIVE), List.of(finding("GHSA-nofix", null, "7.5")),
                noGraph(), archiveReporting());

        assertThat(advice.pinTarget()).isNull();
        assertThat(advice.targetEvaluated()).isFalse();
    }
}
