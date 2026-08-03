package dev.sbomscope.reachability;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.Set;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

import dev.sbomscope.sbom.DependencyScope;
import dev.sbomscope.sbom.ParsedSbom;
import dev.sbomscope.sbom.StoredComponent;

class WorkspaceReachabilityServiceTest {

    @Test
    void reusesOnlyCompletedOrActuallyLiveMatchingRuns() {
        assertThat(WorkspaceReachabilityService.reusable(run(WorkspaceAnalysisRun.Status.COMPLETED), "same", false))
                .isTrue();
        assertThat(WorkspaceReachabilityService.reusable(run(WorkspaceAnalysisRun.Status.RUNNING), "same", true))
                .isTrue();
        assertThat(WorkspaceReachabilityService.reusable(run(WorkspaceAnalysisRun.Status.QUEUED), "same", false))
                .isFalse();
        assertThat(WorkspaceReachabilityService.reusable(run(WorkspaceAnalysisRun.Status.RUNNING), "same", false))
                .isFalse();
        assertThat(WorkspaceReachabilityService.reusable(run(WorkspaceAnalysisRun.Status.STOPPED), "same", false))
                .isFalse();
        assertThat(WorkspaceReachabilityService.reusable(run(WorkspaceAnalysisRun.Status.FAILED), "same", false))
                .isFalse();
        assertThat(WorkspaceReachabilityService.reusable(run(WorkspaceAnalysisRun.Status.COMPLETED), "changed", false))
                .isFalse();
    }

    @Test
    void buildsAnExactDependencyClosureForEachMappedModule() {
        StoredComponent moduleA = component("module-a", "pkg:maven/app/module-a@1", DependencyScope.APPLICATION);
        StoredComponent moduleB = component("module-b", "pkg:maven/app/module-b@1", DependencyScope.APPLICATION);
        StoredComponent versionOne = component("library-1", "pkg:maven/example/library@1", DependencyScope.DIRECT);
        StoredComponent versionTwo = component("library-2", "pkg:maven/example/library@2", DependencyScope.DIRECT);
        List<ParsedSbom.DependencyEdge> edges = List.of(
                new ParsedSbom.DependencyEdge(moduleA.bomRef(), versionOne.bomRef()),
                new ParsedSbom.DependencyEdge(moduleB.bomRef(), versionTwo.bomRef()));

        assertThat(WorkspaceReachabilityService.dependencyClosure(
                moduleA, List.of(moduleA, moduleB, versionOne, versionTwo), edges))
                .extracting(StoredComponent::purl)
                .containsExactly(moduleA.purl(), versionOne.purl());
    }

    @Test
    void positiveCoverageStaysReachableWithoutADisplayablePath() {
        ReachabilityWorkerResult.ComponentCoverage coverage = new ReachabilityWorkerResult.ComponentCoverage(
                "pkg:maven/example/library@1", 1, 0, List.of(), true, false);
        WorkspaceAnalysisInputs completeInputs = new WorkspaceAnalysisInputs(
                List.of(), List.of(), List.of(), Set.of(), "fingerprint");

        assertThat(WorkspaceReachabilityService.coverageStatus(coverage, completeInputs))
                .isEqualTo(WorkspaceReachabilityEvidence.Status.REACHABLE);
    }

    private WorkspaceAnalysisRun run(WorkspaceAnalysisRun.Status status) {
        return new WorkspaceAnalysisRun(UUID.randomUUID(), UUID.randomUUID(), "same", status,
                null, null, List.of(), null, Instant.now(), null, null);
    }

    private StoredComponent component(String ref, String purl, DependencyScope scope) {
        String version = purl.substring(purl.lastIndexOf('@') + 1);
        return new StoredComponent(UUID.randomUUID(), ref, "example", ref, version, purl,
                "library", false, scope);
    }
}
