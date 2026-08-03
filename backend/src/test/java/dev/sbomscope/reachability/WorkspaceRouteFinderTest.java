package dev.sbomscope.reachability;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class WorkspaceRouteFinderTest {

    private final WorkspaceRouteFinder finder = new WorkspaceRouteFinder();

    @Test
    void countsEveryReachingMethodEvenWhenOnlyTenShortestPathsAreDisplayed() {
        List<ReachabilityGraph.MethodEdge> edges = new ArrayList<>();
        for (int index = 1; index <= 11; index++) {
            edges.add(new ReachabilityGraph.MethodEdge("modulea.Use%d#call()".formatted(index),
                    "library.Target#operation()"));
        }
        edges.add(new ReachabilityGraph.MethodEdge("moduleb.Other#call()", "library.Target#operation()"));
        Map<String, String> modules = new java.util.HashMap<>();
        for (int index = 1; index <= 11; index++) modules.put("modulea.Use%d".formatted(index), "module-a");
        modules.put("moduleb.Other", "module-b");

        WorkspaceRouteFinder.RouteCoverage coverage = finder.find("module-a", modules, edges, Set.of("library.Target"));

        assertThat(coverage.reachableMethods()).isEqualTo(11);
        assertThat(coverage.directMethods()).isEqualTo(11);
        assertThat(coverage.displayPaths()).hasSize(10);
        assertThat(coverage.displayPaths()).allSatisfy(path -> assertThat(path.getFirst()).startsWith("modulea."));
    }

    @Test
    void keepsAFrameworkMediatedPathTransitiveWhileCountingItsApplicationMethod() {
        List<ReachabilityGraph.MethodEdge> edges = List.of(
                new ReachabilityGraph.MethodEdge("modulea.Controller#read()", "spring.Adapter#convert()"),
                new ReachabilityGraph.MethodEdge("spring.Adapter#convert()", "jackson.ObjectMapper#readTree()"));

        WorkspaceRouteFinder.RouteCoverage coverage = finder.find("module-a",
                Map.of("modulea.Controller", "module-a"), edges, Set.of("jackson.ObjectMapper"));

        assertThat(coverage.reachableMethods()).isEqualTo(1);
        assertThat(coverage.directMethods()).isZero();
        assertThat(coverage.displayPaths()).containsExactly(List.of(
                "modulea.Controller#read()", "spring.Adapter#convert()", "jackson.ObjectMapper#readTree()"));
    }

    @Test
    void retainsPositiveCoverageWhenTheRepresentativePathExceedsTheDisplayDepth() {
        List<ReachabilityGraph.MethodEdge> edges = new ArrayList<>();
        String caller = "modulea.Entry#call()";
        for (int index = 0; index < 17; index++) {
            String callee = "framework.Hop%d#call()".formatted(index);
            edges.add(new ReachabilityGraph.MethodEdge(caller, callee));
            caller = callee;
        }
        edges.add(new ReachabilityGraph.MethodEdge(caller, "library.Target#operation()"));

        WorkspaceRouteFinder.RouteCoverage coverage = finder.find("module-a",
                Map.of("modulea.Entry", "module-a"), edges, Set.of("library.Target"));

        assertThat(coverage.reachableMethods()).isEqualTo(1);
        assertThat(coverage.displayPaths()).isEmpty();
        assertThat(coverage.representativePathsLimited()).isTrue();
    }
}
