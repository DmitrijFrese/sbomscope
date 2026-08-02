package dev.sbomscope.sbom;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import org.junit.jupiter.api.Test;

import dev.sbomscope.sbom.ComponentGraph.ModuleRoutes;
import dev.sbomscope.sbom.ComponentGraph.TreeNode;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Traversal semantics, against graphs built by hand.
 *
 * <p>Constructed rather than taken from a real document, unlike the parser fixtures. The
 * cases worth protecting here — a diamond, a cycle, a library four modules pull in — are
 * precisely the ones a generator will not produce on request, and they are what every guard
 * in the service exists for. `ScopeClassifierTest` pins its refusals the same way.
 */
class DependencyGraphTest {

    private final DependencyGraphService service = new DependencyGraphService(null);

    private final List<StoredComponent> components = new ArrayList<>();
    private final List<ParsedSbom.DependencyEdge> edges = new ArrayList<>();

    /** A component of your own: a module, or the root the document describes. */
    private void own(String ref, boolean root) {
        add(ref, root, DependencyScope.APPLICATION);
    }

    private void library(String ref, DependencyScope scope) {
        add(ref, false, scope);
    }

    private void add(String ref, boolean root, DependencyScope scope) {
        components.add(new StoredComponent(
                UUID.randomUUID(), ref, "com.example", ref, "1.0.0",
                "pkg:maven/com.example/" + ref + "@1.0.0", "library", root, scope));
    }

    private void depends(String from, String to) {
        edges.add(new ParsedSbom.DependencyEdge(from, to));
    }

    private ComponentGraph graphOf(String ref) {
        return graphOf(ref, Set.of());
    }

    private ComponentGraph graphOf(String ref, Set<String> vulnerable) {
        return service.graphFor(components, edges, "pkg:maven/com.example/" + ref + "@1.0.0", vulnerable);
    }

    private static List<String> names(List<GraphNode> route) {
        return route.stream().map(GraphNode::bomRef).toList();
    }

    /** The shape this project actually ships: a parent pom over modules over libraries. */
    private void aggregateBuild() {
        own("parent", true);
        own("backend", false);
        own("frontend", false);
        depends("parent", "backend");
        depends("parent", "frontend");
    }

    // --- upward ------------------------------------------------------------------------

    @Test
    void aRouteStopsAtTheOwningModuleAndNeverAtTheParentPom() {
        // The parent aggregates rather than depends, so leading every route with its name
        // would say nothing — and it is the one component nobody can act on.
        aggregateBuild();
        library("web", DependencyScope.DIRECT);
        library("jackson", DependencyScope.TRANSITIVE);
        depends("backend", "web");
        depends("web", "jackson");

        ComponentGraph graph = graphOf("jackson");

        assertThat(graph.reachedFrom()).hasSize(1);
        assertThat(names(graph.reachedFrom().getFirst().routes().getFirst()))
                .containsExactly("backend", "web", "jackson");
    }

    @Test
    void everyOwningModuleIsListed() {
        // The case that matters most: a library in most of your modules. The set of modules
        // affected is the scope of the problem, so none of them may be abbreviated away.
        aggregateBuild();
        own("reporting", false);
        depends("parent", "reporting");

        library("shared", DependencyScope.DIRECT);
        depends("backend", "shared");
        depends("frontend", "shared");
        depends("reporting", "shared");

        ComponentGraph graph = graphOf("shared");

        assertThat(graph.reachedFrom()).hasSize(3);
        assertThat(graph.reachedFrom().stream().map(m -> m.module().bomRef()))
                .containsExactlyInAnyOrder("backend", "frontend", "reporting");
        assertThat(graph.ownModuleCount())
                .as("the parent pom is not one of them: no route can ever top out at it")
                .isEqualTo(3);
    }

    @Test
    void aSingleModuleBuildCountsItsRootAsTheModule() {
        // Excluding the root is right for an aggregate build and wrong for npm or a
        // single-module Maven project, where the root is the module. Same reduction that
        // makes the scope classification safe on those documents.
        own("app", true);
        library("web", DependencyScope.DIRECT);
        depends("app", "web");

        ComponentGraph graph = graphOf("web");

        assertThat(graph.ownModuleCount()).isEqualTo(1);
        assertThat(graph.reachedFrom()).hasSize(1);
    }

    @Test
    void aDiamondIsTwoRoutesFromOneModuleAndTheShortestComesFirst() {
        // Both routes are true. Drawing one would assert the other does not exist, and
        // ordering by length puts the one worth reading at the top.
        aggregateBuild();
        library("web", DependencyScope.DIRECT);
        library("json", DependencyScope.TRANSITIVE);
        library("core", DependencyScope.TRANSITIVE);
        depends("backend", "web");
        depends("backend", "core");
        depends("web", "json");
        depends("json", "core");

        ModuleRoutes reached = graphOf("core").reachedFrom().getFirst();

        assertThat(reached.totalRoutes()).isEqualTo(2);
        assertThat(names(reached.routes().getFirst())).containsExactly("backend", "core");
        assertThat(names(reached.routes().get(1))).containsExactly("backend", "web", "json", "core");
    }

    @Test
    void remedyCountsAreExactBeyondTheTenRouteDisplayCap() {
        aggregateBuild();
        library("declaration-a", DependencyScope.DIRECT);
        library("declaration-b", DependencyScope.DIRECT);
        library("target", DependencyScope.TRANSITIVE);
        depends("backend", "declaration-a");
        depends("backend", "declaration-b");

        for (int i = 0; i < 20; i++) {
            String branch = "a-" + i;
            library(branch, DependencyScope.TRANSITIVE);
            depends("declaration-a", branch);
            depends(branch, "target");
        }
        for (int i = 0; i < 15; i++) {
            String branch = "b-" + i;
            library(branch, DependencyScope.TRANSITIVE);
            depends("declaration-b", branch);
            depends(branch, "target");
        }

        ModuleRoutes reached = graphOf("target").reachedFrom().getFirst();

        assertThat(reached.routes()).as("presentation stays capped").hasSize(10);
        assertThat(reached.totalRoutes()).as("correctness does not use that cap").isEqualTo(35);
        assertThat(reached.truncated()).isFalse();
        assertThat(reached.declarations())
                .extracting(entry -> entry.declaration().bomRef() + ":" + entry.routes())
                .containsExactlyInAnyOrder("declaration-a:20", "declaration-b:15");
    }

    @Test
    void aCycleAboveTheComponentTerminates() {
        // Real documents contain them, and following one does not stop on its own.
        aggregateBuild();
        library("a", DependencyScope.DIRECT);
        library("b", DependencyScope.TRANSITIVE);
        depends("backend", "a");
        depends("a", "b");
        depends("b", "a");

        ComponentGraph graph = graphOf("b");

        assertThat(graph.reachedFrom()).hasSize(1);
        assertThat(names(graph.reachedFrom().getFirst().routes().getFirst()))
                .containsExactly("backend", "a", "b");
    }

    @Test
    void aComponentWithNoRouteToYourCodeSaysSoRatherThanInventingOne() {
        // A document can describe something nothing reaches. Empty is the honest answer.
        aggregateBuild();
        library("orphan", DependencyScope.TRANSITIVE);

        assertThat(graphOf("orphan").reachedFrom()).isEmpty();
    }

    @Test
    void yourOwnModuleIsMarkedAsSuchRatherThanOfferedAnUpgrade() {
        aggregateBuild();

        ComponentGraph graph = graphOf("backend");

        assertThat(graph.targetIsOwnCode()).isTrue();
    }

    // --- downward ----------------------------------------------------------------------

    @Test
    void descendantsAreATreeDownToTheLeaves() {
        aggregateBuild();
        library("web", DependencyScope.DIRECT);
        library("json", DependencyScope.TRANSITIVE);
        library("core", DependencyScope.TRANSITIVE);
        depends("backend", "web");
        depends("web", "json");
        depends("json", "core");

        TreeNode tree = graphOf("web").tree();

        assertThat(tree.node().bomRef()).isEqualTo("web");
        assertThat(tree.children()).hasSize(1);
        assertThat(tree.children().getFirst().node().bomRef()).isEqualTo("json");
        assertThat(tree.children().getFirst().children().getFirst().node().bomRef()).isEqualTo("core");
    }

    @Test
    void aSharedSubtreeIsMarkedRatherThanRebuilt() {
        // Expanding a shared library under every parent that reaches it is how a few hundred
        // components become a few million nodes. It is shown in place, marked, and not
        // expanded twice — so the reader still sees it is there.
        aggregateBuild();
        library("web", DependencyScope.DIRECT);
        library("a", DependencyScope.TRANSITIVE);
        library("b", DependencyScope.TRANSITIVE);
        library("shared", DependencyScope.TRANSITIVE);
        depends("web", "a");
        depends("web", "b");
        depends("a", "shared");
        depends("b", "shared");

        TreeNode tree = graphOf("web").tree();
        TreeNode first = tree.children().getFirst();
        TreeNode second = tree.children().get(1);

        assertThat(first.children().getFirst().repeated()).isFalse();
        assertThat(second.children().getFirst().node().bomRef()).isEqualTo("shared");
        assertThat(second.children().getFirst().repeated()).isTrue();
        assertThat(second.children().getFirst().children()).isEmpty();
    }

    @Test
    void aCycleBelowTheComponentIsMarkedAndStops() {
        aggregateBuild();
        library("a", DependencyScope.TRANSITIVE);
        library("b", DependencyScope.TRANSITIVE);
        depends("a", "b");
        depends("b", "a");

        TreeNode tree = graphOf("a").tree();
        TreeNode b = tree.children().getFirst();

        assertThat(b.node().bomRef()).isEqualTo("b");
        assertThat(b.children().getFirst().node().bomRef()).isEqualTo("a");
        assertThat(b.children().getFirst().cyclic()).isTrue();
        assertThat(b.children().getFirst().children()).isEmpty();
    }

    @Test
    void vulnerableNodesAreMarkedWhereverTheyAppear() {
        // The point of marking them is that a chain shows where else the problem sits, not
        // only at the end you started from.
        aggregateBuild();
        library("web", DependencyScope.DIRECT);
        library("json", DependencyScope.TRANSITIVE);
        depends("backend", "web");
        depends("web", "json");

        ComponentGraph graph = graphOf("json", Set.of("pkg:maven/com.example/web@1.0.0"));
        List<GraphNode> route = graph.reachedFrom().getFirst().routes().getFirst();

        assertThat(route.stream().filter(GraphNode::vulnerable).map(GraphNode::bomRef))
                .containsExactly("web");
    }
}
