package dev.sbomscope.sbom;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import org.springframework.stereotype.Service;

import dev.sbomscope.sbom.ComponentGraph.ModuleRoutes;
import dev.sbomscope.sbom.ComponentGraph.TreeNode;

/**
 * Walks one SBOM's dependency graph around a chosen component.
 *
 * <p>The edges are the document's own {@code dependencies} array, stored at import. Nothing
 * here needs the network, the scanner, or any data beyond the uploaded file — which is why
 * this panel could be built while upgrade paths waits on R4.
 *
 * <p>Two guards run through everything below, because a dependency graph is neither a tree
 * nor acyclic in practice:
 *
 * <ul>
 *   <li><b>Path enumeration is exponential.</b> A graph full of diamonds has more distinct
 *       routes than can be walked, let alone read, so enumeration is bounded and says when
 *       it stopped rather than reporting a total it did not finish counting.</li>
 *   <li><b>Expansion is bounded by expanding each component once.</b> Without that, the same
 *       shared subtree is rebuilt under every parent that reaches it.</li>
 * </ul>
 */
@Service
public class DependencyGraphService {

    /**
     * How many routes are read out per module.
     *
     * <p>Three, because after the shortest one the rest are usually the same story with an
     * extra hop. This caps <em>routes</em>; the modules themselves are never capped.
     */
    private static final int ROUTES_SHOWN = 3;

    /**
     * How far enumeration goes before it gives up counting.
     *
     * <p>Reaching this makes {@code totalRoutes} a floor rather than a total, and the caller
     * is told so. Counting exactly would mean walking every path, which is the thing that
     * does not terminate in reasonable time.
     */
    private static final int ROUTES_ENUMERATED = 25;

    /** A whole-request ceiling, so one pathological component cannot hang the panel. */
    private static final int ROUTE_STEPS_BUDGET = 200_000;

    private final SbomRepository repository;

    DependencyGraphService(SbomRepository repository) {
        this.repository = repository;
    }

    /**
     * @param vulnerablePurls supplied by the caller rather than looked up here, so this
     *                        package does not have to depend on the scanner package to answer
     *                        a question about the document's own structure
     */
    public ComponentGraph graphFor(UUID sbomId, String purl, Set<String> vulnerablePurls) {
        return graphFor(
                repository.findComponents(sbomId),
                repository.findEdges(sbomId),
                purl,
                vulnerablePurls);
    }

    /**
     * The walk itself, over data already loaded.
     *
     * <p>Separated from the fetch so the traversal can be tested against graphs a real
     * generator will not produce on demand — a diamond, a cycle, a component pulled in by
     * four modules. Those are the cases the guards exist for, and waiting to meet one in
     * the wild is not a test strategy.
     */
    ComponentGraph graphFor(
            List<StoredComponent> components,
            List<ParsedSbom.DependencyEdge> edges,
            String purl,
            Set<String> vulnerablePurls) {

        Map<String, StoredComponent> byRef = new HashMap<>();
        for (StoredComponent component : components) {
            byRef.put(component.bomRef(), component);
        }

        Map<String, List<String>> children = new HashMap<>();
        Map<String, List<String>> parents = new HashMap<>();
        for (ParsedSbom.DependencyEdge edge : edges) {
            children.computeIfAbsent(edge.fromBomRef(), ref -> new ArrayList<>()).add(edge.toBomRef());
            parents.computeIfAbsent(edge.toBomRef(), ref -> new ArrayList<>()).add(edge.fromBomRef());
        }

        // A purl is not unique within a document, so the component can be present under
        // several bom-refs. They are the same library, so every one of them is a starting
        // point and their routes belong in the same answer.
        List<StoredComponent> targets = components.stream()
                .filter(component -> purl.equals(component.purl()))
                .toList();

        if (targets.isEmpty()) {
            return new ComponentGraph(List.of(), ownModuleCount(components), false, null);
        }

        boolean ownCode = targets.stream()
                .anyMatch(component -> component.scope() == DependencyScope.APPLICATION);

        return new ComponentGraph(
                ancestors(targets, byRef, parents, vulnerablePurls),
                ownModuleCount(components),
                ownCode,
                descendants(targets.getFirst(), byRef, children, vulnerablePurls));
    }

    /**
     * How many modules of your own there are — the denominator for "reached from n of m".
     *
     * <p>The root of an aggregate build is excluded. It depends only on the project's own
     * modules, so no route can ever top out at it, and including it would put a component in
     * the denominator that cannot appear in the numerator: every ratio would read lower than
     * it is. Where the root is the <em>only</em> application component — npm, single-module
     * Maven — it is itself the module and counts as one, which is the same reduction that
     * makes {@link ScopeClassifier} safe on those documents.
     */
    private int ownModuleCount(List<StoredComponent> components) {
        long siblings = components.stream()
                .filter(component -> component.scope() == DependencyScope.APPLICATION)
                .filter(component -> !component.root())
                .count();

        if (siblings > 0) {
            return (int) siblings;
        }
        return (int) components.stream()
                .filter(component -> component.scope() == DependencyScope.APPLICATION)
                .count();
    }

    // --- upward: which of your modules pull this in, and by what route -------------------

    /**
     * Two passes, and the split is the whole point.
     *
     * <p>The first is plain reachability and is <b>complete</b>: breadth-first up the graph,
     * stopping at your own code, collecting the modules it meets. Linear, so it cannot be
     * defeated by a dense graph, which is what makes "every owning module is listed" a
     * guarantee rather than an intention.
     *
     * <p>The second enumerates routes and is <b>bounded</b>. A module the second pass could
     * not produce a route for still appears, marked truncated — because which modules are
     * affected is the answer, and by which hop is the detail.
     */
    private List<ModuleRoutes> ancestors(
            List<StoredComponent> targets,
            Map<String, StoredComponent> byRef,
            Map<String, List<String>> parents,
            Set<String> vulnerablePurls) {

        Set<String> owningModules = reachableModules(targets, byRef, parents);
        if (owningModules.isEmpty()) {
            return List.of();
        }

        Map<String, List<List<String>>> routesByModule = new HashMap<>();
        Map<String, Boolean> truncated = new HashMap<>();
        int[] budget = { ROUTE_STEPS_BUDGET };

        for (StoredComponent target : targets) {
            Deque<String> path = new ArrayDeque<>();
            path.push(target.bomRef());
            walkUp(target.bomRef(), path, byRef, parents, routesByModule, truncated, budget);
        }

        List<ModuleRoutes> result = new ArrayList<>();
        for (String moduleRef : owningModules) {
            StoredComponent module = byRef.get(moduleRef);
            if (module == null) {
                continue;
            }
            List<List<String>> found = routesByModule.getOrDefault(moduleRef, List.of());

            List<List<String>> shortestFirst = new ArrayList<>(found);
            shortestFirst.sort(Comparator.comparingInt(List::size));

            List<List<GraphNode>> shown = shortestFirst.stream()
                    .limit(ROUTES_SHOWN)
                    .map(route -> route.stream()
                            .map(ref -> node(byRef.get(ref), vulnerablePurls))
                            .filter(java.util.Objects::nonNull)
                            .toList())
                    .toList();

            result.add(new ModuleRoutes(
                    node(module, vulnerablePurls),
                    shown,
                    found.size(),
                    Boolean.TRUE.equals(truncated.get(moduleRef)) || found.isEmpty()));
        }

        // Most affected module first: where several of your modules carry the same library,
        // the one reaching it by the most routes is usually where the work starts.
        result.sort(Comparator
                .comparingInt((ModuleRoutes m) -> m.totalRoutes()).reversed()
                .thenComparing(m -> m.module().coordinates()));
        return result;
    }

    /** Complete, linear, and the reason no module can go missing. */
    private Set<String> reachableModules(
            List<StoredComponent> targets,
            Map<String, StoredComponent> byRef,
            Map<String, List<String>> parents) {

        Set<String> modules = new LinkedHashSet<>();
        Set<String> seen = new HashSet<>();
        Deque<String> queue = new ArrayDeque<>();

        for (StoredComponent target : targets) {
            queue.add(target.bomRef());
            seen.add(target.bomRef());
        }

        while (!queue.isEmpty()) {
            String ref = queue.poll();
            for (String parent : parents.getOrDefault(ref, List.of())) {
                if (!seen.add(parent)) {
                    continue;
                }
                StoredComponent component = byRef.get(parent);
                if (component == null) {
                    continue;
                }
                if (component.scope() == DependencyScope.APPLICATION) {
                    // Stop here. The parent pom sits above this and aggregates rather than
                    // depends, so continuing would top every route with a name that explains
                    // nothing.
                    modules.add(parent);
                } else {
                    queue.add(parent);
                }
            }
        }
        return modules;
    }

    private void walkUp(
            String ref,
            Deque<String> path,
            Map<String, StoredComponent> byRef,
            Map<String, List<String>> parents,
            Map<String, List<List<String>>> routesByModule,
            Map<String, Boolean> truncated,
            int[] budget) {

        for (String parent : parents.getOrDefault(ref, List.of())) {
            if (budget[0]-- <= 0) {
                return;
            }
            // Guards the current path only, not the whole search: a component legitimately
            // appears on many different routes, but never twice on one.
            if (path.contains(parent)) {
                continue;
            }
            StoredComponent component = byRef.get(parent);
            if (component == null) {
                continue;
            }

            if (component.scope() == DependencyScope.APPLICATION) {
                List<List<String>> routes =
                        routesByModule.computeIfAbsent(parent, key -> new ArrayList<>());
                if (routes.size() >= ROUTES_ENUMERATED) {
                    truncated.put(parent, true);
                    continue;
                }
                // The path is pushed onto, so iterating it runs from the step nearest this
                // module down to the component — already the reading order. Only the module
                // itself has to go on the front.
                List<String> route = new ArrayList<>(path);
                route.addFirst(parent);
                routes.add(route);
                continue;
            }

            path.push(parent);
            walkUp(parent, path, byRef, parents, routesByModule, truncated, budget);
            path.pop();
        }
    }

    // --- downward: what this component drags in -----------------------------------------

    /**
     * Each component is expanded at most once across the whole tree.
     *
     * <p>Without that the tree is not bounded by the graph's size but by its path count: a
     * shared library reached ten ways is rebuilt ten times, and its subtree with it. Nodes
     * met again are shown in place and marked, so the reader can see the library is there
     * without the tree pretending it is a different one.
     */
    private TreeNode descendants(
            StoredComponent target,
            Map<String, StoredComponent> byRef,
            Map<String, List<String>> children,
            Set<String> vulnerablePurls) {

        return expand(target.bomRef(), byRef, children, vulnerablePurls,
                new LinkedHashSet<>(), new HashSet<>());
    }

    private TreeNode expand(
            String ref,
            Map<String, StoredComponent> byRef,
            Map<String, List<String>> children,
            Set<String> vulnerablePurls,
            Set<String> onPath,
            Set<String> expanded) {

        StoredComponent component = byRef.get(ref);
        if (component == null) {
            return null;
        }
        GraphNode self = node(component, vulnerablePurls);

        if (onPath.contains(ref)) {
            return new TreeNode(self, List.of(), false, true);
        }
        if (!expanded.add(ref)) {
            return new TreeNode(self, List.of(), true, false);
        }

        onPath.add(ref);
        List<TreeNode> kids = new ArrayList<>();
        for (String child : children.getOrDefault(ref, List.of())) {
            TreeNode built = expand(child, byRef, children, vulnerablePurls, onPath, expanded);
            if (built != null) {
                kids.add(built);
            }
        }
        onPath.remove(ref);

        kids.sort(Comparator.comparing(child -> child.node().coordinates()));
        return new TreeNode(self, List.copyOf(kids), false, false);
    }

    private GraphNode node(StoredComponent component, Set<String> vulnerablePurls) {
        if (component == null) {
            return null;
        }
        return GraphNode.of(component, component.purl() != null && vulnerablePurls.contains(component.purl()));
    }
}
