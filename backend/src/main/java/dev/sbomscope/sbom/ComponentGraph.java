package dev.sbomscope.sbom;

import java.util.List;

/**
 * One component's place in its SBOM's dependency graph, in the two shapes the two questions
 * actually have.
 *
 * <p><b>Upward the question is "why is this here", and the answer is a route.</b> So
 * ancestors are paths — each one a readable chain from one of your own modules down to the
 * component — rather than a tree that would have to repeat nodes to show a diamond.
 *
 * <p><b>Downward the question is "what does this drag in", and the answer is a set.</b> So
 * descendants are a tree, where a path list would repeat a long shared prefix on every line.
 *
 * @param reachedFrom     every module of your own that pulls this component in. Never
 *                        abbreviated — the set of your modules affected is the scope of the
 *                        problem, and hiding one is a wrong answer rather than a tidier one
 * @param ownModuleCount  the denominator, so {@code reachedFrom.size()} reads as "6 of your
 *                        9 modules". <b>Excludes the root of an aggregate build.</b> The
 *                        parent pom aggregates rather than depends, so no route can ever top
 *                        out at it — counting it would put something in the denominator that
 *                        cannot appear in the numerator and quietly understate every ratio.
 *                        Where the root is the only application component, as in npm and
 *                        single-module Maven, it <em>is</em> the module and counts as one
 * @param targetIsOwnCode the component being inspected is itself one of your modules, so
 *                        there is nothing above it to explain and nothing to upgrade
 * @param tree            what this component pulls in, or null when it pulls in nothing
 */
public record ComponentGraph(
        List<ModuleRoutes> reachedFrom,
        int ownModuleCount,
        boolean targetIsOwnCode,
        TreeNode tree) {

    /** Most-affected module where the target is genuinely transitive, for the Maven probe. */
    public java.util.Optional<ModuleRoutes> primaryTransitiveOwner() {
        return reachedFrom.stream().filter(owner -> !owner.declarations().isEmpty()).findFirst();
    }

    /**
     * How one of your modules reaches this component.
     *
     * @param routes       the shortest few, each running module → … → component inclusive
     * @param totalRoutes  exact number found. The UI caps only the routes it displays; remedy
     *                     coverage is computed from the complete enumeration
     * @param truncated    retained in the API for compatibility. Enumeration itself is now
     *                     complete; true is reserved for the defensive case where reachability
     *                     found an owner but no concrete route could be materialised
     */
    public record ModuleRoutes(
            GraphNode module,
            List<List<GraphNode>> routes,
            int totalRoutes,
            boolean truncated,
            /** Routes where the module declares the target itself. */
            int directRoutes,
            /** Every direct dependency through which transitive routes enter this module. */
            List<DeclarationRoutes> declarations) {

        /** Compatibility constructor for hand-built graphs in callers and tests. */
        public ModuleRoutes(GraphNode module, List<List<GraphNode>> routes,
                            int totalRoutes, boolean truncated) {
            this(module, routes, totalRoutes, truncated, directRoutesFrom(routes), declarationsFrom(routes));
        }

        public boolean directlyDeclared() {
            return directRoutes > 0;
        }

        private static int directRoutesFrom(List<List<GraphNode>> routes) {
            return (int) routes.stream().filter(route -> route.size() == 2).count();
        }

        private static List<DeclarationRoutes> declarationsFrom(List<List<GraphNode>> routes) {
            java.util.Map<String, DeclarationRoutes> byRef = new java.util.LinkedHashMap<>();
            for (List<GraphNode> route : routes) {
                if (route.size() < 3) {
                    continue;
                }
                GraphNode declaration = route.get(1);
                byRef.compute(declaration.bomRef(), (ref, existing) -> new DeclarationRoutes(
                        declaration, existing == null ? 1 : existing.routes() + 1));
            }
            return List.copyOf(byRef.values());
        }
    }

    /** Exact route count through one declaration, computed independently of the display cap. */
    public record DeclarationRoutes(GraphNode declaration, int routes) {}

    /**
     * A node of the descendants tree.
     *
     * <p>A dependency graph is not a tree, so rendering it as one has to say where it
     * stopped rather than quietly pretending it reached the bottom.
     *
     * @param repeated this component appears elsewhere in the tree and was expanded there.
     *                 Expanding it again would be the same subtree, and in a diamond-heavy
     *                 graph that is how a few hundred components become a few million nodes
     * @param cyclic   this component is already on the path above it. Real SBOMs do contain
     *                 cycles, and following one does not terminate
     */
    public record TreeNode(
            GraphNode node,
            List<TreeNode> children,
            boolean repeated,
            boolean cyclic) {}
}
