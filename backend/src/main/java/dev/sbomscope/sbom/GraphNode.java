package dev.sbomscope.sbom;

/**
 * A component as the dependency graph refers to it.
 *
 * <p>Deliberately thinner than {@link StoredComponent}: a route can be a dozen steps long and
 * a tree hundreds of nodes, so each one carries what it takes to render and identify a step
 * and nothing else. Anything more is a click away — every node carries the purl the
 * Inspector is keyed by.
 *
 * @param vulnerable this component has at least one known vulnerability, so a chain shows
 *                   where else the problem sits rather than only at its ends
 */
public record GraphNode(
        String bomRef,
        String coordinates,
        String version,
        String purl,
        boolean root,
        DependencyScope scope,
        boolean vulnerable) {

    static GraphNode of(StoredComponent component, boolean vulnerable) {
        return new GraphNode(
                component.bomRef(),
                component.coordinates(),
                component.version(),
                component.purl(),
                component.root(),
                component.scope(),
                vulnerable);
    }
}
