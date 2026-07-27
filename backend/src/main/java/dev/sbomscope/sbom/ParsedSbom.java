package dev.sbomscope.sbom;

import java.util.List;

/**
 * The parts of a CycloneDX document SBOMscope cares about, already normalised.
 *
 * <p>Deliberately independent of both the wire format and the database: the parser
 * produces this, persistence consumes it, and neither needs to know about the other.
 *
 * @param specVersion CycloneDX spec version the document declared
 * @param rootBomRef  bom-ref of the component being described, or {@code null} when the
 *                    document carried no metadata component
 * @param components  every component, with nesting flattened away
 * @param edges       the dependency graph, as declared
 */
public record ParsedSbom(
        String specVersion,
        String rootBomRef,
        List<ParsedComponent> components,
        List<DependencyEdge> edges) {

    public ParsedSbom {
        components = List.copyOf(components);
        edges = List.copyOf(edges);
    }

    /**
     * A single component.
     *
     * @param bomRef SBOM-internal identifier the dependency graph refers to
     * @param group  Maven groupId or npm scope; {@code null} for unscoped packages
     * @param purl   package URL, the identifier used later for vulnerability lookups
     * @param root   true when this is the component the document describes
     * @param scope  your own code, something you declared, or something pulled in for you
     */
    public record ParsedComponent(
            String bomRef,
            String group,
            String name,
            String version,
            String purl,
            String type,
            boolean root,
            DependencyScope scope) {

        /** Before the graph has been walked; {@link ScopeClassifier} decides the real value. */
        ParsedComponent withScope(DependencyScope resolved) {
            return new ParsedComponent(bomRef, group, name, version, purl, type, root, resolved);
        }
    }

    /** One edge of the dependency graph: {@code from} depends on {@code to}. */
    public record DependencyEdge(String fromBomRef, String toBomRef) {}
}
