package dev.sbomscope.sbom;

import java.io.InputStream;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.stereotype.Component;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.ObjectMapper;

import dev.sbomscope.sbom.ParsedSbom.DependencyEdge;
import dev.sbomscope.sbom.ParsedSbom.ParsedComponent;

/**
 * Reads CycloneDX JSON into {@link ParsedSbom}.
 *
 * <p>Parsing is done against a hand-written model rather than the reference library:
 * SBOMscope only reads two sections of the document, only in JSON, and the fields it
 * needs have been stable since spec 1.2 — so tolerating unknown properties covers
 * version differences without carrying a dependency tree that includes XML support.
 */
@Component
public class CycloneDxParser {

    private static final String EXPECTED_FORMAT = "CycloneDX";

    /**
     * Versions this parser has been reasoned about. Newer documents are accepted with
     * the same handling, because unknown fields are ignored and the shape of the parts
     * we read has not changed; refusing them would be more disruptive than useful.
     */
    private static final Set<String> KNOWN_SPEC_VERSIONS =
            Set.of("1.2", "1.3", "1.4", "1.5", "1.6");

    private final ObjectMapper objectMapper;

    public CycloneDxParser(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public ParsedSbom parse(InputStream input) {
        CycloneDxDocument document = readDocument(input);
        requireCycloneDx(document);

        String rootBomRef = rootBomRefOf(document);
        List<DependencyEdge> edges = readEdges(document);

        Map<String, ParsedComponent> components = readComponents(document, rootBomRef);

        // Scope is a property of the graph, not of any one component, so it is decided once
        // the whole document has been read rather than guessed at while reading it.
        List<ParsedComponent> flat = List.copyOf(components.values());
        Map<String, DependencyScope> scopes =
                ScopeClassifier.classify(flat, edges, rootBomRef, edges.isEmpty());

        return new ParsedSbom(
                document.specVersion(),
                rootBomRef,
                flat.stream()
                        .map(component -> component.withScope(
                                scopes.getOrDefault(component.bomRef(), DependencyScope.TRANSITIVE)))
                        .toList(),
                edges);
    }

    private CycloneDxDocument readDocument(InputStream input) {
        try {
            CycloneDxDocument document = objectMapper.readValue(input, CycloneDxDocument.class);
            if (document == null) {
                throw new InvalidSbomException("The file is empty.");
            }
            return document;
        } catch (JacksonException e) {
            // Jackson 3 reports read failures as unchecked JacksonException, and wraps
            // underlying I/O problems in it too, so this is the single failure path.
            throw new InvalidSbomException(
                    "The file is not valid JSON. SBOMscope reads CycloneDX in JSON format — "
                            + "if you generated XML, re-run the CycloneDX plugin with JSON output.",
                    e);
        }
    }

    private void requireCycloneDx(CycloneDxDocument document) {
        if (document.bomFormat() == null || document.specVersion() == null) {
            throw new InvalidSbomException(
                    "This does not look like a CycloneDX document: it declares neither "
                            + "'bomFormat' nor 'specVersion'.");
        }
        if (!EXPECTED_FORMAT.equalsIgnoreCase(document.bomFormat())) {
            throw new InvalidSbomException(
                    "Unsupported SBOM format '%s'. SBOMscope reads CycloneDX."
                            .formatted(document.bomFormat()));
        }
    }

    private String rootBomRefOf(CycloneDxDocument document) {
        if (document.metadata() == null || document.metadata().component() == null) {
            return null;
        }
        return document.metadata().component().bomRef();
    }

    /**
     * The declared graph, with repeats collapsed.
     *
     * <p>Deduplicated because generators do repeat themselves: a document may list the same
     * ref twice in {@code dependencies}, or the same target twice within one
     * {@code dependsOn}. Both describe one relationship, and stored twice they violate
     * {@code component_dependency}'s primary key and fail the whole import — which is how
     * this surfaced, as an SBOM that simply would not load.
     *
     * <p>A set rather than a database-side ignore, because the duplication is meaningless
     * rather than a conflict to resolve. Insertion order is kept so the graph reads in the
     * order it was declared.
     */
    private List<DependencyEdge> readEdges(CycloneDxDocument document) {
        if (document.dependencies() == null) {
            return List.of();
        }

        Set<DependencyEdge> edges = new LinkedHashSet<>();
        for (CycloneDxDocument.Dependency dependency : document.dependencies()) {
            if (dependency == null || dependency.ref() == null || dependency.dependsOn() == null) {
                continue;
            }
            for (String target : dependency.dependsOn()) {
                // A component listed as its own dependency carries no information and would
                // turn the graph walk into a self-loop.
                if (target != null && !target.equals(dependency.ref())) {
                    edges.add(new DependencyEdge(dependency.ref(), target));
                }
            }
        }
        return List.copyOf(edges);
    }

    private Map<String, ParsedComponent> readComponents(
            CycloneDxDocument document, String rootBomRef) {

        // Keyed by bom-ref so a document repeating a component collapses to one row,
        // which the (sbom_id, bom_ref) uniqueness constraint requires anyway.
        Map<String, ParsedComponent> byRef = new LinkedHashMap<>();

        if (document.metadata() != null && document.metadata().component() != null) {
            CycloneDxDocument.Component root = document.metadata().component();
            if (root.bomRef() != null) {
                byRef.put(root.bomRef(), toParsed(root, true));
            }
        }

        collect(document.components(), byRef, rootBomRef);

        if (byRef.isEmpty()) {
            throw new InvalidSbomException(
                    "The SBOM contains no components. Check that the CycloneDX plugin ran "
                            + "against a resolved project rather than an empty one.");
        }
        return byRef;
    }

    private void collect(
            List<CycloneDxDocument.Component> source,
            Map<String, ParsedComponent> target,
            String rootBomRef) {

        if (source == null) {
            return;
        }

        for (CycloneDxDocument.Component component : source) {
            if (component == null || component.name() == null) {
                continue;
            }

            String bomRef = component.bomRef() != null ? component.bomRef() : synthesiseRef(component);
            target.putIfAbsent(bomRef, toParsed(component, bomRef.equals(rootBomRef)));

            // Nested components are part of the same flat inventory.
            collect(component.components(), target, rootBomRef);
        }
    }

    /**
     * bom-ref is optional in the specification. When it is absent the component cannot
     * participate in the dependency graph, but it should still appear in the inventory,
     * so a stable identifier is derived from its coordinates.
     */
    private String synthesiseRef(CycloneDxDocument.Component component) {
        if (component.purl() != null) {
            return component.purl();
        }
        StringBuilder ref = new StringBuilder();
        if (component.group() != null) {
            ref.append(component.group()).append(':');
        }
        ref.append(component.name());
        if (component.version() != null) {
            ref.append('@').append(component.version());
        }
        return ref.toString();
    }

    /** Scope is left at its weakest value here; {@link ScopeClassifier} sets the real one. */
    private ParsedComponent toParsed(CycloneDxDocument.Component component, boolean root) {
        String bomRef = component.bomRef() != null ? component.bomRef() : synthesiseRef(component);
        return new ParsedComponent(
                bomRef,
                component.group(),
                component.name(),
                component.version(),
                component.purl(),
                component.type(),
                root,
                DependencyScope.TRANSITIVE);
    }

    /** Exposed for diagnostics and tests. */
    static boolean isKnownSpecVersion(String specVersion) {
        return KNOWN_SPEC_VERSIONS.contains(specVersion);
    }
}
