package dev.sbomscope.sbom;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import dev.sbomscope.sbom.ParsedSbom.DependencyEdge;

/**
 * Decides each component's {@link DependencyScope} from the dependency graph.
 *
 * <p>The rule is one idea applied twice:
 *
 * <ol>
 *   <li>Work out which components are <em>the application</em> — the root, plus any sibling
 *       modules of the same build.</li>
 *   <li>Anything that set depends on, and which is not itself part of it, is
 *       {@code DIRECT}. Everything else is {@code TRANSITIVE}.</li>
 * </ol>
 *
 * <p>For an npm SBOM, or a single-module Maven project, the application is just the root and
 * the rule reduces to "what the root depends on is direct" — which is what the old boolean
 * already got right. For an aggregate Maven build it fixes the case that boolean could not
 * express.
 *
 * <h2>Recognising a module</h2>
 *
 * <p>CycloneDX offers no marker for this: in a real aggregate BOM the project's own modules
 * are emitted as {@code type: library} with no scope and no properties, indistinguishable
 * from a third-party artifact. The only usable signals are structural, so a module is a
 * component reachable from the root whose group is the root's group or beneath it
 * <em>and</em> whose version is exactly the root's.
 *
 * <p>Both conditions together, because either alone is too loose: an organisation routinely
 * consumes its own published libraries under the same group prefix, and those are real
 * dependencies that can be upgraded. Sharing a group <em>and</em> an exact version with the
 * thing being built is what makes a reactor module. A blank root group disables module
 * detection entirely, which is what makes npm safe — its components carry no group, so
 * nothing could be compared.
 */
final class ScopeClassifier {

    private ScopeClassifier() {}

    /**
     * @param noGraph when the document declared no dependency graph at all. Every component
     *                is then reported as direct: treating them all as transitive would be
     *                actively misleading, and a flat SBOM genuinely carries no information
     *                to distinguish the two.
     * @return scope by bom-ref, for every component given
     */
    static Map<String, DependencyScope> classify(
            List<ParsedSbom.ParsedComponent> components,
            List<DependencyEdge> edges,
            String rootBomRef,
            boolean noGraph) {

        Map<String, DependencyScope> scopes = new HashMap<>();

        if (noGraph || rootBomRef == null) {
            for (ParsedSbom.ParsedComponent component : components) {
                scopes.put(component.bomRef(),
                        component.bomRef().equals(rootBomRef)
                                ? DependencyScope.APPLICATION
                                : DependencyScope.DIRECT);
            }
            return scopes;
        }

        Map<String, List<String>> dependsOn = adjacency(edges);
        Map<String, ParsedSbom.ParsedComponent> byRef = new HashMap<>();
        components.forEach(component -> byRef.put(component.bomRef(), component));

        Set<String> application = applicationSet(byRef, dependsOn, rootBomRef);

        // Everything the application depends on, minus the application itself.
        Set<String> direct = new HashSet<>();
        for (String member : application) {
            for (String target : dependsOn.getOrDefault(member, List.of())) {
                if (!application.contains(target)) {
                    direct.add(target);
                }
            }
        }

        for (ParsedSbom.ParsedComponent component : components) {
            String ref = component.bomRef();
            scopes.put(ref, application.contains(ref)
                    ? DependencyScope.APPLICATION
                    : direct.contains(ref) ? DependencyScope.DIRECT : DependencyScope.TRANSITIVE);
        }
        return scopes;
    }

    /**
     * The root plus its sibling modules, found by walking outward from the root.
     *
     * <p>Traversal rather than a single pass over the root's children, because modules nest:
     * a parent aggregator may hold an intermediate module that in turn holds the leaves, and
     * a leaf is no more a dependency than its parent is. Bounded by the visited set, so
     * cycles and diamonds terminate.
     */
    private static Set<String> applicationSet(
            Map<String, ParsedSbom.ParsedComponent> byRef,
            Map<String, List<String>> dependsOn,
            String rootBomRef) {

        Set<String> application = new HashSet<>();
        application.add(rootBomRef);

        ParsedSbom.ParsedComponent root = byRef.get(rootBomRef);
        String rootGroup = root == null ? null : root.group();
        String rootVersion = root == null ? null : root.version();

        // Without both, there is nothing to match on and every component stays a dependency.
        if (isBlank(rootGroup) || isBlank(rootVersion)) {
            return application;
        }

        Deque<String> queue = new ArrayDeque<>();
        queue.add(rootBomRef);

        while (!queue.isEmpty()) {
            for (String candidate : dependsOn.getOrDefault(queue.poll(), List.of())) {
                if (application.contains(candidate)) {
                    continue;
                }
                if (isModule(byRef.get(candidate), rootGroup, rootVersion)) {
                    application.add(candidate);
                    queue.add(candidate);
                }
            }
        }
        return application;
    }

    private static boolean isModule(
            ParsedSbom.ParsedComponent component, String rootGroup, String rootVersion) {

        if (component == null || isBlank(component.group()) || isBlank(component.version())) {
            return false;
        }
        return rootVersion.equals(component.version()) && inGroup(component.group(), rootGroup);
    }

    /** Same group, or beneath it — but not merely sharing a prefix, so `acme` misses `acmex`. */
    private static boolean inGroup(String group, String rootGroup) {
        return group.equals(rootGroup) || group.startsWith(rootGroup + ".");
    }

    private static Map<String, List<String>> adjacency(List<DependencyEdge> edges) {
        Map<String, List<String>> dependsOn = new HashMap<>();
        for (DependencyEdge edge : edges) {
            dependsOn.computeIfAbsent(edge.fromBomRef(), key -> new ArrayList<>()).add(edge.toBomRef());
        }
        return dependsOn;
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
