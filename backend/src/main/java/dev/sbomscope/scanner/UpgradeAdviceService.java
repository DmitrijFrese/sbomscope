package dev.sbomscope.scanner;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.stereotype.Service;

import dev.sbomscope.sbom.ComponentGraph;
import dev.sbomscope.sbom.DependencyScope;
import dev.sbomscope.sbom.GraphNode;
import dev.sbomscope.sbom.StoredComponent;

import dev.sbomscope.scanner.UpgradeAdvice.AdvisoryFix;
import dev.sbomscope.scanner.UpgradeAdvice.Remedy;
import dev.sbomscope.scanner.UpgradeAdvice.RemedyKind;

/**
 * Turns a component's findings and its place in the graph into remedies.
 *
 * <p>Pure: everything it needs is passed in, so it is testable without a database and cannot
 * quietly acquire a network call. That matters more here than elsewhere — this is the tier
 * whose entire promise is that it works offline.
 */
@Service
public class UpgradeAdviceService {

    /**
     * Checks a version the user does not have against the local archives.
     *
     * <p>A callback rather than an injected matcher, so this service stays pure and cannot
     * quietly acquire a data source — the tier's whole promise is that it works offline, and
     * a test that constructs it with no dependencies is the cheapest way to keep that true.
     *
     * @return empty when the archive for this ecosystem is absent, which is <b>not</b> the
     *         same as the version being clean
     */
    @FunctionalInterface
    public interface TargetEvaluator {

        java.util.Optional<List<OsvArchiveMatcher.AdvisoryHit>> evaluate(String version);

        /** For callers with no archive, and for tests that are not about this. */
        static TargetEvaluator unavailable() {
            return version -> java.util.Optional.empty();
        }
    }

    public UpgradeAdvice adviseFor(StoredComponent component, List<FindingRow> rows,
                                   ComponentGraph graph, TargetEvaluator targetEvaluator) {
        List<AdvisoryFix> advisories = advisoriesFrom(rows);

        List<String> clears = advisories.stream()
                .filter(advisory -> advisory.fixedVersion() != null)
                .map(AdvisoryFix::osvId)
                .toList();

        List<String> leaves = advisories.stream()
                .filter(advisory -> advisory.fixedVersion() == null)
                .map(AdvisoryFix::osvId)
                .toList();

        String pinTarget = highestFix(advisories);
        List<String> declaredBy = declaringDependencies(graph);

        List<Remedy> remedies = new ArrayList<>();
        remedies.add(upgrade(component, pinTarget, clears, leaves));
        remedies.add(pin(component, pinTarget, clears, leaves));
        remedies.add(bumpAncestor(component, declaredBy));
        remedies.add(exclude());

        // Only worth asking when there is a target to ask about.
        java.util.Optional<List<OsvArchiveMatcher.AdvisoryHit>> onTarget =
                pinTarget == null ? java.util.Optional.empty() : targetEvaluator.evaluate(pinTarget);

        return new UpgradeAdvice(
                component.version(),
                component.scope(),
                pinTarget,
                advisories,
                declaredBy,
                remedies,
                suggest(component, pinTarget, advisories),
                onTarget.isPresent(),
                onTarget.orElse(List.of()));
    }

    /**
     * The advisories a component's rows describe, as the shared input both {@link #adviseFor}
     * and the Maven probe's {@code clears} list are built from — so the two cannot disagree
     * about what is being fixed.
     */
    public static List<AdvisoryFix> advisoriesFrom(List<FindingRow> rows) {
        return rows.stream()
                .filter(FindingRow::hasFinding)
                .map(row -> new AdvisoryFix(row.osvId(), row.cveId(), row.severityScore(), row.fixedVersion()))
                .toList();
    }

    /**
     * The highest fix version any advisory names, so a single pin addresses all of them.
     *
     * <p>Highest rather than lowest: pinning to the lowest would leave the others in place.
     * Compared with {@link VersionOrder}, which is already written and tested for exactly the
     * dotted-release shapes OSV emits.
     */
    private String highestFix(List<AdvisoryFix> advisories) {
        String highest = null;
        for (AdvisoryFix advisory : advisories) {
            String fix = advisory.fixedVersion();
            if (fix == null || fix.isBlank()) {
                continue;
            }
            if (highest == null || VersionOrder.INSTANCE.compare(fix, highest) > 0) {
                highest = fix;
            }
        }
        return highest;
    }

    /**
     * The dependencies your own code declares that lead here.
     *
     * <p>Second step of each route: the first is one of your modules, so the second is what
     * that module wrote down. That is the thing whose version you would raise, and the thing
     * whose maintainer you would ask — "transitive" on its own tells a reader they cannot fix
     * it directly without telling them who can.
     */
    private List<String> declaringDependencies(ComponentGraph graph) {
        return declaringNodes(graph).stream().map(GraphNode::coordinates).toList();
    }

    /**
     * The same declaring dependencies as {@link #declaringDependencies}, as full nodes rather
     * than display strings — the Maven probe (Tier 2) needs the node's own version to build a
     * version range, which a coordinates string has already thrown away.
     */
    public static List<GraphNode> declaringNodes(ComponentGraph graph) {
        Map<String, GraphNode> byCoordinates = new LinkedHashMap<>();
        for (ComponentGraph.ModuleRoutes module : graph.reachedFrom()) {
            for (List<GraphNode> route : module.routes()) {
                if (route.size() >= 2) {
                    byCoordinates.putIfAbsent(route.get(1).coordinates(), route.get(1));
                }
            }
        }
        return List.copyOf(byCoordinates.values());
    }

    private Remedy upgrade(StoredComponent component, String pinTarget,
                           List<String> clears, List<String> leaves) {

        if (component.scope() != DependencyScope.DIRECT) {
            return new Remedy(RemedyKind.UPGRADE, false, null, null, List.of(), List.of(),
                    component.scope() == DependencyScope.APPLICATION
                            ? "This is your own code. There is no version of it to move to."
                            : "You do not declare this dependency, so there is no version of it "
                                    + "in your manifest to change.");
        }
        if (pinTarget == null) {
            return new Remedy(RemedyKind.UPGRADE, false, null, null, List.of(), leaves,
                    "No advisory against this component names a fixed version.");
        }
        return new Remedy(RemedyKind.UPGRADE, true, pinTarget,
                upgradeSnippet(component, pinTarget), clears, leaves, null);
    }

    private Remedy pin(StoredComponent component, String pinTarget,
                       List<String> clears, List<String> leaves) {

        if (component.scope() == DependencyScope.APPLICATION) {
            return new Remedy(RemedyKind.PIN, false, null, null, List.of(), List.of(),
                    "This is your own code, not a dependency to pin.");
        }
        if (pinTarget == null) {
            return new Remedy(RemedyKind.PIN, false, null, null, List.of(), leaves,
                    "No advisory against this component names a fixed version, so there is "
                            + "nothing to pin it to.");
        }
        String snippet = pinSnippet(component, pinTarget);
        if (snippet == null) {
            return new Remedy(RemedyKind.PIN, false, pinTarget, null, clears, leaves,
                    "SBOMscope does not know how to force a version in this ecosystem.");
        }
        return new Remedy(RemedyKind.PIN, true, pinTarget, snippet, clears, leaves, null);
    }

    /**
     * Always listed, never actionable in this tier.
     *
     * <p>Whether a newer version of the declaring dependency ships the fix means reading
     * <em>its</em> dependencies at that version, which appears in no SBOM of this project and
     * in no advisory database. It is the one remedy that genuinely requires a lookup, and
     * naming what is missing is more use than omitting the option.
     */
    private Remedy bumpAncestor(StoredComponent component, List<String> declaredBy) {
        if (component.scope() != DependencyScope.TRANSITIVE) {
            return new Remedy(RemedyKind.BUMP_ANCESTOR, false, null, null, List.of(), List.of(),
                    "Nothing pulls this in on your behalf.");
        }
        // The names are already listed above the remedies, so repeating them here produced a
        // sentence with three coordinates inside it and no room left for the point.
        String who = declaredBy.isEmpty() ? null : String.join(", ", declaredBy);
        return new Remedy(RemedyKind.BUMP_ANCESTOR, false, who, null, List.of(), List.of(),
                who == null
                        ? "Nothing in this SBOM declares this component."
                        : "Whether a newer version of what declares this ships the fix cannot be "
                                + "determined offline — it needs that dependency's own "
                                + "dependencies at versions you do not have. Configure the Maven "
                                + "probe in Settings and check from here to answer it.");
    }

    /**
     * Listed with its condition, and never suggested.
     *
     * <p>Recommending the removal of a dependency the code turns out to use is worse than
     * recommending nothing, and whether it is used is Phase 9's answer.
     */
    private Remedy exclude() {
        return new Remedy(RemedyKind.EXCLUDE, false, null, null, List.of(), List.of(),
                "Only safe if your code does not use this library. Workspace usage detection "
                        + "is not built yet, so SBOMscope cannot tell you whether that holds.");
    }

    /**
     * The suggestion, and the reasoning is deliberately shallow.
     *
     * <p>Declare it and there is a version to change; do not and a pin is the precise answer.
     * Anything cleverer would be guessing at a project's appetite for breakage, which the
     * tool has no way to know.
     */
    private RemedyKind suggest(StoredComponent component, String pinTarget, List<AdvisoryFix> advisories) {
        if (advisories.isEmpty() || pinTarget == null
                || component.scope() == DependencyScope.APPLICATION) {
            return null;
        }
        return component.scope() == DependencyScope.DIRECT ? RemedyKind.UPGRADE : RemedyKind.PIN;
    }

    // --- snippets ----------------------------------------------------------------------

    private boolean isMaven(StoredComponent component) {
        return component.purl() != null && component.purl().startsWith("pkg:maven/");
    }

    private boolean isNpm(StoredComponent component) {
        return component.purl() != null && component.purl().startsWith("pkg:npm/");
    }

    private String upgradeSnippet(StoredComponent component, String version) {
        if (isMaven(component)) {
            return """
                    <dependency>
                      <groupId>%s</groupId>
                      <artifactId>%s</artifactId>
                      <version>%s</version>
                    </dependency>""".formatted(component.group(), component.name(), version);
        }
        if (isNpm(component)) {
            return "\"%s\": \"%s\"".formatted(npmName(component), version);
        }
        return null;
    }

    /**
     * Forcing a version you do not declare.
     *
     * <p>Maven resolves {@code dependencyManagement} ahead of anything a transitive path
     * asks for, and npm's {@code overrides} does the same for the tree below you. Both are
     * the documented way to do this, which is why the snippet can be handed over as-is.
     */
    private String pinSnippet(StoredComponent component, String version) {
        if (isMaven(component)) {
            return """
                    <dependencyManagement>
                      <dependencies>
                        <dependency>
                          <groupId>%s</groupId>
                          <artifactId>%s</artifactId>
                          <version>%s</version>
                        </dependency>
                      </dependencies>
                    </dependencyManagement>""".formatted(component.group(), component.name(), version);
        }
        if (isNpm(component)) {
            return """
                    "overrides": {
                      "%s": "%s"
                    }""".formatted(npmName(component), version);
        }
        return null;
    }

    /** Scoped packages reach us either joined or split; npm always writes them joined. */
    private String npmName(StoredComponent component) {
        if (component.group() == null || component.group().isBlank()) {
            return component.name();
        }
        return component.group() + "/" + component.name();
    }
}
