package dev.sbomscope.probe;

import java.util.List;

/**
 * What the ranked candidates are an answer <em>about</em> — the two questions the panel used to
 * decide silently.
 *
 * <p>Both are diamonds, one level apart. Across modules, several may own the component and only
 * the most-affected one is probed. Within that module, several direct dependencies may pull it
 * in and only one of them is the declaration Maven honours. A version with neither stated is not
 * an answer a reader can act on: it does not say what to bump, and it does not say where the
 * answer holds.
 *
 * @param module          the owning module the whole run is scoped to
 * @param otherModules    other modules that also pull the component in and were <b>not</b>
 *                        probed. Their direct sets differ, so their answer may too — stated
 *                        rather than probed, because probing every owning module multiplies the
 *                        run budget by the module count for a question nobody asked
 * @param ancestor        the direct dependency being bumped: the one the target actually hangs
 *                        under in the resolved tree, read from {@code dependency:tree}'s own
 *                        indentation rather than guessed from the shortest SBOM route
 * @param ancestorVersion that ancestor's currently declared version, so the caption can say what
 *                        is being moved and from where
 * @param otherAncestors  the module's other direct dependencies that also reach the component.
 *                        Listed, never ranked: Maven resolves through {@code ancestor}, so
 *                        bumping any of these alone cannot change what the component resolves
 *                        to — which is the sentence that turns an inexplicable "still affected"
 *                        into an understandable one
 * @param decidedByMaven  false when the tree could not be read for provenance and the ancestor
 *                        fell back to the shortest route. The claim in the caption is weaker
 *                        then, and says so, rather than presenting a guess as a reading
 * @param routesCovered   exact routes through the chosen ancestor in this module
 * @param routesTotal     exact routes from this module to the component
 */
public record BumpScope(
        String module,
        List<String> otherModules,
        String ancestor,
        String ancestorVersion,
        List<String> otherAncestors,
        boolean decidedByMaven,
        int routesCovered,
        int routesTotal) {

    public boolean completeForModule() {
        return routesTotal > 0 && routesCovered == routesTotal;
    }
}
