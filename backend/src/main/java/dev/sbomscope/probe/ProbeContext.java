package dev.sbomscope.probe;

import java.time.Duration;
import java.util.List;

/**
 * What one probe run needs, gathered once by the caller rather than re-derived per probe.
 *
 * @param mvnExecutable      path to the user's own {@code mvn}/{@code mvn.cmd} — never
 *                           downloaded, exactly like the osv-scanner binary
 * @param isolatedRepository {@code ~/.sbomscope/probe-repo}, never the user's {@code ~/.m2}.
 *                           A failed probe's {@code .lastUpdated} markers must not be able to
 *                           make a later real build refuse to retry a download
 * @param liftedXml          {@code <dependencyManagement>} and {@code <repositories>} lifted
 *                           verbatim from {@code mvn help:effective-pom} when the SBOM has a
 *                           workspace path attached; absent when it does not, in which case
 *                           the generated POM stays isolated
 * @param timeout            per-probe ceiling; Maven can hang on an unreachable repository
 * @param profiles           comma-separated Maven profile IDs, exactly as configured in
 *                           Settings, or null/blank for none. A profile that changes what a
 *                           dependency resolves to (an added repository, a property the build
 *                           depends on) has to be active here too, or the probe is answering
 *                           for a build the user does not actually run
 */
public record ProbeContext(
        String mvnExecutable,
        String isolatedRepository,
        EffectivePomFragments liftedXml,
        Duration timeout,
        String profiles) {

    public boolean hasWorkspaceLiftIn() {
        return liftedXml != null;
    }

    /** {@code -P<profiles>} as its own argument, or empty when no profile is configured. */
    public List<String> profileArgs() {
        return profiles == null || profiles.isBlank() ? List.of() : List.of("-P" + profiles.trim());
    }
}
