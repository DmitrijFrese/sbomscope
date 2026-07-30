package dev.sbomscope.settings;

import java.util.regex.Pattern;

/**
 * How SBOMscope drives the user's own Maven for the Tier 2 bump probe.
 *
 * <p>Configured exactly like {@link ScannerSettings}: a user-supplied path, never downloaded,
 * unavailable rather than broken when absent. No settings are parsed and no credentials read
 * here — Maven reads its own {@code settings.xml}, so mirrors and authentication come along
 * for free and this never learns them.
 *
 * @param enabled         when false, the Bump-it remedy stays the always-unavailable
 *                        placeholder Tier 1 already shows. Probing is slow enough (a real
 *                        external process, possibly several of them) that it stays opt-in
 *                        independent of whether a path happens to be configured.
 * @param executablePath  absolute path to {@code mvn} (or {@code mvn.cmd} on Windows)
 * @param maxProbes       ceiling on how many {@code mvn dependency:tree} invocations one bump
 *                        probe may spend, shared across ranking every major line and the
 *                        combination step. The only sound lever for trading completeness for
 *                        cost — narrowing the search itself (e.g. a wide version range standing
 *                        in for several minor lines) answers for one version and silently
 *                        drops the rest, which is the exact class of bug this project keeps
 *                        finding and fixing
 * @param runBudgetMinutes wall-clock ceiling for the same run. Measured to matter more than the
 *                         probe count in practice: a cold probe repository can spend minutes on
 *                         a dozen probes that take seconds once warm
 * @param profiles         comma-separated Maven profile IDs (e.g. {@code "prod,internal-repo"}),
 *                         passed to every probe invocation as {@code -P<profiles>} exactly as
 *                         typed — the same syntax {@code mvn} itself accepts. Null or blank
 *                         means no profiles are activated, Maven's own default. A profile that
 *                         adds a repository or changes a property Maven's resolution depends on
 *                         is exactly the kind of thing that has to be active here too, or the
 *                         probe resolves against a build the user does not actually have
 */
public record MavenToolSettings(
        boolean enabled, String executablePath, int maxProbes, int runBudgetMinutes, String profiles,
        String dependencyPluginVersion, String helpPluginVersion) {

    public static final int DEFAULT_MAX_PROBES = 20;
    public static final int DEFAULT_RUN_BUDGET_MINUTES = 8;
    public static final int MIN_PROBES = 1;
    public static final int MAX_PROBES = 200;
    public static final int MIN_RUN_BUDGET_MINUTES = 1;
    public static final int MAX_RUN_BUDGET_MINUTES = 60;

    /**
     * The probe drives these two plugins, pinned rather than invoked by prefix.
     *
     * <p>Configurable because the version that exists is a fact about the user's repository, not
     * about SBOMscope: a curated mirror that proxies an approved subset of Central rather than
     * all of it may carry a different one, and on such a machine the feature would otherwise be
     * unusable with no way to say so. The same reasoning as pointing at your own {@code mvn} and
     * naming your own profiles — the environment is the authority.
     */
    public static final String DEFAULT_DEPENDENCY_PLUGIN_VERSION = "3.6.1";
    public static final String DEFAULT_HELP_PLUGIN_VERSION = "3.4.0";

    /**
     * Interpolated into a goal coordinate such as
     * {@code org.apache.maven.plugins:maven-dependency-plugin:3.6.1:tree}, so a colon or a space
     * would not merely be invalid — it would change which goal Maven runs. Validated on the way
     * in rather than escaped at each use.
     */
    public static final Pattern VERSION_PATTERN = Pattern.compile("[A-Za-z0-9._-]+");

    public boolean hasExecutable() {
        return executablePath != null && !executablePath.isBlank();
    }

    public boolean usable() {
        return enabled && hasExecutable();
    }

    public boolean hasProfiles() {
        return profiles != null && !profiles.isBlank();
    }

    /**
     * {@code org.apache.maven.plugins:maven-dependency-plugin:<version>:tree} — the fully
     * qualified goal, never the {@code dependency:tree} prefix. A prefix costs an extra
     * {@code maven-metadata.xml} lookup to learn which artifact {@code dependency} means (the
     * source of {@code NoPluginFoundForPrefixException}) and then resolves the plugin's
     * <em>latest</em> version, so a probe could behave differently month to month with nothing
     * changed locally. Pinning also makes the probe's plugin requirements a known, finite set —
     * which is what makes seeding a repository on a disconnected machine possible at all.
     */
    public String dependencyTreeGoal() {
        return "org.apache.maven.plugins:maven-dependency-plugin:%s:tree"
                .formatted(versionOr(dependencyPluginVersion, DEFAULT_DEPENDENCY_PLUGIN_VERSION));
    }

    /** {@code org.apache.maven.plugins:maven-help-plugin:<version>:effective-pom}. */
    public String effectivePomGoal() {
        return "org.apache.maven.plugins:maven-help-plugin:%s:effective-pom"
                .formatted(versionOr(helpPluginVersion, DEFAULT_HELP_PLUGIN_VERSION));
    }

    /** Blank means "whatever SBOMscope ships with", so clearing the field cannot break a probe. */
    private static String versionOr(String configured, String fallback) {
        return configured == null || configured.isBlank() ? fallback : configured.trim();
    }
}
