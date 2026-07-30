package dev.sbomscope.settings;

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
        boolean enabled, String executablePath, int maxProbes, int runBudgetMinutes, String profiles) {

    public static final int DEFAULT_MAX_PROBES = 20;
    public static final int DEFAULT_RUN_BUDGET_MINUTES = 8;
    public static final int MIN_PROBES = 1;
    public static final int MAX_PROBES = 200;
    public static final int MIN_RUN_BUDGET_MINUTES = 1;
    public static final int MAX_RUN_BUDGET_MINUTES = 60;

    public boolean hasExecutable() {
        return executablePath != null && !executablePath.isBlank();
    }

    public boolean usable() {
        return enabled && hasExecutable();
    }

    public boolean hasProfiles() {
        return profiles != null && !profiles.isBlank();
    }
}
