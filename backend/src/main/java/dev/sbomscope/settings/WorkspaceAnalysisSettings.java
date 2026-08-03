package dev.sbomscope.settings;

/**
 * Read-only inputs used to construct a workspace reachability classpath.
 *
 * <p>This is deliberately not part of {@link MavenToolSettings}. The Maven probe owns an
 * isolated, app-managed repository because it can download and leave Maven state behind;
 * reachability only reads artifacts the user's normal build has already placed in its own local
 * cache. Keeping the settings separate makes that ownership boundary visible in both code and UI.
 *
 * @param mavenLocalRepository absolute path to the user's Maven artifact cache. SBOMscope reads
 *                             it but never creates, downloads, deletes or otherwise changes it.
 * @param maxRunMinutes hard wall-clock ceiling for one isolated WALA worker. Default 10.
 * @param maxHeapMegabytes hard JVM heap ceiling for one isolated WALA worker. Default 1024.
 */
public record WorkspaceAnalysisSettings(String mavenLocalRepository, int maxRunMinutes, int maxHeapMegabytes) {
    public static final int DEFAULT_MAX_RUN_MINUTES = 10;
    public static final int MIN_MAX_RUN_MINUTES = 1;
    public static final int MAX_MAX_RUN_MINUTES = 60;
    public static final int DEFAULT_MAX_HEAP_MEGABYTES = 1024;
    public static final int MIN_MAX_HEAP_MEGABYTES = 256;
    public static final int MAX_MAX_HEAP_MEGABYTES = 8192;
}
