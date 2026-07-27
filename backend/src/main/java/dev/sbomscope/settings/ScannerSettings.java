package dev.sbomscope.settings;

/**
 * How SBOMscope should perform vulnerability matching.
 *
 * @param enabled        when false the application runs as an SBOM inventory and
 *                       vulnerability columns report "not analysed". This is a
 *                       supported mode, not a broken one — SBOMscope never requires the
 *                       external scanner to be useful.
 * @param executablePath absolute path to the osv-scanner binary. SBOMscope never
 *                       downloads it: the user places it and points here.
 * @param databaseDirectory  where the offline OSV database lives. Unlike the executable,
 *                       this is data rather than code, so SBOMscope will populate it on
 *                       explicit request.
 */
public record ScannerSettings(
        boolean enabled,
        String executablePath,
        String databaseDirectory) {

    public boolean hasExecutable() {
        return executablePath != null && !executablePath.isBlank();
    }

    /** Usable only when switched on and actually pointed at something. */
    public boolean usable() {
        return enabled && hasExecutable();
    }
}
