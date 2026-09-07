package dev.sbomscope.bump;

/**
 * @param minimalTargetAvailability whether the minimal fix version appears in the release
 *                                  metadata already on disk. Never a claim when nothing on disk
 *                                  can answer — see {@link TargetAvailability}
 */
public record BumpRow(
        DeclarationSite site, String minimalTarget, String latestTarget,
        TargetAvailability minimalTargetAvailability,
        java.util.List<BumpAdvisory> advisories, String highestSeverity,
        String artifactUrl, String currentVersionUrl,
        String minimalTargetUrl, String latestTargetUrl) {}
