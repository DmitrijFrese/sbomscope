package dev.sbomscope.bump;

public record BumpRow(
        DeclarationSite site, String minimalTarget, String latestTarget,
        java.util.List<BumpAdvisory> advisories, String highestSeverity,
        String artifactUrl, String currentVersionUrl,
        String minimalTargetUrl, String latestTargetUrl) {}
