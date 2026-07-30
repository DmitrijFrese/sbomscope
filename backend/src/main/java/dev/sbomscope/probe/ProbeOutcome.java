package dev.sbomscope.probe;

import java.util.Map;

/**
 * What one {@code mvn dependency:tree} invocation found.
 *
 * @param resolvedVersions the version each <em>overridden</em> artifact actually resolved to,
 *                          keyed by artifact — one entry for a single-ancestor bump, several
 *                          for combination testing. Never includes artifacts that were not
 *                          overridden; those are fixed inputs, not something being asked about
 * @param targetVersion     the version of the component being watched for, as it landed in
 *                          the resolved tree — null when the tree does not contain it at all,
 *                          which is reported honestly rather than assumed clean
 */
public record ProbeOutcome(
        boolean resolved,
        Map<MavenArtifact, String> resolvedVersions,
        String targetVersion,
        ProbeFailureReason failureReason,
        String detail) {

    public static ProbeOutcome resolved(Map<MavenArtifact, String> resolvedVersions, String targetVersion) {
        return new ProbeOutcome(true, resolvedVersions, targetVersion, null, null);
    }

    public static ProbeOutcome failed(ProbeFailureReason reason, String detail) {
        return new ProbeOutcome(false, Map.of(), null, reason, detail);
    }
}
