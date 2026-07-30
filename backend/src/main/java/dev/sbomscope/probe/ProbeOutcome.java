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
 * @param targetDeclaredBy  the module's own direct dependency the target hangs under in the
 *                          resolved tree, as {@code group:artifact} — <b>the declaration Maven
 *                          actually honoured</b>, which is a different question from which route
 *                          is shortest in the SBOM and the only one that decides what a bump
 *                          does. Read from the tree's indentation, so it costs no extra
 *                          invocation. Null when the target is absent, or when it is itself a
 *                          direct dependency of the generated POM
 */
public record ProbeOutcome(
        boolean resolved,
        Map<MavenArtifact, String> resolvedVersions,
        String targetVersion,
        String targetDeclaredBy,
        ProbeFailureReason failureReason,
        String detail) {

    public static ProbeOutcome resolved(
            Map<MavenArtifact, String> resolvedVersions, String targetVersion, String targetDeclaredBy) {
        return new ProbeOutcome(true, resolvedVersions, targetVersion, targetDeclaredBy, null, null);
    }

    /**
     * A resolution with no provenance to report — the shape a caller uses when there is no tree
     * to read it from. Null is the honest value: the search then falls back to the shortest
     * route and says so, rather than treating "unknown" as "no other declaration exists".
     */
    public static ProbeOutcome resolved(Map<MavenArtifact, String> resolvedVersions, String targetVersion) {
        return resolved(resolvedVersions, targetVersion, null);
    }

    public static ProbeOutcome failed(ProbeFailureReason reason, String detail) {
        return new ProbeOutcome(false, Map.of(), null, null, reason, detail);
    }
}
