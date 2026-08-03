package dev.sbomscope.reachability;

import java.util.List;
import java.util.Set;

/** JSON-safe form of the parent-approved, read-only input handed to the worker JVM. */
public record ReachabilityWorkerRequest(
        List<String> productionOutputs,
        List<String> supportingOutputs,
        List<Artifact> dependencyArtifacts,
        List<String> missingInputs,
        Set<CompletenessBlocker> blockers,
        String fingerprint) {
    public record Artifact(String purl, String jar) {}
}
