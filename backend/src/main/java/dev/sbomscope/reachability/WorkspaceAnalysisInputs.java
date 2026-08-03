package dev.sbomscope.reachability;

import java.nio.file.Path;
import java.util.List;
import java.util.Set;

/** Immutable, read-only input set handed from discovery to a reachability engine. */
public record WorkspaceAnalysisInputs(
        List<Path> productionOutputs,
        List<Path> supportingOutputs,
        List<ComponentArtifact> dependencyArtifacts,
        List<String> missingInputs,
        Set<CompletenessBlocker> blockers,
        String fingerprint) {

    public WorkspaceAnalysisInputs(List<Path> productionOutputs,
                                   List<ComponentArtifact> dependencyArtifacts,
                                   List<String> missingInputs,
                                   Set<CompletenessBlocker> blockers,
                                   String fingerprint) {
        this(productionOutputs, List.of(), dependencyArtifacts, missingInputs, blockers, fingerprint);
    }

    public boolean hasProductionOutputs() {
        return !productionOutputs.isEmpty();
    }

    public boolean completeForNegativeResult() {
        return missingInputs.isEmpty() && blockers.isEmpty();
    }

    /** A component identity and the exact already-cached jar WALA may read. */
    public record ComponentArtifact(String purl, Path jar) {}
}
