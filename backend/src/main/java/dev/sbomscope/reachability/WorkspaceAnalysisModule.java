package dev.sbomscope.reachability;

/** Immutable mapping of one compiled output directory to an aggregate-SBOM application root. */
public record WorkspaceAnalysisModule(
        String modulePath,
        String productionOutput,
        String applicationBomRef,
        MappingStatus mappingStatus,
        String mappingDetail) {

    public enum MappingStatus {
        MAPPED,
        UNMAPPED
    }
}
