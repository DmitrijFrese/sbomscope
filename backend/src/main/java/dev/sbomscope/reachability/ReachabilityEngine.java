package dev.sbomscope.reachability;

/**
 * Builds method-level reachability evidence from already-built workspace inputs.
 *
 * <p>Engines have no authority to discover artifacts, invoke a build or interpret a negative
 * result as a security conclusion. Those responsibilities stay with input discovery and the
 * assessment policy respectively.
 */
public interface ReachabilityEngine {

    ReachabilityGraph analyse(WorkspaceAnalysisInputs inputs);
}
