package dev.sbomscope.reachability;

import java.util.List;

/** Conservative per-component evidence from a completed workspace analysis run. */
public record WorkspaceReachabilityEvidence(
        String purl,
        String modulePath,
        Status status,
        List<List<String>> methodPaths,
        int reachableMethodCount,
        int directMethodCount,
        int displayedPathCount,
        String detail) {

    public enum Status {
        REACHABLE,
        NO_CALL_PATH,
        NEEDS_REVIEW,
        UNAVAILABLE
    }
}
