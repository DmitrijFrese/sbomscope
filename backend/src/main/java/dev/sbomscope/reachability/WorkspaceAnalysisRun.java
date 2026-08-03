package dev.sbomscope.reachability;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/** A fingerprinted, offline analysis of the compiled workspace attached to one SBOM. */
public record WorkspaceAnalysisRun(
        UUID id,
        UUID sbomId,
        String inputFingerprint,
        Status status,
        String engine,
        String algorithm,
        List<String> blockers,
        String errorMessage,
        Instant requestedAt,
        Instant startedAt,
        Instant finishedAt) {

    public enum Status {
        QUEUED, RUNNING, COMPLETED, STOPPED, FAILED
    }
}
