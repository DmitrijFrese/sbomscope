package dev.sbomscope.reachability;

import java.time.Instant;
import java.util.UUID;

/** One local reachability worker as Monitoring presents it. */
public record WorkspaceAnalysisTaskView(UUID id, UUID sbomId, String workspacePath,
                                        State state, Instant submittedAt, Instant startedAt,
                                        Instant finishedAt) {
    public enum State { QUEUED, RUNNING, COMPLETED, STOPPED, FAILED }
}
