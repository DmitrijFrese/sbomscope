package dev.sbomscope.reachability;

import java.time.Instant;
import java.util.List;

/** What the Inspector can say about one component without overstating a negative result. */
public record WorkspaceComponentAnalysis(
        State state,
        Instant requestedAt,
        Instant finishedAt,
        String message,
        List<WorkspaceReachabilityEvidence> evidence) {

    public enum State {
        NOT_CONFIGURED,
        QUEUED,
        RUNNING,
        COMPLETED,
        STOPPED,
        FAILED
    }

    static WorkspaceComponentAnalysis notConfigured(String message) {
        return new WorkspaceComponentAnalysis(State.NOT_CONFIGURED, null, null, message, List.of());
    }
}
