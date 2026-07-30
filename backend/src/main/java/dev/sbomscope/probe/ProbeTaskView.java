package dev.sbomscope.probe;

import java.time.Instant;
import java.util.UUID;

/**
 * One probe the queue is holding, as the Monitoring page shows it.
 *
 * <p>Deliberately separate from {@link BumpProgress}, which answers "what did the probe for
 * <em>this component</em> find". This answers "what is this application doing right now", which
 * is a question asked by somebody who has lost track of which component it was — so it carries
 * enough to get back there ({@code sbomId} and {@code purl} are the Inspector's own address)
 * rather than any of the findings.
 *
 * @param startedAt  null while {@code state} is {@code QUEUED} — the distinction the single
 *                   probe thread makes real, and the reason elapsed time is computed by the
 *                   reader from these instants rather than sent as a duration that is stale the
 *                   moment it arrives
 * @param finishedAt null while the probe is still queued or running; with {@code startedAt} it
 *                   is also how long the run actually took
 */
public record ProbeTaskView(
        String id,
        UUID sbomId,
        String purl,
        String component,
        String module,
        State state,
        Instant submittedAt,
        Instant startedAt,
        Instant finishedAt) {

    /**
     * {@code QUEUED} and {@code RUNNING} are the two {@link BumpProgress.State} draws, for the
     * same reason; the rest are how a run ended.
     *
     * <p>Finished runs stay in this list for the session. A probe that has just finished is the
     * one somebody is most likely to be looking for — "did that thing I started actually do
     * anything" is asked immediately after it stops, and a list that empties itself at exactly
     * that moment answers it with silence. {@code STOPPED} is kept apart from {@code COMPLETED}
     * because a run the user cut short and one that ran to the end of its budget are different
     * claims about how much of the search happened.
     */
    public enum State { QUEUED, RUNNING, COMPLETED, STOPPED, FAILED;

        public boolean finished() {
            return this == COMPLETED || this == STOPPED || this == FAILED;
        }
    }
}
