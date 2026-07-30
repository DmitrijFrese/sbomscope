package dev.sbomscope.probe;

import java.util.ArrayList;
import java.util.List;

import dev.sbomscope.scanner.UpgradeAdvice.Remedy;

/**
 * Progress of one component's bump probe, polled by the UI — the same shape as
 * {@link dev.sbomscope.scanner.DownloadProgress}, for the same reason: a run that can take
 * real wall-clock time must not be a silent wait.
 *
 * @param verdicts   one line per probe as it completes — e.g. {@code "4.2.0 → jackson-databind
 *                   3.1.6 → clean"} — so the reasoning is visible while it runs, not only once
 *                   it is done
 * @param candidates one ranked row per major line for the primary declaring ancestor — Tier 1's
 *                   own "candidates, not a recommendation" shape, since no single verdict can
 *                   claim to be the earliest without checking every major
 * @param remedy     populated only for the failure/unavailable paths and for the multi-ancestor
 *                   combination result — reuses the exact type Tier 1's remedies already use,
 *                   so the frontend renders it with the same component. Null whenever
 *                   {@code candidates} is the whole answer
 */
public record BumpProgress(
        State state, List<String> verdicts, List<BumpCandidate> candidates, Remedy remedy, String message) {

    /**
     * {@code QUEUED} exists because the single background thread that runs every probe (see
     * {@link BumpProbeService}) serialises them — a second component's probe started while
     * another is in flight does not run concurrently, it waits. Reporting that as {@code
     * RUNNING} would say "probing your own Maven right now" for something that has not
     * started, which is a wrong answer about what is actually happening, not just an
     * imprecise one.
     */
    public enum State { IDLE, QUEUED, RUNNING, COMPLETED, FAILED }

    public static BumpProgress idle() {
        return new BumpProgress(State.IDLE, List.of(), List.of(), null, null);
    }

    public static BumpProgress starting() {
        return new BumpProgress(State.RUNNING, List.of(), List.of(), null, null);
    }

    /**
     * Back to RUNNING for a continued search, <b>keeping the rows already established</b>.
     * {@link #starting()} would blank them, and a reader who pressed "continue" is watching a
     * table they already have answers in — emptying it to re-derive the same rows would read
     * as having lost them.
     */
    public BumpProgress resuming() {
        return new BumpProgress(State.RUNNING, verdicts, candidates, null, null);
    }

    /** Submitted, but waiting behind another component's probe on the single probe thread. */
    public static BumpProgress queued() {
        return new BumpProgress(State.QUEUED, List.of(), List.of(), null,
                "Queued — a probe for another component is already running. This one will "
                        + "start as soon as it finishes.");
    }

    public BumpProgress withVerdict(String verdict) {
        List<String> updated = new ArrayList<>(verdicts);
        updated.add(verdict);
        return new BumpProgress(State.RUNNING, List.copyOf(updated), candidates, null, null);
    }

    /** The ordinary completion: a ranked list, and a remedy only when one applies. */
    public BumpProgress completed(List<BumpCandidate> candidates, Remedy remedy) {
        return completed(candidates, remedy, null);
    }

    /**
     * As above, with a note saying why the run is shorter than a full one.
     *
     * <p>A stopped run is {@code COMPLETED}, not a state of its own, and that is deliberate: it
     * is a cut-short run, exactly as budget exhaustion produces, and every row already reports
     * what it did not reach. What the rows cannot say is <em>why</em> the search stopped, which
     * is the one thing a reader needs to know before deciding whether to press Continue.
     */
    public BumpProgress completed(List<BumpCandidate> candidates, Remedy remedy, String note) {
        return new BumpProgress(State.COMPLETED, verdicts, candidates, remedy, note);
    }

    /** For the failure/unavailable paths that never reach a ranked list at all. */
    public BumpProgress completed(Remedy remedy) {
        return new BumpProgress(State.COMPLETED, verdicts, List.of(), remedy, null);
    }

    /**
     * The run was stopped, keeping whatever it had settled and discarding any remedy.
     *
     * <p>The discard is the point. Killing the {@code mvn} in flight makes that invocation fail,
     * so a run stopped during calibration ends on the "could not resolve" path and would
     * otherwise report the kill as a real dependency problem — a confidently wrong answer
     * produced by the act of asking it to stop. Verdicts and settled candidates survive because
     * they were true before the stop and still are.
     */
    public BumpProgress stopped(String note) {
        return new BumpProgress(State.COMPLETED, verdicts, candidates, null, note);
    }

    public BumpProgress failed(String message) {
        return new BumpProgress(State.FAILED, verdicts, List.of(), null, message);
    }

    /** True for {@code RUNNING} and {@code QUEUED} alike: both mean a probe is already in
     *  flight for this key, so {@link BumpProbeService#start} must not submit a second one. */
    public boolean running() {
        return state == State.RUNNING || state == State.QUEUED;
    }
}
