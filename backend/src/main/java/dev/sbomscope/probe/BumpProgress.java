package dev.sbomscope.probe;

import java.util.ArrayList;
import java.util.List;

import dev.sbomscope.scanner.UpgradeAdvice.Remedy;

/**
 * Progress of one component's bump probe, polled by the UI — the same shape as
 * {@link dev.sbomscope.scanner.DownloadProgress}, for the same reason: a run that can take
 * real wall-clock time must not be a silent wait.
 *
 * @param verdicts   one {@link ProbeStep} per probe as it completes — e.g. {@code "4.2.0 →
 *                   jackson-databind 3.1.6 → clean"} — so the reasoning is visible while it
 *                   runs, not only once it is done. Structured rather than prose since
 *                   2026-07-31: each step names the major line it belongs to, which is what
 *                   lets the panel show an attempt beside the result it contributed to
 * @param candidates one ranked row per major line for the primary declaring ancestor — Tier 1's
 *                   own "candidates, not a recommendation" shape, since no single verdict can
 *                   claim to be the earliest without checking every major
 * @param remedy     populated only for the failure/unavailable paths and for the multi-ancestor
 *                   combination result — reuses the exact type Tier 1's remedies already use,
 *                   so the frontend renders it with the same component. Null whenever
 *                   {@code candidates} is the whole answer
 */
public record BumpProgress(
        State state,
        List<ProbeStep> verdicts,
        List<BumpCandidate> candidates,
        Remedy remedy,
        String message,
        /**
         * Which module and which declaring ancestor the rows are an answer about. Null until
         * calibration has run, since the deciding ancestor is read from that probe's own tree.
         */
        BumpScope scope) {

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
        return new BumpProgress(State.IDLE, List.of(), List.of(), null, null, null);
    }

    public static BumpProgress starting() {
        return new BumpProgress(State.RUNNING, List.of(), List.of(), null, null, null);
    }

    /**
     * Records what this run is an answer about, once calibration has read it from the tree.
     *
     * <p>Carried on the progress rather than on each candidate because every row of one run
     * shares it — it is a property of the search, not of a major line.
     */
    public BumpProgress withScope(BumpScope scope) {
        return new BumpProgress(state, verdicts, candidates, remedy, message, scope);
    }

    /**
     * Back to RUNNING for a continued search, <b>keeping the rows already established</b>.
     * {@link #starting()} would blank them, and a reader who pressed "continue" is watching a
     * table they already have answers in — emptying it to re-derive the same rows would read
     * as having lost them.
     */
    public BumpProgress resuming() {
        return new BumpProgress(State.RUNNING, verdicts, candidates, null, null, scope);
    }

    /** Submitted, but waiting behind another component's probe on the single probe thread. */
    public static BumpProgress queued() {
        return new BumpProgress(State.QUEUED, List.of(), List.of(), null,
                "Queued — a probe for another component is already running. This one will "
                        + "start as soon as it finishes.", null);
    }

    /**
     * The rows as they stand mid-run: the skeleton first, then each major replaced as it settles.
     *
     * <p>Published before anything is known about the lines it names. Every major the search will
     * walk is knowable the moment the feasibility probe returns — the labels come from the
     * current and latest versions, not from any verdict — so the panel can show the shape of the
     * answer immediately and fill it in, instead of showing nothing for minutes and then
     * everything at once. The rows start as {@link BumpCandidate#notProbed}, which already means
     * exactly "this line exists and nothing is known about it yet".
     */
    public BumpProgress withCandidates(List<BumpCandidate> candidates) {
        return new BumpProgress(State.RUNNING, verdicts, List.copyOf(candidates), null, null, scope);
    }

    public BumpProgress withVerdict(ProbeStep verdict) {
        List<ProbeStep> updated = new ArrayList<>(verdicts);
        updated.add(verdict);
        return new BumpProgress(State.RUNNING, List.copyOf(updated), candidates, null, null, scope);
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
        return new BumpProgress(State.COMPLETED, verdicts, candidates, remedy, note, scope);
    }

    /** For the failure/unavailable paths that never reach a ranked list at all. */
    public BumpProgress completed(Remedy remedy) {
        return new BumpProgress(State.COMPLETED, verdicts, List.of(), remedy, null, scope);
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
        return new BumpProgress(State.COMPLETED, verdicts, candidates, null, note, scope);
    }

    public BumpProgress failed(String message) {
        return new BumpProgress(State.FAILED, verdicts, List.of(), null, message, scope);
    }

    /** True for {@code RUNNING} and {@code QUEUED} alike: both mean a probe is already in
     *  flight for this key, so {@link BumpProbeService#start} must not submit a second one. */
    public boolean running() {
        return state == State.RUNNING || state == State.QUEUED;
    }
}
