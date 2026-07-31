package dev.sbomscope.probe;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Service;

import dev.sbomscope.logging.ActivityLogger;
import dev.sbomscope.sbom.ComponentGraph;
import dev.sbomscope.sbom.DependencyScope;
import dev.sbomscope.sbom.GraphNode;
import dev.sbomscope.sbom.StoredComponent;
import dev.sbomscope.scanner.OsvArchiveMatcher.AdvisoryHit;
import dev.sbomscope.scanner.UpgradeAdvice.AdvisoryFix;
import dev.sbomscope.scanner.UpgradeAdvice.Remedy;
import dev.sbomscope.scanner.UpgradeAdvice.RemedyKind;
import dev.sbomscope.scanner.UpgradeAdviceService;
import dev.sbomscope.scanner.VersionOrder;
import dev.sbomscope.settings.MavenSettingsChangedEvent;
import dev.sbomscope.settings.MavenToolSettings;

import static dev.sbomscope.settings.SettingsService.defaultProbeRepository;

/**
 * Orchestrates the Maven probe into ranked {@code BUMP_ANCESTOR} candidates.
 *
 * <p><b>Whole-module, not single-dependency.</b> A component reached by two routes appears in
 * the SBOM as one resolved node with two parents, and the SBOM does not record which
 * declaration Maven honoured. Probing one ancestor in isolation cannot see this: it answers
 * what that dependency brings on its own, which is not the question. Every probe here
 * resolves the owning module's <em>whole</em> direct set, with only the artifact under test
 * overridden, so Maven's own nearest-wins resolution — not an approximation of it — decides
 * what the target resolves to.
 *
 * <p><b>One candidate per major line, never a single winner.</b> A feasibility probe coming
 * back affected does not prove no earlier release is clean — the same non-monotonicity this
 * design already refuses to bisect past — so every major from the currently-declared one up to
 * the latest that exists gets its own row, each carrying whatever it still carries. This is
 * Tier 1's own "candidates, not a recommendation" shape, extended here rather than invented.
 *
 * <p><b>Every probe past feasibility targets an exact known release, never a numeric range.</b>
 * A bounded range such as {@code [3.0.0,4.0.0)} was found live to resolve to {@code 4.0.0-RC2}:
 * Maven compares major versions before qualifiers, so a pre-release of the next major outranks
 * every real release of the one being asked about and can win the range outright. Candidates
 * come from {@code knownVersions}, which already excludes pre-releases.
 *
 * <p><b>Fallback is per-component, by construction.</b> This service is invoked once per
 * component the reader opens; a probe failure here produces an "unavailable, here is why"
 * remedy for <em>this</em> component only. Tier 1's PIN/UPGRADE/EXCLUDE remedies are computed
 * entirely separately in {@link UpgradeAdviceService} and never see this class at all, so
 * nothing here can take them down with it.
 *
 * <p><b>The run budget — probe count and wall-clock time — is user-configurable, and is the
 * only sound lever for trading completeness for cost.</b> Narrowing the search itself instead
 * (a wide version range standing in for several minor lines, say) answers for one version and
 * silently drops the rest — the same class of bug the pre-release finding above already
 * demonstrated. Raising or lowering {@link MavenToolSettings#maxProbes()} and {@link
 * MavenToolSettings#runBudgetMinutes()} changes how much of the search completes before
 * degrading to "not probed"; it never changes what a completed probe is allowed to assume.
 */
@Service
public class BumpProbeService {

    private static final Logger log = LoggerFactory.getLogger(BumpProbeService.class);

    /** Maven can hang on an unreachable repository; this is the ceiling for one invocation. */
    private static final Duration PROBE_TIMEOUT = Duration.ofSeconds(60);

    private final DependencyResolver resolver;
    private final EffectivePomCache effectivePoms;
    private final ActivityLogger activityLog;

    /** Single thread: Maven invocations are heavyweight, and this serialises them like the
     *  OSV database downloads already are. */
    private final ExecutorService executor = Executors.newSingleThreadExecutor(runnable -> {
        Thread thread = new Thread(runnable, "maven-probe");
        thread.setDaemon(true);
        return thread;
    });

    /**
     * Keyed by {@code moduleBomRef -> targetCoordinates} — one probe run considers every
     * declaring ancestor within the module together, so that pair is the natural cache unit,
     * not any single ancestor within it.
     *
     * <p>Session-scoped: cleared on Maven settings change, not persisted. A restart is a fine
     * time to re-validate against whatever configuration is current.
     */
    private final ConcurrentHashMap<String, BumpProgress> progressByKey = new ConcurrentHashMap<>();

    /**
     * The key currently executing on {@link #executor}, or null between runs. Read only to
     * decide what a newly-submitted probe should report about itself — {@code QUEUED} versus
     * {@code RUNNING} — so a stale read costs at most one imprecise poll, never a wrong
     * decision about what actually runs; the executor's own FIFO queue is still the only
     * thing that decides execution order.
     */
    private final AtomicReference<String> activeKey = new AtomicReference<>();

    /**
     * Every probe submitted and not yet finished — the queue as a whole, rather than one
     * component's view of it.
     *
     * <p>A probe deliberately outlives the tab it was started from: the Inspector is a view of
     * this state, not its owner. But that means a tab closed by the reader — or evicted by the
     * tab cap — leaves a probe holding the single probe thread with no way to reach it, because
     * the only other route in is {@code progress(component, graph)}, which requires already
     * knowing which component to ask about. That is exactly what somebody who has lost track of
     * it does not know.
     */
    private final Map<String, ProbeTask> tasks = new ConcurrentHashMap<>();

    /**
     * One submitted probe, from the queue's point of view rather than the component's.
     *
     * <p>Everything mutable here is written by the probe thread and read by request threads
     * listing or cancelling, hence {@code volatile} throughout. None of it needs to be
     * consistent as a set: a listing that catches a task mid-start shows it a poll early or
     * late, which is what polling already means.
     */
    private static final class ProbeTask {
        private final String id = UUID.randomUUID().toString();
        private final String key;
        private final UUID sbomId;
        private final String purl;
        private final String component;
        private final String module;
        private final Instant submittedAt = Instant.now();

        private volatile Instant startedAt;
        private volatile Instant finishedAt;
        private volatile ProbeTaskView.State outcome;
        private volatile Thread thread;
        private volatile SearchBudget budget;
        private volatile Future<?> future;

        /**
         * Checked at the top of the run as well as acted on immediately, because
         * {@code executor.submit} can begin executing before the returned {@link Future} has
         * been assigned — so a cancellation arriving in that window has nothing to cancel and
         * has to be able to leave a note instead.
         */
        private volatile boolean cancelled;

        ProbeTask(String key, BumpRequest request) {
            this.key = key;
            this.sbomId = request.sbomId();
            this.purl = request.component().purl();
            this.component = request.component().coordinates()
                    + (request.component().version() == null ? "" : "@" + request.component().version());
            this.module = request.graph().reachedFrom().isEmpty()
                    ? null
                    : request.graph().reachedFrom().getFirst().module().coordinates();
        }

        ProbeTaskView view() {
            ProbeTaskView.State current = outcome != null
                    ? outcome
                    : startedAt == null ? ProbeTaskView.State.QUEUED : ProbeTaskView.State.RUNNING;
            return new ProbeTaskView(id, sbomId, purl, component, module, current,
                    submittedAt, startedAt, finishedAt);
        }
    }

    /**
     * How many finished probes are kept before the oldest is dropped.
     *
     * <p>A bound rather than a full history: this is a session-scoped record of what just
     * happened, not an audit trail — {@code activity.jsonl} is that, and it survives restarts,
     * which this deliberately does not.
     */
    private static final int REMEMBERED_FINISHED = 25;

    /**
     * Running, queued, and recently finished.
     *
     * <p>Live rows first in submission order — which is the order they will execute in — then
     * finished ones, most recent first. Two orderings in one list because they answer different
     * questions: the queue is about what happens next, the history about what just happened.
     */
    public List<ProbeTaskView> probes() {
        List<ProbeTaskView> live = tasks.values().stream()
                .filter(task -> task.outcome == null)
                .sorted(Comparator.comparing(task -> task.submittedAt))
                .map(ProbeTask::view)
                .toList();

        List<ProbeTaskView> finished = tasks.values().stream()
                .filter(task -> task.outcome != null)
                .sorted(Comparator.comparing((ProbeTask task) -> task.finishedAt).reversed())
                .map(ProbeTask::view)
                .toList();

        List<ProbeTaskView> all = new ArrayList<>(live);
        all.addAll(finished);
        return List.copyOf(all);
    }

    /**
     * Stops a probe, whether it is running or still waiting.
     *
     * <p>A running probe stops at the next checkpoint the search already consults, keeping every
     * row it had settled — see {@link SearchBudget#cancelled}. Killing the {@code mvn} in flight
     * is what makes that prompt rather than up to a full probe timeout away, and it is also the
     * only thing that works: the probe thread is blocked reading that process's output, which no
     * interrupt will end.
     *
     * <p>A queued probe simply never starts, and its progress record is dropped so the component
     * reads as never probed rather than as permanently pending.
     *
     * @return whether a task with this id was found to stop
     */
    public boolean cancel(String taskId) {
        ProbeTask task = tasks.get(taskId);
        if (task == null || task.outcome != null) {
            // Already finished — it is still in the list, as history, but there is nothing left
            // to stop. Reported as a miss rather than a success, since claiming to have stopped
            // something that ended on its own would be a small lie about what just happened.
            return false;
        }

        task.cancelled = true;
        SearchBudget budget = task.budget;
        if (budget != null) {
            budget.cancel();
        }

        Thread thread = task.thread;
        if (thread != null) {
            MavenInvocation.cancelRunningOn(thread);
            activityLog.record(ActivityLogger.Category.PROCESS, "MAVEN_PROBE",
                    "Stopped on request: the running probe for " + task.component);
            return true;
        }

        Future<?> future = task.future;
        if (future != null) {
            future.cancel(false);
        }
        // The component reads as never probed rather than permanently pending, but the row
        // stays as history: "I queued that and then stopped it" is worth being able to see.
        progressByKey.remove(task.key);
        task.finishedAt = Instant.now();
        task.outcome = ProbeTaskView.State.STOPPED;
        forgetOldestFinished();
        activityLog.record(ActivityLogger.Category.PROCESS, "MAVEN_PROBE",
                "Stopped on request before it started: the queued probe for " + task.component);
        return true;
    }

    BumpProbeService(DependencyResolver resolver, EffectivePomCache effectivePoms, ActivityLogger activityLog) {
        this.resolver = resolver;
        this.effectivePoms = effectivePoms;
        this.activityLog = activityLog;
    }

    @EventListener
    public void onMavenSettingsChanged(MavenSettingsChangedEvent event) {
        progressByKey.clear();
    }

    /** Current status for this component — {@code IDLE} if a probe was never started. */
    public BumpProgress progress(StoredComponent component, ComponentGraph graph) {
        String key = cacheKeyFor(graph, component);
        return key == null ? BumpProgress.idle() : progressByKey.getOrDefault(key, BumpProgress.idle());
    }

    /**
     * Starts a probe if one is not already running or complete for this exact
     * (module, target) pair, and returns the current progress either way.
     *
     * <p>{@code mavenSettings} is passed in rather than looked up here, so this service is a
     * pure function of its inputs — cheap to construct in a test with a fake resolver and no
     * Spring context at all, the same reason {@link UpgradeAdviceService} takes its evaluator
     * as a parameter instead of reaching for settings itself.
     */
    public BumpProgress start(BumpRequest request, MavenToolSettings mavenSettings) {
        if (request.component().scope() != DependencyScope.TRANSITIVE) {
            return BumpProgress.idle().failed("Nothing pulls this in on your behalf.");
        }

        String key = cacheKeyFor(request.graph(), request.component());
        if (key == null) {
            return BumpProgress.idle().failed("Nothing in this SBOM declares this component.");
        }

        if (!mavenSettings.usable()) {
            return BumpProgress.idle().failed(
                    "Configure the Maven probe in Settings, and enable it, before checking here.");
        }

        BumpProgress existing = progressByKey.get(key);
        if (existing != null && (existing.running() || existing.state() == BumpProgress.State.COMPLETED)) {
            return existing;
        }

        // Whether this reports RUNNING or QUEUED is decided here, once, from whatever
        // activeKey happens to hold right now — a snapshot, not a reservation. The executor's
        // own FIFO queue is what actually decides execution order; this can only under- or
        // over-report queueing by one poll if it races another start(), never get the order
        // of execution itself wrong.
        BumpProgress initial = activeKey.get() == null ? BumpProgress.starting() : BumpProgress.queued();
        progressByKey.put(key, initial);
        ProbeTask task = new ProbeTask(key, request);
        tasks.put(task.id, task);
        task.future = executor.submit(() -> runProbe(key, request, mavenSettings, task));
        return progressByKey.get(key);
    }

    /**
     * Extends a finished run that the budget cut short, keeping every row already settled.
     *
     * <p>Without this the only way to look further was to change the Maven settings — which
     * clears the cache as a side effect — and pay for the whole search again from calibration.
     * A row marked "not probed" or "checked up to here" is a question the reader can now
     * answer directly, and answering it costs only the majors that are actually unfinished.
     *
     * <p>Each press takes a <b>fresh</b> budget rather than what was left of the old one, so it
     * means "spend another run's worth on this" and can be pressed again. Calibration and the
     * feasibility probe are not repeated: the model was validated on the first run, settings
     * cannot have changed without clearing this cache, and the existing rows already enumerate
     * every major, which is the only thing feasibility established that is still needed.
     */
    public BumpProgress continueRun(BumpRequest request, MavenToolSettings mavenSettings) {
        String key = cacheKeyFor(request.graph(), request.component());
        if (key == null) {
            return BumpProgress.idle().failed("Nothing in this SBOM declares this component.");
        }
        if (!mavenSettings.usable()) {
            return BumpProgress.idle().failed(
                    "Configure the Maven probe in Settings, and enable it, before checking here.");
        }

        BumpProgress existing = progressByKey.get(key);
        if (existing == null || existing.state() != BumpProgress.State.COMPLETED) {
            // Nothing finished to continue from. A run already going will report its own
            // progress; anything else has to start from the beginning.
            return existing != null ? existing : start(request, mavenSettings);
        }
        if (existing.candidates().isEmpty()) {
            // The run never ranked anything — it failed at calibration, or feasibility, or the
            // archive was not indexed. There is nothing to carry forward, so "continue" here
            // means run it again now that whatever blocked it may have been put right. Without
            // this, a cached unavailable result was a dead end: start() returns the cached
            // COMPLETED forever, and the only way out was changing a Maven setting to clear the
            // cache as a side effect, or restarting the application.
            progressByKey.remove(key);
            return start(request, mavenSettings);
        }
        if (existing.candidates().stream().noneMatch(BumpProbeService::unfinished)) {
            return existing;
        }

        BumpProgress resumed = existing.resuming();
        progressByKey.put(key, activeKey.get() == null ? resumed : BumpProgress.queued());
        ProbeTask task = new ProbeTask(key, request);
        tasks.put(task.id, task);
        task.future = executor.submit(
                () -> runContinue(key, request, mavenSettings, existing.candidates(), existing.remedy(), task));
        return progressByKey.get(key);
    }

    /** A row the search never settled: a major it never reached, or one it stopped partway. */
    private static boolean unfinished(BumpCandidate candidate) {
        return !candidate.probed() || candidate.higherReleasesUnchecked();
    }

    private String cacheKeyFor(ComponentGraph graph, StoredComponent component) {
        if (graph.reachedFrom().isEmpty()) {
            return null;
        }
        return graph.reachedFrom().getFirst().module().bomRef() + "->" + component.coordinates();
    }

    /**
     * The declaring ancestor Maven actually resolves the target through, not the one on the
     * shortest SBOM route.
     *
     * <p>These are different questions and the difference decides whether a bump does anything.
     * Maven picks by depth in the <em>resolved</em> tree; the graph's routes are ordered by
     * length in the SBOM. Where they disagree, bumping the shortest-route ancestor moves the
     * resolved version by nothing at all — a result that reads as "upstream has not fixed this"
     * when it actually means "this declaration never won".
     *
     * <p>Calibration already resolved the untouched module and its tree names the winner, so
     * this costs nothing. Falls back to the first route when the tree could not be read for
     * provenance, or when the winner is not one of the ancestors the graph knows about —
     * reported through {@link BumpScope#decidedByMaven} rather than silently.
     */
    private GraphNode decidingAncestor(List<GraphNode> ancestorNodes, ProbeOutcome calibration) {
        String declaredBy = calibration.targetDeclaredBy();
        if (declaredBy == null) {
            return ancestorNodes.getFirst();
        }
        return ancestorNodes.stream()
                .filter(node -> declaredBy.equals(node.coordinates()))
                .findFirst()
                .orElse(ancestorNodes.getFirst());
    }

    /**
     * Publishes what this run is an answer about, so the panel can say it rather than implying
     * it: which module, which declaring ancestor, and what else reaches the component and was
     * deliberately not ranked.
     */
    private void recordScope(String key, BumpRequest request, List<GraphNode> ancestorNodes,
                              GraphNode chosen, ProbeOutcome calibration) {
        List<ComponentGraph.ModuleRoutes> owners = request.graph().reachedFrom();
        List<String> otherModules = owners.stream()
                .skip(1)
                .map(owner -> owner.module().coordinates())
                .toList();
        List<String> otherAncestors = ancestorNodes.stream()
                .filter(node -> !node.coordinates().equals(chosen.coordinates()))
                .map(GraphNode::coordinates)
                .toList();

        BumpScope scope = new BumpScope(
                owners.isEmpty() ? null : owners.getFirst().module().coordinates(),
                otherModules,
                chosen.coordinates(),
                chosen.version(),
                otherAncestors,
                chosen.coordinates().equals(calibration.targetDeclaredBy()));

        progressByKey.compute(key, (k, current) ->
                (current == null ? BumpProgress.starting() : current).withScope(scope));
    }

    /** Every distinct Maven ancestor, within the most-affected module, that reaches the target. */
    private List<GraphNode> distinctAncestorsInPrimaryModule(ComponentGraph graph) {
        if (graph.reachedFrom().isEmpty()) {
            return List.of();
        }
        Map<String, GraphNode> byCoordinates = new LinkedHashMap<>();
        for (List<GraphNode> route : graph.reachedFrom().getFirst().routes()) {
            if (route.size() < 2) {
                continue;
            }
            GraphNode ancestor = route.get(1);
            if (ancestor.purl() != null && ancestor.purl().startsWith("pkg:maven/")) {
                byCoordinates.putIfAbsent(ancestor.coordinates(), ancestor);
            }
        }
        return List.copyOf(byCoordinates.values());
    }

    private List<ModuleDependency> moduleDependenciesOf(BumpRequest request) {
        return request.moduleDirectDependencies().stream()
                .filter(node -> node.purl() != null && node.purl().startsWith("pkg:maven/"))
                .map(node -> new ModuleDependency(MavenArtifact.fromCoordinates(node.coordinates()), node.version()))
                .toList();
    }

    // --- the probe itself ------------------------------------------------------------------

    private void runProbe(String key, BumpRequest request, MavenToolSettings mavenSettings, ProbeTask task) {
        if (!claim(task)) {
            progressByKey.remove(key);
            return;
        }
        activeKey.set(key);
        // Overwrites a QUEUED record with RUNNING now that this key has actually reached the
        // front of the single background thread — without this, a queued probe would still
        // read QUEUED for its own entire run, since nothing else updates the state field
        // until the first verdict lands partway through calibration.
        progressByKey.compute(key, (k, current) -> BumpProgress.starting());
        try {
            StoredComponent component = request.component();
            MavenArtifact target = MavenArtifact.fromCoordinates(component.coordinates());
            ProbeContext context = buildContext(mavenSettings, request.workspacePath());
            // The only sound lever for trading completeness for cost — see the class-level
            // note. User-configurable because a cold probe repository resolving a real
            // dependency tree took roughly four minutes for twelve probes in practice, against
            // about one minute warm, and how many majors need ranking varies by project.
            SearchBudget budget = new SearchBudget(
                    Instant.now().plus(Duration.ofMinutes(mavenSettings.runBudgetMinutes())),
                    mavenSettings.maxProbes());
            task.budget = budget;

            // Nothing below can be trusted if Tier 1b cannot say whether a candidate is clean
            // at all. Checked against the target's own current version, since the evaluator is
            // scoped to that component's ecosystem and name.
            if (checkClean(component.version(), request.targetEvaluator()) == CleanCheck.UNKNOWN) {
                complete(key, unavailable(
                        "The local vulnerability archive for this ecosystem is not indexed, so a "
                                + "candidate version's cleanliness cannot be confirmed offline. "
                                + "Index it from Settings first."));
                return;
            }

            List<ModuleDependency> moduleDeps = moduleDependenciesOf(request);

            // Step 0 — whole-module calibration: does resolving the module's own declared set,
            // untouched, reproduce what the SBOM actually reports? This is a stronger claim
            // than calibrating one chain, because it is checked against every competing
            // declaration at once, the same way Maven's real resolution was.
            ProbeOutcome calibration = resolver.resolve(moduleDeps, Map.of(), target, context);
            budget.spend();
            appendVerdict(key, verdictForCalibration(calibration, component));

            if (!calibration.resolved()) {
                complete(key, unavailable(failureNote(calibration)));
                return;
            }
            if (calibration.targetVersion() == null || !calibration.targetVersion().equals(component.version())) {
                complete(key, unavailable(
                        "Resolving the whole module in isolation does not reproduce this project's "
                                + "resolved version — something outside what SBOMscope can see overrides "
                                + "it, most likely a parent POM's dependencyManagement. A pin is the "
                                + "answer here, not a guessed bump."));
                return;
            }

            List<GraphNode> ancestorNodes = distinctAncestorsInPrimaryModule(request.graph());
            if (ancestorNodes.isEmpty()) {
                complete(key, unavailable("Nothing in this SBOM declares this component."));
                return;
            }

            // Step 1 — rank every major line for the ancestor that actually decides. Not "first
            // success wins": a later major being affected proves nothing about an earlier one,
            // and Tier 1's own "candidates, not a recommendation" shape applies here too.
            GraphNode primary = decidingAncestor(ancestorNodes, calibration);
            recordScope(key, request, ancestorNodes, primary, calibration);
            List<BumpCandidate> candidates = rankCandidates(
                    key, moduleDeps, primary, target, request.targetEvaluator(), context, budget);
            boolean anyClean = candidates.stream().anyMatch(BumpCandidate::clean);

            // Step 2 — combination: only worth trying when the primary ancestor alone found
            // nothing clean, and only with more than one route into the same module. One
            // feasibility-shaped probe, not a ranked search — "you have to move all of them" is
            // the honest answer here, and it is deliberately coarser than the ranking above.
            if (!anyClean && ancestorNodes.size() > 1 && !budget.exhausted()) {
                Map<MavenArtifact, String> allToLatest = new LinkedHashMap<>();
                for (GraphNode ancestorNode : ancestorNodes) {
                    allToLatest.put(MavenArtifact.fromCoordinates(ancestorNode.coordinates()),
                            "[" + ancestorNode.version() + ",)");
                }
                ProbeOutcome combo = resolver.resolve(moduleDeps, allToLatest, target, context);
                budget.spend();
                CleanCheck comboClean = combo.resolved() && combo.targetVersion() != null
                        ? checkClean(combo.targetVersion(), request.targetEvaluator())
                        : CleanCheck.UNKNOWN;
                appendVerdict(key, verdictForCombination(allToLatest, combo, comboClean));

                if (combo.resolved() && comboClean == CleanCheck.CLEAN) {
                    completeWithCandidates(key, candidates, remedyForCombination(combo.resolvedVersions(), request.advisories()));
                    return;
                }

                String names = ancestorNodes.stream().map(GraphNode::coordinates).collect(Collectors.joining(", "));
                completeWithCandidates(key, candidates, unavailable(
                        ("No single ancestor, and no combination of %s, resolves this cleanly. The ranked "
                                + "candidates show what each still carries.").formatted(names)),
                        budget.cancelled() ? STOPPED_NOTE : null);
                return;
            }

            completeWithCandidates(key, candidates, null, budget.cancelled() ? STOPPED_NOTE : null);

        } catch (ProbeUnavailable e) {
            complete(key, unavailable(e.getMessage()));
        } catch (Throwable t) {
            // Deliberately Throwable, not RuntimeException: this runs on the single background
            // thread with nothing else watching it, so anything this does not catch leaves the
            // progress record stuck at RUNNING forever — the one outcome worse than an honest
            // "failed unexpectedly", since the panel would show a spinner indefinitely with no
            // way for the reader to learn anything went wrong at all.
            log.warn("Bump probe failed unexpectedly for {}", key, t);
            complete(key, unavailable("The probe failed unexpectedly: " + t.getMessage()));
        } finally {
            activeKey.compareAndSet(key, null);
            release(task);
        }
    }

    /**
     * Marks a task as the one now executing, or declines it because it was cancelled while it
     * sat in the queue.
     *
     * <p>Both halves matter. Recording the thread is what lets {@link #cancel} reach the
     * {@code mvn} this run is blocked on; checking {@code cancelled} closes the window where a
     * cancellation arrives after the executor has picked the task up but before
     * {@code executor.submit} has handed back the {@link Future} there was to cancel.
     */
    private boolean claim(ProbeTask task) {
        if (task.cancelled) {
            task.finishedAt = Instant.now();
            task.outcome = ProbeTaskView.State.STOPPED;
            forgetOldestFinished();
            return false;
        }
        task.thread = Thread.currentThread();
        task.startedAt = Instant.now();
        return true;
    }

    /**
     * Moves a task from live to finished, keeping it in the list.
     *
     * <p>The outcome is read from the progress record the run just wrote rather than tracked
     * separately, so the row and the component's own panel can never disagree about how it
     * ended. A run stopped on request is {@code STOPPED} even though its progress record says
     * {@code COMPLETED} — which is correct there, since a cut-short run keeps its settled rows —
     * because here the question is how much of the search happened, not what it found.
     */
    private void release(ProbeTask task) {
        task.thread = null;
        task.budget = null;
        task.finishedAt = Instant.now();

        BumpProgress finalProgress = progressByKey.get(task.key);
        if (task.cancelled) {
            task.outcome = ProbeTaskView.State.STOPPED;
            // Applied here rather than at each completion point because a stop lands on
            // whichever path the run happened to be on. Stopping during calibration kills the
            // mvn mid-invocation, so the run ends by reporting *that* failure — "nothing in
            // this SBOM resolves cleanly" — which is a confidently wrong answer manufactured by
            // the act of stopping it. This is the one place every exit path passes through.
            progressByKey.computeIfPresent(task.key, (k, current) -> current.stopped(STOPPED_NOTE));
        } else if (finalProgress != null && finalProgress.state() == BumpProgress.State.FAILED) {
            task.outcome = ProbeTaskView.State.FAILED;
        } else {
            task.outcome = ProbeTaskView.State.COMPLETED;
        }

        forgetOldestFinished();
    }

    /** Keeps the remembered history bounded; the oldest to finish is the first to go. */
    private void forgetOldestFinished() {
        List<ProbeTask> finished = tasks.values().stream()
                .filter(task -> task.outcome != null && task.finishedAt != null)
                .sorted(Comparator.comparing(task -> task.finishedAt))
                .toList();
        for (int i = 0; i < finished.size() - REMEMBERED_FINISHED; i++) {
            tasks.remove(finished.get(i).id);
        }
    }

    /**
     * A stopped run is a cut-short run, and says so where the reader is looking.
     *
     * <p>The rows themselves already carry the truth — a major never reached is {@code
     * probed: false}, one walked partway is {@code higherReleasesUnchecked} — so nothing here
     * has to reinterpret them. What the message adds is <em>why</em> the run is short, which
     * budget exhaustion and a deliberate stop would otherwise be unable to tell apart.
     */
    private static final String STOPPED_NOTE =
            "Stopped on request. Everything already settled is kept — Continue resumes from where it stopped.";

    /**
     * Re-ranks only the unfinished majors, in place, leaving settled rows untouched.
     *
     * <p>A cut-short row resumes <em>above</em> the version it stopped at — that is exactly what
     * {@code rankMajor}'s {@code startAfterMinor} already expresses, so continuing needed no new
     * search logic, only a different starting point per row.
     */
    private void runContinue(String key, BumpRequest request, MavenToolSettings mavenSettings,
                              List<BumpCandidate> existing, Remedy previousRemedy, ProbeTask task) {
        if (!claim(task)) {
            // Nothing to roll back to but the rows it was going to extend, which is exactly
            // what a continue that never started should leave behind.
            completeWithCandidates(key, existing, previousRemedy, STOPPED_NOTE);
            return;
        }
        activeKey.set(key);
        progressByKey.compute(key, (k, current) ->
                current == null ? BumpProgress.starting() : current.resuming());
        try {
            StoredComponent component = request.component();
            MavenArtifact target = MavenArtifact.fromCoordinates(component.coordinates());
            ProbeContext context = buildContext(mavenSettings, request.workspacePath());
            SearchBudget budget = new SearchBudget(
                    Instant.now().plus(Duration.ofMinutes(mavenSettings.runBudgetMinutes())),
                    mavenSettings.maxProbes());
            task.budget = budget;

            List<ModuleDependency> moduleDeps = moduleDependenciesOf(request);
            List<GraphNode> ancestorNodes = distinctAncestorsInPrimaryModule(request.graph());
            if (ancestorNodes.isEmpty()) {
                complete(key, unavailable("Nothing in this SBOM declares this component."));
                return;
            }
            GraphNode primary = ancestorNodes.getFirst();
            MavenArtifact ancestor = MavenArtifact.fromCoordinates(primary.coordinates());
            MajorMinor current = MajorMinor.parse(primary.version());
            List<String> knownVersions = resolver.knownVersions(ancestor, context);

            // Starts as the rows already settled and replaces them in place, so a resumed run
            // fills in exactly as a first one does rather than showing the old list until the
            // whole pass finishes. `resuming()` has already put these back on screen.
            List<BumpCandidate> merged = new ArrayList<>(existing);
            for (int index = 0; index < merged.size(); index++) {
                BumpCandidate candidate = merged.get(index);
                if (!unfinished(candidate) || budget.exhausted()) {
                    continue;
                }
                merged.set(index, rankMajor(key, moduleDeps, ancestor, candidate.ancestorCoordinates(), target,
                        request.targetEvaluator(), context, budget, candidate.major(),
                        resumePointFor(candidate, current), knownVersions, candidate.label()));
                publishCandidates(key, merged);
            }

            // A clean row found on this pass retires any "nothing resolves this" note the first
            // run left behind — that verdict was true of what had been probed then, and is not
            // true of what has been probed now.
            boolean anyClean = merged.stream().anyMatch(BumpCandidate::clean);
            completeWithCandidates(key, merged, anyClean ? null : previousRemedy,
                    budget.cancelled() ? STOPPED_NOTE : null);

        } catch (ProbeUnavailable e) {
            complete(key, unavailable(e.getMessage()));
        } catch (Throwable t) {
            log.warn("Continued bump probe failed unexpectedly for {}", key, t);
            complete(key, unavailable("The probe failed unexpectedly: " + t.getMessage()));
        } finally {
            activeKey.compareAndSet(key, null);
            release(task);
        }
    }

    /**
     * Where a resumed walk picks up: above the last version actually probed for a cut-short
     * major, and from the start for one never reached — except the currently-declared major,
     * which still skips the minor lines below the version in use, exactly as the first pass did.
     */
    private long resumePointFor(BumpCandidate candidate, MajorMinor current) {
        if (candidate.higherReleasesUnchecked() && candidate.version() != null) {
            return MajorMinor.parse(candidate.version()).minor();
        }
        return candidate.major() == current.major() ? current.minor() - 1 : -1;
    }

    /**
     * One row per major line, from the currently-declared one up to the latest that exists.
     *
     * <p>The feasibility probe ({@code [current,)}) is kept for two reasons that have nothing to
     * do with picking a winner: it is the metadata primer — {@code knownVersions} reads the local
     * repository, and nothing is there until some range probe makes Maven fetch it — and it
     * establishes the upper bound for the major loop below. <b>Its result no longer stops the
     * search.</b> Found live: {@code keycloak-core}'s own latest release (26.7.0) still left
     * jackson-databind affected, and the first-pass search took that as proof nothing works,
     * without probing a single intermediate Keycloak release. That is unproven, not disproven —
     * exactly the non-monotonicity this design already invokes elsewhere.
     */
    private List<BumpCandidate> rankCandidates(String key, List<ModuleDependency> moduleDeps, GraphNode ancestorNode,
                                                MavenArtifact target, UpgradeAdviceService.TargetEvaluator evaluator,
                                                ProbeContext context, SearchBudget budget) {
        MavenArtifact ancestor = MavenArtifact.fromCoordinates(ancestorNode.coordinates());
        String currentVersion = ancestorNode.version();
        String coordinates = ancestorNode.coordinates();

        if (budget.exhausted()) {
            return List.of();
        }
        // Null major: this one spans every line by construction, so filing it under any single
        // major would misattribute it.
        ProbeAttempt feasibility = probeOne(moduleDeps, ancestor, "[" + currentVersion + ",)", target,
                context, evaluator, key, budget, null);
        if (!feasibility.outcome().resolved()) {
            // Not even a ranked list can be built without knowing what exists. The reason is
            // carried out rather than swallowed: an empty list alone completed the run showing
            // nothing at all — no rows, no remedy, no error — which reads as "the probe found
            // no upgrade" when what happened is that it never got to look.
            throw new ProbeUnavailable(failureNote(feasibility.outcome()));
        }
        String globalLatest = feasibility.outcome().resolvedVersions().get(ancestor);
        List<String> knownVersions = resolver.knownVersions(ancestor, context);

        MajorMinor current = MajorMinor.parse(currentVersion);
        MajorMinor latest = MajorMinor.parse(globalLatest);

        // Every row up front, all of them unprobed — the skeleton. Which majors will be walked
        // is settled the moment feasibility returns, so the panel can show the shape of the
        // answer now and fill it in, rather than showing nothing for minutes and then everything
        // at once. `notProbed` already means "this line exists and nothing is known yet", so the
        // skeleton is the honest state rather than a placeholder that has to be explained.
        List<BumpCandidate> candidates = new ArrayList<>();
        for (long major = current.major(); major <= latest.major(); major++) {
            candidates.add(BumpCandidate.notProbed(
                    labelFor(major, current.major(), latest.major()), coordinates, major));
        }
        publishCandidates(key, candidates);

        for (int index = 0; index < candidates.size(); index++) {
            long major = current.major() + index;
            // A budget that runs out leaves the remaining rows exactly as the skeleton set them,
            // which is the same claim they would have carried anyway: reached, not examined.
            if (budget.exhausted()) {
                continue;
            }
            long startAfterMinor = major == current.major() ? current.minor() - 1 : -1;
            candidates.set(index, rankMajor(key, moduleDeps, ancestor, coordinates, target, evaluator,
                    context, budget, major, startAfterMinor, knownVersions,
                    labelFor(major, current.major(), latest.major())));
            publishCandidates(key, candidates);
        }
        return candidates;
    }

    /** One major's row settled, or the initial skeleton — published so the panel can fill in. */
    private void publishCandidates(String key, List<BumpCandidate> candidates) {
        progressByKey.compute(key, (k, current) ->
                (current == null ? BumpProgress.starting() : current).withCandidates(candidates));
    }

    private String labelFor(long major, long currentMajor, long latestMajor) {
        if (major == currentMajor) {
            return "Stay on %d.x".formatted(major);
        }
        if (major == latestMajor) {
            return "Move to %d.x (latest)".formatted(major);
        }
        return "Move to %d.x".formatted(major);
    }

    /**
     * Walks minor lines ascending within one major, starting after {@code startAfterMinor},
     * looking for the earliest clean one. Always walks the whole major within budget — an
     * earlier release being affected proves nothing about a later one and vice versa, so the
     * only way to find the earliest clean line is to look, not to infer it from one probe.
     *
     * <p>When nothing in the major is clean, the last release actually probed becomes the row's
     * reported version, carrying whatever it still carries. Walked to the end that is the
     * major's own highest known release; stopped early by the budget it is not, and the row is
     * marked {@code higherReleasesUnchecked} so the two cannot be read as the same claim.
     */
    private BumpCandidate rankMajor(String key, List<ModuleDependency> moduleDeps, MavenArtifact ancestor,
                                     String ancestorCoordinates, MavenArtifact target,
                                     UpgradeAdviceService.TargetEvaluator evaluator, ProbeContext context,
                                     SearchBudget budget, long major, long startAfterMinor,
                                     List<String> knownVersions, String label) {

        List<Long> minors = knownVersions.stream()
                .map(MajorMinor::parse)
                .filter(mm -> mm.major() == major && mm.minor() > startAfterMinor)
                .map(MajorMinor::minor)
                .distinct()
                .sorted()
                .toList();

        String lastVersion = null;
        ProbeAttempt lastAttempt = null;
        // Set only where the budget stopped the walk with minor lines still unexamined. A walk
        // that ran to the end, or stopped because it found its earliest clean release, is a
        // complete answer for this major and must not be marked.
        boolean higherReleasesUnchecked = false;

        for (long minor : minors) {
            if (budget.exhausted()) {
                higherReleasesUnchecked = true;
                break;
            }
            String version = highestWithin(knownVersions, major, minor);
            if (version == null) {
                continue;
            }
            ProbeAttempt attempt = probeOne(moduleDeps, ancestor, "[" + version + "]", target, context,
                    evaluator, key, budget, major);
            lastVersion = version;
            lastAttempt = attempt;
            if (attempt.isCleanResolution()) {
                break; // ascending order guarantees this is the earliest clean line
            }
        }

        if (lastAttempt == null) {
            // Nothing in this major was probed at all, whether the budget ran out on the first
            // step or the major has no releases to look at — "not probed" already says that
            // without needing the partial marker too.
            return BumpCandidate.notProbed(label, ancestorCoordinates, major);
        }

        String targetVersion = lastAttempt.outcome().resolved() ? lastAttempt.outcome().targetVersion() : null;
        List<AdvisoryHit> hits = targetVersion == null ? List.of() : evaluator.evaluate(targetVersion).orElse(List.of());
        boolean clean = hits.isEmpty();
        boolean clearsCriticalAndHigh = hits.stream().noneMatch(BumpProbeService::isCriticalOrHigh);

        return new BumpCandidate(label, ancestorCoordinates, major, lastVersion, targetVersion, true,
                clean, clearsCriticalAndHigh, hits, dependencySnippet(ancestor, lastVersion),
                higherReleasesUnchecked);
    }

    private static boolean isCriticalOrHigh(AdvisoryHit hit) {
        return "HIGH".equalsIgnoreCase(hit.rating()) || "CRITICAL".equalsIgnoreCase(hit.rating());
    }

    /** The highest known release on one exact minor line ({@code major.minor.*}), or null. */
    private String highestWithin(List<String> knownVersions, long major, long minor) {
        return knownVersions.stream()
                .filter(version -> {
                    MajorMinor mm = MajorMinor.parse(version);
                    return mm.major() == major && mm.minor() == minor;
                })
                .max(VersionOrder.INSTANCE)
                .orElse(null);
    }

    /**
     * @param major the major line this attempt belongs to, or null for the opening feasibility
     *              probe, which spans every line. Threaded through rather than parsed back out
     *              of {@code versionSpec} later: the caller knows it, and recovering it from the
     *              rendered string would be inference where there is a fact.
     */
    private ProbeAttempt probeOne(List<ModuleDependency> moduleDeps, MavenArtifact ancestor, String versionSpec,
                                   MavenArtifact target, ProbeContext context,
                                   UpgradeAdviceService.TargetEvaluator evaluator, String key, SearchBudget budget,
                                   Long major) {
        ProbeOutcome outcome = resolver.resolve(moduleDeps, Map.of(ancestor, versionSpec), target, context);
        budget.spend();

        String resolvedAncestor = outcome.resolvedVersions().get(ancestor);
        if (outcome.resolved() && isPreRelease(resolvedAncestor)) {
            // A right-exclusive upper bound such as [3.0.0,4.0.0) still admits 4.0.0's own
            // milestones and release candidates — found live: Maven sorts 4.0.0-RC2 below the
            // final 4.0.0, so it satisfies "< 4.0.0" and can win the range. Never offered as an
            // answer regardless of what the archive says about the target: a confident
            // milestone recommendation is worse than continuing the search past it.
            // NOT_CHECKED rather than AFFECTED: refusing to offer a milestone is a decision about
            // what we will recommend, not a finding about the version. It is treated as
            // still-affected internally only so the walk continues past it.
            appendVerdict(key, ProbeStep.attempt(major, versionSpec, ProbeStep.Outcome.NOT_CHECKED,
                    "%s → %s (pre-release, not offered)".formatted(versionSpec, resolvedAncestor)));
            return new ProbeAttempt(outcome, CleanCheck.STILL_AFFECTED);
        }

        CleanCheck clean = outcome.resolved() && outcome.targetVersion() != null
                ? checkClean(outcome.targetVersion(), evaluator)
                : CleanCheck.UNKNOWN;
        appendVerdict(key, verdictFor(major, versionSpec, outcome, ancestor, clean));
        return new ProbeAttempt(outcome, clean);
    }

    private static boolean isPreRelease(String version) {
        return version != null && version.contains("-");
    }

    private ProbeContext buildContext(MavenToolSettings mavenSettings, String workspacePath) {
        String isolatedRepository = defaultProbeRepository();
        EffectivePomFragments lifted = null;
        if (workspacePath != null && !workspacePath.isBlank()) {
            lifted = effectivePoms.forWorkspace(
                    workspacePath, mavenSettings.executablePath(), isolatedRepository, PROBE_TIMEOUT,
                    mavenSettings.profiles(), mavenSettings.effectivePomGoal())
                    .orElse(null);
        }
        return new ProbeContext(mavenSettings.executablePath(), isolatedRepository, lifted, PROBE_TIMEOUT,
                mavenSettings.profiles(), mavenSettings.dependencyTreeGoal());
    }

    /**
     * The search cannot proceed, and the reason is the reader's answer rather than an error to
     * log. Unchecked and caught in {@link #runProbe}, so the failure surfaces as an
     * "unavailable, here is why" remedy in the panel — the same shape every other probe
     * failure already takes.
     */
    private static final class ProbeUnavailable extends RuntimeException {
        ProbeUnavailable(String note) {
            super(note);
        }
    }

    private enum CleanCheck { CLEAN, STILL_AFFECTED, UNKNOWN }

    private CleanCheck checkClean(String version, UpgradeAdviceService.TargetEvaluator evaluator) {
        Optional<List<AdvisoryHit>> hits = evaluator.evaluate(version);
        if (hits.isEmpty()) {
            return CleanCheck.UNKNOWN;
        }
        return hits.get().isEmpty() ? CleanCheck.CLEAN : CleanCheck.STILL_AFFECTED;
    }

    private record ProbeAttempt(ProbeOutcome outcome, CleanCheck clean) {
        boolean isCleanResolution() {
            return outcome.resolved() && clean == CleanCheck.CLEAN;
        }
    }

    /** Shared across the whole run — ranking every major and the combination step draw from
     *  the same budget, since it is what "the run budget, not the probe count" means. */
    private static final class SearchBudget {
        private final Instant deadline;
        private int remaining;

        /**
         * Set when the user stops the run. Deliberately expressed as exhaustion rather than as
         * its own concept: every level of the search already consults {@link #exhausted()} and
         * already reports what it did not reach — a major it never got to is {@code
         * probed: false}, one it walked partway is {@code higherReleasesUnchecked}. A stopped
         * run is a cut-short run, so it inherits all of that honesty, and {@code continueRun}
         * resumes it with no new resume logic at all.
         */
        private volatile boolean cancelled;

        SearchBudget(Instant deadline, int probes) {
            this.deadline = deadline;
            this.remaining = probes;
        }

        boolean exhausted() {
            return cancelled || remaining <= 0 || Instant.now().isAfter(deadline);
        }

        void cancel() {
            cancelled = true;
        }

        boolean cancelled() {
            return cancelled;
        }

        void spend() {
            remaining--;
        }
    }

    private Remedy unavailable(String note) {
        return new Remedy(RemedyKind.BUMP_ANCESTOR, false, null, null, List.of(), List.of(), note);
    }

    private Remedy remedyForCombination(Map<MavenArtifact, String> resolvedVersions, List<AdvisoryFix> advisories) {
        List<String> clears = advisories.stream().map(AdvisoryFix::osvId).toList();
        String snippet = resolvedVersions.entrySet().stream()
                .map(entry -> dependencySnippet(entry.getKey(), entry.getValue()))
                .collect(Collectors.joining("\n"));
        String names = resolvedVersions.entrySet().stream()
                .map(entry -> "%s:%s@%s".formatted(entry.getKey().groupId(), entry.getKey().artifactId(), entry.getValue()))
                .collect(Collectors.joining(", "));
        String note = "No single ancestor resolves this alone. Verified against your own Maven: moving "
                + "all of the following together brings a version with nothing known against it: " + names;
        return new Remedy(RemedyKind.BUMP_ANCESTOR, true, names, snippet, clears, List.of(), note);
    }

    private String dependencySnippet(MavenArtifact artifact, String version) {
        return """
                <dependency>
                  <groupId>%s</groupId>
                  <artifactId>%s</artifactId>
                  <version>%s</version>
                </dependency>""".formatted(artifact.groupId(), artifact.artifactId(), version);
    }

    private String failureNote(ProbeOutcome outcome) {
        String reason = switch (outcome.failureReason()) {
            case NOT_FOUND -> "Not found in any configured repository.";
            case AUTHENTICATION -> "Authentication failed against a configured repository.";
            case NOT_RUNNABLE -> "mvn could not be started at the configured path.";
            case PLUGIN_UNAVAILABLE -> ("Maven ran, but could not obtain the plugin the probe needs. "
                    + "The probe resolves into its own repository (%s), never your ~/.m2, so on a "
                    + "machine that cannot reach a repository it has no way to obtain that plugin. "
                    + "The full Maven output is in sbomscope.log.").formatted(defaultProbeRepository());
            // Says nothing about the artifact, so it must not read as though it did. The most
            // common cause here is TLS-inspecting security software, whose fix is an environment
            // variable and not a JVM flag — the probe's mvn is a child process, and children
            // inherit the environment, never the parent's -D options.
            case REPOSITORY_UNREACHABLE -> "Maven could not complete the download — the repository's "
                    + "certificate could not be verified, or the repository could not be reached. "
                    + "This says nothing about whether the artifact exists. If your machine inspects "
                    + "HTTPS, set MAVEN_OPTS=-Djavax.net.ssl.trustStoreType=Windows-ROOT in the "
                    + "environment SBOMscope is started from — a -D flag on SBOMscope's own JVM does "
                    + "not reach the mvn it runs. The full Maven output is in sbomscope.log.";
            case TIMEOUT -> "mvn did not finish within the probe timeout.";
            case OTHER -> "The probe failed.";
        };
        return "%s %s".formatted(reason, outcome.detail() == null ? "" : outcome.detail());
    }

    private ProbeStep verdictForCalibration(ProbeOutcome outcome, StoredComponent component) {
        if (!outcome.resolved()) {
            return ProbeStep.calibration(ProbeStep.Outcome.FAILED,
                    "calibration → failed: %s".formatted(outcome.detail()));
        }
        return ProbeStep.calibration(ProbeStep.Outcome.INFO,
                "calibration → target resolves to %s (SBOM reports %s)"
                        .formatted(outcome.targetVersion(), component.version()));
    }

    private ProbeStep verdictForCombination(Map<MavenArtifact, String> overrides, ProbeOutcome outcome,
                                            CleanCheck clean) {
        String spec = overrides.entrySet().stream()
                .map(entry -> entry.getKey().artifactId() + " " + entry.getValue())
                .collect(Collectors.joining(" + "));
        if (!outcome.resolved()) {
            return ProbeStep.combination(ProbeStep.Outcome.FAILED, spec,
                    "%s (combined) → failed: %s".formatted(spec, outcome.detail()));
        }
        String verdictWord = switch (clean) {
            case CLEAN -> "clean";
            case STILL_AFFECTED -> "still affected";
            case UNKNOWN -> "not checked";
        };
        return ProbeStep.combination(outcomeOf(clean), spec,
                "%s (combined) → target %s → %s".formatted(spec, outcome.targetVersion(), verdictWord));
    }

    private ProbeStep verdictFor(Long major, String versionSpec, ProbeOutcome outcome,
                                 MavenArtifact primary, CleanCheck clean) {
        if (!outcome.resolved()) {
            return ProbeStep.attempt(major, versionSpec, ProbeStep.Outcome.FAILED,
                    "%s → failed: %s".formatted(versionSpec, outcome.detail()));
        }
        String resolvedPrimary = outcome.resolvedVersions().get(primary);
        if (outcome.targetVersion() == null) {
            // Resolved, but the target is not in the tree at all — nothing was learned about it,
            // which is not the same as learning it is still affected.
            return ProbeStep.attempt(major, versionSpec, ProbeStep.Outcome.NOT_CHECKED,
                    "%s → %s (target absent from the resolved tree)".formatted(versionSpec, resolvedPrimary));
        }
        String verdictWord = switch (clean) {
            case CLEAN -> " → clean";
            case STILL_AFFECTED -> " → still affected";
            case UNKNOWN -> " → not checked";
        };
        return ProbeStep.attempt(major, versionSpec, outcomeOf(clean),
                "%s → %s → %s%s".formatted(versionSpec, resolvedPrimary, outcome.targetVersion(), verdictWord));
    }

    /** One mapping from the internal check to the reported outcome, rather than one per call site. */
    private static ProbeStep.Outcome outcomeOf(CleanCheck clean) {
        return switch (clean) {
            case CLEAN -> ProbeStep.Outcome.CLEAN;
            case STILL_AFFECTED -> ProbeStep.Outcome.AFFECTED;
            case UNKNOWN -> ProbeStep.Outcome.NOT_CHECKED;
        };
    }

    private void appendVerdict(String key, ProbeStep verdict) {
        progressByKey.compute(key, (k, current) ->
                (current == null ? BumpProgress.starting() : current).withVerdict(verdict));
        activityLog.record(ActivityLogger.Category.PROCESS, "MAVEN_PROBE", verdict.text());
    }

    private void completeWithCandidates(String key, List<BumpCandidate> candidates, Remedy remedy) {
        completeWithCandidates(key, candidates, remedy, null);
    }

    private void completeWithCandidates(String key, List<BumpCandidate> candidates, Remedy remedy, String note) {
        progressByKey.compute(key, (k, current) ->
                (current == null ? BumpProgress.starting() : current).completed(candidates, remedy, note));
    }

    private void complete(String key, Remedy remedy) {
        progressByKey.compute(key, (k, current) ->
                (current == null ? BumpProgress.starting() : current).completed(remedy));
    }

    private record MajorMinor(long major, long minor) {
        static MajorMinor parse(String version) {
            String[] parts = version == null ? new String[0] : version.split("\\.");
            return new MajorMinor(digitsOf(parts, 0), digitsOf(parts, 1));
        }

        private static long digitsOf(String[] parts, int index) {
            if (index >= parts.length) {
                return 0;
            }
            StringBuilder digits = new StringBuilder();
            for (char character : parts[index].toCharArray()) {
                if (!Character.isDigit(character)) {
                    break;
                }
                digits.append(character);
            }
            if (digits.isEmpty()) {
                return 0;
            }
            try {
                return Long.parseLong(digits.toString());
            } catch (NumberFormatException e) {
                return 0;
            }
        }
    }

    @PreDestroy
    void shutdown() {
        executor.shutdownNow();
    }
}
