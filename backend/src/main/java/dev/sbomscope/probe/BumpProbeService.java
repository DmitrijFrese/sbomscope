package dev.sbomscope.probe;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
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
        executor.submit(() -> runProbe(key, request, mavenSettings));
        return progressByKey.get(key);
    }

    private String cacheKeyFor(ComponentGraph graph, StoredComponent component) {
        if (graph.reachedFrom().isEmpty()) {
            return null;
        }
        return graph.reachedFrom().getFirst().module().bomRef() + "->" + component.coordinates();
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

    // --- the probe itself ------------------------------------------------------------------

    private void runProbe(String key, BumpRequest request, MavenToolSettings mavenSettings) {
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

            List<ModuleDependency> moduleDeps = request.moduleDirectDependencies().stream()
                    .filter(node -> node.purl() != null && node.purl().startsWith("pkg:maven/"))
                    .map(node -> new ModuleDependency(MavenArtifact.fromCoordinates(node.coordinates()), node.version()))
                    .toList();

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

            // Step 1 — rank every major line for the primary declaring ancestor. Not "first
            // success wins": a later major being affected proves nothing about an earlier one,
            // and Tier 1's own "candidates, not a recommendation" shape applies here too.
            GraphNode primary = ancestorNodes.getFirst();
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
                                + "candidates show what each still carries.").formatted(names)));
                return;
            }

            completeWithCandidates(key, candidates, null);

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
        }
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
        ProbeAttempt feasibility = probeOne(moduleDeps, ancestor, "[" + currentVersion + ",)", target,
                context, evaluator, key, budget);
        if (!feasibility.outcome().resolved()) {
            // Not even a ranked list can be built without knowing what exists.
            return List.of();
        }
        String globalLatest = feasibility.outcome().resolvedVersions().get(ancestor);
        List<String> knownVersions = resolver.knownVersions(ancestor, context);

        MajorMinor current = MajorMinor.parse(currentVersion);
        MajorMinor latest = MajorMinor.parse(globalLatest);

        List<BumpCandidate> candidates = new ArrayList<>();
        for (long major = current.major(); major <= latest.major(); major++) {
            String label = labelFor(major, current.major(), latest.major());
            if (budget.exhausted()) {
                candidates.add(BumpCandidate.notProbed(label, coordinates, major));
                continue;
            }
            long startAfterMinor = major == current.major() ? current.minor() - 1 : -1;
            candidates.add(rankMajor(key, moduleDeps, ancestor, coordinates, target, evaluator, context, budget,
                    major, startAfterMinor, knownVersions, label));
        }
        return candidates;
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
     * <p>When nothing in the major is clean, the last release actually probed — which, walked
     * ascending to the end, is the major's own highest known release — becomes the row's
     * reported version, carrying whatever it still carries.
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

        for (long minor : minors) {
            if (budget.exhausted()) {
                break;
            }
            String version = highestWithin(knownVersions, major, minor);
            if (version == null) {
                continue;
            }
            ProbeAttempt attempt = probeOne(moduleDeps, ancestor, "[" + version + "]", target, context, evaluator, key, budget);
            lastVersion = version;
            lastAttempt = attempt;
            if (attempt.isCleanResolution()) {
                break; // ascending order guarantees this is the earliest clean line
            }
        }

        if (lastAttempt == null) {
            return BumpCandidate.notProbed(label, ancestorCoordinates, major);
        }

        String targetVersion = lastAttempt.outcome().resolved() ? lastAttempt.outcome().targetVersion() : null;
        List<AdvisoryHit> hits = targetVersion == null ? List.of() : evaluator.evaluate(targetVersion).orElse(List.of());
        boolean clean = hits.isEmpty();
        boolean clearsCriticalAndHigh = hits.stream().noneMatch(BumpProbeService::isCriticalOrHigh);

        return new BumpCandidate(label, ancestorCoordinates, major, lastVersion, targetVersion, true,
                clean, clearsCriticalAndHigh, hits, dependencySnippet(ancestor, lastVersion));
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

    private ProbeAttempt probeOne(List<ModuleDependency> moduleDeps, MavenArtifact ancestor, String versionSpec,
                                   MavenArtifact target, ProbeContext context,
                                   UpgradeAdviceService.TargetEvaluator evaluator, String key, SearchBudget budget) {
        ProbeOutcome outcome = resolver.resolve(moduleDeps, Map.of(ancestor, versionSpec), target, context);
        budget.spend();

        String resolvedAncestor = outcome.resolvedVersions().get(ancestor);
        if (outcome.resolved() && isPreRelease(resolvedAncestor)) {
            // A right-exclusive upper bound such as [3.0.0,4.0.0) still admits 4.0.0's own
            // milestones and release candidates — found live: Maven sorts 4.0.0-RC2 below the
            // final 4.0.0, so it satisfies "< 4.0.0" and can win the range. Never offered as an
            // answer regardless of what the archive says about the target: a confident
            // milestone recommendation is worse than continuing the search past it.
            appendVerdict(key, "%s → %s (pre-release, not offered)".formatted(versionSpec, resolvedAncestor));
            return new ProbeAttempt(outcome, CleanCheck.STILL_AFFECTED);
        }

        CleanCheck clean = outcome.resolved() && outcome.targetVersion() != null
                ? checkClean(outcome.targetVersion(), evaluator)
                : CleanCheck.UNKNOWN;
        appendVerdict(key, verdictFor(versionSpec, outcome, ancestor, clean));
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
                    mavenSettings.profiles())
                    .orElse(null);
        }
        return new ProbeContext(mavenSettings.executablePath(), isolatedRepository, lifted, PROBE_TIMEOUT,
                mavenSettings.profiles());
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

        SearchBudget(Instant deadline, int probes) {
            this.deadline = deadline;
            this.remaining = probes;
        }

        boolean exhausted() {
            return remaining <= 0 || Instant.now().isAfter(deadline);
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
            case TIMEOUT -> "mvn did not finish within the probe timeout.";
            case OTHER -> "The probe failed.";
        };
        return "%s %s".formatted(reason, outcome.detail() == null ? "" : outcome.detail());
    }

    private String verdictForCalibration(ProbeOutcome outcome, StoredComponent component) {
        if (!outcome.resolved()) {
            return "calibration → failed: %s".formatted(outcome.detail());
        }
        return "calibration → target resolves to %s (SBOM reports %s)"
                .formatted(outcome.targetVersion(), component.version());
    }

    private String verdictForCombination(Map<MavenArtifact, String> overrides, ProbeOutcome outcome, CleanCheck clean) {
        String spec = overrides.entrySet().stream()
                .map(entry -> entry.getKey().artifactId() + " " + entry.getValue())
                .collect(Collectors.joining(" + "));
        if (!outcome.resolved()) {
            return "%s (combined) → failed: %s".formatted(spec, outcome.detail());
        }
        String verdictWord = switch (clean) {
            case CLEAN -> "clean";
            case STILL_AFFECTED -> "still affected";
            case UNKNOWN -> "not checked";
        };
        return "%s (combined) → target %s → %s".formatted(spec, outcome.targetVersion(), verdictWord);
    }

    private String verdictFor(String versionSpec, ProbeOutcome outcome, MavenArtifact primary, CleanCheck clean) {
        if (!outcome.resolved()) {
            return "%s → failed: %s".formatted(versionSpec, outcome.detail());
        }
        String resolvedPrimary = outcome.resolvedVersions().get(primary);
        if (outcome.targetVersion() == null) {
            return "%s → %s (target absent from the resolved tree)".formatted(versionSpec, resolvedPrimary);
        }
        String verdictWord = switch (clean) {
            case CLEAN -> " → clean";
            case STILL_AFFECTED -> " → still affected";
            case UNKNOWN -> " → not checked";
        };
        return "%s → %s → %s%s".formatted(versionSpec, resolvedPrimary, outcome.targetVersion(), verdictWord);
    }

    private void appendVerdict(String key, String verdict) {
        progressByKey.compute(key, (k, current) ->
                (current == null ? BumpProgress.starting() : current).withVerdict(verdict));
        activityLog.record(ActivityLogger.Category.PROCESS, "MAVEN_PROBE", verdict);
    }

    private void completeWithCandidates(String key, List<BumpCandidate> candidates, Remedy remedy) {
        progressByKey.compute(key, (k, current) ->
                (current == null ? BumpProgress.starting() : current).completed(candidates, remedy));
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
