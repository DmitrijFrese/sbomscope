package dev.sbomscope.reachability;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.ArrayDeque;
import java.util.Collection;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import org.springframework.stereotype.Service;

import dev.sbomscope.logging.ActivityLogger;
import dev.sbomscope.sbom.StoredComponent;
import dev.sbomscope.sbom.StoredSbom;
import dev.sbomscope.sbom.SbomService;
import dev.sbomscope.settings.SettingsService;
import dev.sbomscope.settings.WorkspaceAnalysisSettings;

/**
 * Queues one offline bytecode analysis per SBOM when the reader opens its Workspace usage tab.
 *
 * <p>The trigger is deliberately user-visible access, not a timer or a watcher. The fingerprint
 * tells us when a new build or a changed cached JAR makes the stored result stale; no workspace
 * build, Maven invocation or network request is ever made here.
 */
@Service
public class WorkspaceReachabilityService {

    private final SbomService sboms;
    private final SettingsService settings;
    private final WorkspaceInputDiscovery inputs;
    private final WorkspaceModuleMapper moduleMapper;
    private final ReachabilityWorkerInvocation workerInvocation;
    private final WorkspaceReachabilityRepository repository;
    private final ActivityLogger activityLog;
    private final ExecutorService worker = Executors.newSingleThreadExecutor(runnable -> {
        Thread thread = new Thread(runnable, "workspace-reachability");
        thread.setDaemon(true);
        return thread;
    });
    private final Set<UUID> inFlight = ConcurrentHashMap.newKeySet();
    private final Map<UUID, AnalysisTask> tasks = new ConcurrentHashMap<>();

    private static final class AnalysisTask {
        final WorkspaceAnalysisRun run;
        final String workspacePath;
        volatile Instant startedAt;
        volatile Instant finishedAt;
        volatile WorkspaceAnalysisTaskView.State state = WorkspaceAnalysisTaskView.State.QUEUED;
        volatile boolean cancelled;
        volatile Future<?> future;
        volatile ReachabilityWorkerInvocation.Running worker;
        AnalysisTask(WorkspaceAnalysisRun run, String workspacePath) { this.run = run; this.workspacePath = workspacePath; }
        WorkspaceAnalysisTaskView view() { return new WorkspaceAnalysisTaskView(run.id(), run.sbomId(), workspacePath,
                state, run.requestedAt(), startedAt, finishedAt); }
    }

    WorkspaceReachabilityService(SbomService sboms, SettingsService settings,
                                 WorkspaceInputDiscovery inputs, WorkspaceModuleMapper moduleMapper,
                                 ReachabilityWorkerInvocation workerInvocation,
                                 WorkspaceReachabilityRepository repository,
                                 ActivityLogger activityLog) {
        this.sboms = sboms;
        this.settings = settings;
        this.inputs = inputs;
        this.moduleMapper = moduleMapper;
        this.workerInvocation = workerInvocation;
        this.repository = repository;
        this.activityLog = activityLog;
    }

    @PostConstruct
    void reconcileAbandonedRuns() {
        int reconciled = repository.failAbandoned(Instant.now());
        if (reconciled > 0) {
            activityLog.record(ActivityLogger.Category.PROCESS, "WORKSPACE_REACHABILITY", "RECOVERED",
                    "%d abandoned queued/running analysis record%s".formatted(
                            reconciled, reconciled == 1 ? "" : "s"));
        }
    }

    /** Returns the latest answer and implicitly queues a fresh one if compiled inputs changed. */
    public WorkspaceComponentAnalysis inspect(UUID sbomId, String purl) {
        StoredSbom sbom = sboms.findById(sbomId).orElseThrow();
        if (sbom.workspacePath() == null || sbom.workspacePath().isBlank()) {
            return WorkspaceComponentAnalysis.notConfigured(
                    "This SBOM was imported without a workspace path, so there is no local bytecode to analyse.");
        }

        Path workspace = Path.of(sbom.workspacePath());
        WorkspaceAnalysisSettings analysisSettings = settings.workspaceAnalysisSettings();
        List<StoredComponent> components = sboms.findComponents(sbomId);
        WorkspaceAnalysisInputs discovered = inputs.discover(workspace,
                Path.of(analysisSettings.mavenLocalRepository()), components);
        List<WorkspaceModuleMapper.ModuleMapping> mappings = moduleMapper.map(
                workspace, discovered.productionOutputs(), components);
        String fingerprint = analysisFingerprint(discovered, mappings, analysisSettings);
        WorkspaceAnalysisRun latest = repository.latest(sbomId).orElse(null);
        if (!reusable(latest, fingerprint)) {
            latest = queue(sbom, discovered, mappings, components, analysisSettings, fingerprint);
        }
        return view(latest, purl);
    }

    private WorkspaceAnalysisRun queue(StoredSbom sbom, WorkspaceAnalysisInputs discovered,
                                       List<WorkspaceModuleMapper.ModuleMapping> mappings,
                                       List<StoredComponent> components,
                                       WorkspaceAnalysisSettings analysisSettings, String fingerprint) {
        // A second component tab can be opened while the first request is doing its discovery.
        // Re-read under the per-SBOM in-flight gate so there is still one durable run and one worker.
        synchronized (inFlight) {
            WorkspaceAnalysisRun latest = repository.latest(sbom.id()).orElse(null);
            if (reusable(latest, fingerprint)) {
                return latest;
            }
            WorkspaceAnalysisRun run = new WorkspaceAnalysisRun(UUID.randomUUID(), sbom.id(),
                    fingerprint, WorkspaceAnalysisRun.Status.QUEUED, null, null,
                    discovered.blockers().stream().map(Enum::name).sorted().toList(), null,
                    Instant.now(), null, null);
            repository.insertQueued(run);
            inFlight.add(sbom.id());
            AnalysisTask task = new AnalysisTask(run, sbom.workspacePath());
            tasks.put(run.id(), task);
            task.future = worker.submit(() -> analyse(
                    task, discovered, mappings, components, analysisSettings));
            activityLog.record(ActivityLogger.Category.PROCESS, "WORKSPACE_REACHABILITY", "QUEUED",
                    sbom.filename());
            return run;
        }
    }

    public List<WorkspaceAnalysisTaskView> tasks() {
        return tasks.values().stream().map(AnalysisTask::view)
                .sorted(Comparator.comparing(WorkspaceAnalysisTaskView::submittedAt)).toList();
    }

    public boolean cancel(UUID id) {
        AnalysisTask task = tasks.get(id);
        if (task == null) return false;
        synchronized (task) {
            if (task.finishedAt != null || isTerminal(task.state)) return false;
            task.cancelled = true;
            ReachabilityWorkerInvocation.Running running = task.worker;
            if (running != null) running.stop();
            Future<?> future = task.future;
            if (future != null) future.cancel(false);
            finishStopped(task);
        }
        activityLog.record(ActivityLogger.Category.PROCESS, "WORKSPACE_REACHABILITY", "STOPPED", task.workspacePath);
        return true;
    }

    private void analyse(AnalysisTask task, WorkspaceAnalysisInputs discovered,
                         List<WorkspaceModuleMapper.ModuleMapping> mappings,
                         List<StoredComponent> components,
                         WorkspaceAnalysisSettings analysisSettings) {
        WorkspaceAnalysisRun run = task.run;
        String workspacePath = task.workspacePath;
        synchronized (task) {
            if (task.cancelled) {
                finishStopped(task);
                return;
            }
            task.startedAt = Instant.now();
            if (!repository.markRunning(run.id(), task.startedAt)) {
                task.cancelled = true;
                finishStopped(task);
                return;
            }
            task.state = WorkspaceAnalysisTaskView.State.RUNNING;
        }
        activityLog.record(ActivityLogger.Category.PROCESS, "WORKSPACE_REACHABILITY", "STARTED",
                workspacePath);
        try {
            List<WorkspaceReachabilityEvidence> evidence = new ArrayList<>();
            if (!discovered.hasProductionOutputs()) {
                evidence.addAll(evaluate(discovered, components));
            } else {
                for (WorkspaceModuleMapper.ModuleMapping mapping : mappings) {
                    if (task.cancelled) throw new WorkerStoppedException();
                    if (!mapping.mapped()) {
                        evidence.addAll(unmappedEvidence(mapping, components));
                        continue;
                    }
                    List<StoredComponent> closure = dependencyClosure(
                            mapping.component(), components, sboms.findEdges(run.sbomId()));
                    WorkspaceAnalysisInputs moduleInputs = inputs.discoverModule(
                            mapping.output(), Path.of(analysisSettings.mavenLocalRepository()), closure);
                    Set<String> closureRefs = closure.stream().map(StoredComponent::bomRef)
                            .collect(java.util.stream.Collectors.toSet());
                    List<Path> supportingOutputs = mappings.stream()
                            .filter(WorkspaceModuleMapper.ModuleMapping::mapped)
                            .filter(candidate -> !candidate.equals(mapping))
                            .filter(candidate -> closureRefs.contains(candidate.component().bomRef()))
                            .map(WorkspaceModuleMapper.ModuleMapping::output)
                            .sorted().toList();
                    moduleInputs = new WorkspaceAnalysisInputs(
                            moduleInputs.productionOutputs(), supportingOutputs,
                            moduleInputs.dependencyArtifacts(), moduleInputs.missingInputs(),
                            moduleInputs.blockers(), moduleInputs.fingerprint());
                    ReachabilityWorkerResult result = analyseInWorker(moduleInputs, task, analysisSettings);
                    evidence.addAll(evaluateModule(mapping, moduleInputs, closure, components, result));
                }
            }
            synchronized (task) {
                if (task.cancelled) throw new WorkerStoppedException();
                repository.complete(run.id(), WalaReachabilityEngine.ENGINE, WalaReachabilityEngine.ALGORITHM,
                        Instant.now(), storedModules(mappings), evidence);
                task.state = WorkspaceAnalysisTaskView.State.COMPLETED;
                task.finishedAt = Instant.now();
            }
            activityLog.record(ActivityLogger.Category.PROCESS, "WORKSPACE_REACHABILITY", "SUCCESS",
                    "%s (%d component/module answers)".formatted(workspacePath, evidence.size()));
        } catch (WorkerStoppedException e) {
            finishStopped(task);
        } catch (Exception e) {
            synchronized (task) {
                if (task.cancelled) {
                    finishStopped(task);
                    return;
                }
                repository.fail(run.id(), conciseMessage(e), Instant.now());
                task.state = WorkspaceAnalysisTaskView.State.FAILED;
                task.finishedAt = Instant.now();
            }
            activityLog.record(ActivityLogger.Category.PROCESS, "WORKSPACE_REACHABILITY", "FAILURE",
                    workspacePath + ": " + conciseMessage(e));
        } finally {
            if (task.finishedAt == null) task.finishedAt = Instant.now();
            inFlight.remove(run.sbomId());
        }
    }

    private ReachabilityWorkerResult analyseInWorker(WorkspaceAnalysisInputs discovered, AnalysisTask task,
                                                       WorkspaceAnalysisSettings analysisSettings) throws Exception {
        if (task.cancelled) throw new WorkerStoppedException();
        ReachabilityWorkerInvocation.Running running = workerInvocation.start(
                discovered, analysisSettings.maxHeapMegabytes());
        task.worker = running;
        try {
            if (task.cancelled) {
                running.stop();
                throw new WorkerStoppedException();
            }
            int maxRunMinutes = analysisSettings.maxRunMinutes();
            if (!running.await(java.time.Duration.ofMinutes(maxRunMinutes))) {
                running.stop();
                throw new ReachabilityAnalysisException(
                        "Workspace call-graph analysis exceeded its %d-minute limit.".formatted(maxRunMinutes), null);
            }
            if (task.cancelled) throw new WorkerStoppedException();
            if (running.process().exitValue() != 0) {
                throw new ReachabilityAnalysisException("Workspace call-graph worker failed: "
                        + workerInvocation.failureMessage(running), null);
            }
            return workerInvocation.read(running);
        } finally {
            task.worker = null;
            workerInvocation.cleanUp(running);
        }
    }

    private void finishStopped(AnalysisTask task) {
        synchronized (task) {
            if (task.finishedAt != null) return;
            task.state = WorkspaceAnalysisTaskView.State.STOPPED;
            task.finishedAt = Instant.now();
            repository.stop(task.run.id(), task.finishedAt);
            inFlight.remove(task.run.sbomId());
        }
    }

    private static final class WorkerStoppedException extends Exception {}

    private boolean isTerminal(WorkspaceAnalysisTaskView.State state) {
        return state == WorkspaceAnalysisTaskView.State.COMPLETED
                || state == WorkspaceAnalysisTaskView.State.STOPPED
                || state == WorkspaceAnalysisTaskView.State.FAILED;
    }

    private List<WorkspaceReachabilityEvidence> evaluate(WorkspaceAnalysisInputs discovered,
                                                          List<StoredComponent> components) {
        return unavailableEvidence(discovered, components);
    }

    private List<WorkspaceReachabilityEvidence> evaluateModule(
            WorkspaceModuleMapper.ModuleMapping mapping,
            WorkspaceAnalysisInputs moduleInputs,
            List<StoredComponent> closure,
            List<StoredComponent> allComponents,
            ReachabilityWorkerResult workerResult) {
        Set<String> closurePurls = closure.stream().map(StoredComponent::purl)
                .filter(java.util.Objects::nonNull).collect(java.util.stream.Collectors.toSet());
        Map<String, ReachabilityWorkerResult.ComponentCoverage> coverageByPurl = workerResult.components().stream()
                .collect(java.util.stream.Collectors.toMap(
                        ReachabilityWorkerResult.ComponentCoverage::purl, item -> item, (left, right) -> left));
        List<WorkspaceReachabilityEvidence> result = new ArrayList<>();
        for (StoredComponent component : externalMavenComponents(allComponents)) {
            if (!closurePurls.contains(component.purl())) {
                result.add(new WorkspaceReachabilityEvidence(component.purl(), mapping.label(),
                        WorkspaceReachabilityEvidence.Status.NO_CALL_PATH, List.of(), 0, 0, 0,
                        "This component is not in the mapped module's SBOM dependency closure."));
                continue;
            }
            ReachabilityWorkerResult.ComponentCoverage coverage = coverageByPurl.get(component.purl());
            if (coverage == null) {
                result.add(new WorkspaceReachabilityEvidence(component.purl(), mapping.label(),
                        WorkspaceReachabilityEvidence.Status.UNAVAILABLE, List.of(), 0, 0, 0,
                        "The exact dependency JAR was not available from the configured read-only Maven cache."));
            } else if (coverageStatus(coverage, moduleInputs)
                    == WorkspaceReachabilityEvidence.Status.NEEDS_REVIEW
                    && coverage.ambiguousClassOwnership()) {
                result.add(new WorkspaceReachabilityEvidence(component.purl(), mapping.label(),
                        WorkspaceReachabilityEvidence.Status.NEEDS_REVIEW, coverage.displayPaths(),
                        coverage.reachableMethods(), coverage.directMethods(), coverage.displayPaths().size(),
                        "Two dependency JARs in this module provide one or more of the same classes, so WALA cannot attribute the observed bytecode to this exact component version."));
            } else if (coverageStatus(coverage, moduleInputs) == WorkspaceReachabilityEvidence.Status.REACHABLE) {
                result.add(reachableEvidence(mapping.label(), coverage));
            } else if (coverageStatus(coverage, moduleInputs) == WorkspaceReachabilityEvidence.Status.NO_CALL_PATH) {
                result.add(new WorkspaceReachabilityEvidence(component.purl(), mapping.label(),
                        WorkspaceReachabilityEvidence.Status.NO_CALL_PATH, List.of(), 0, 0, 0,
                        "No bytecode call path was found in this module's compiled production output."));
            } else {
                result.add(new WorkspaceReachabilityEvidence(component.purl(), mapping.label(),
                        WorkspaceReachabilityEvidence.Status.NEEDS_REVIEW, List.of(), 0, 0, 0,
                        negativeBlockerDetail(moduleInputs)));
            }
        }
        return result;
    }

    static WorkspaceReachabilityEvidence.Status coverageStatus(
            ReachabilityWorkerResult.ComponentCoverage coverage, WorkspaceAnalysisInputs inputs) {
        if (coverage.ambiguousClassOwnership()) return WorkspaceReachabilityEvidence.Status.NEEDS_REVIEW;
        if (coverage.reachableMethods() > 0) return WorkspaceReachabilityEvidence.Status.REACHABLE;
        return inputs.completeForNegativeResult()
                ? WorkspaceReachabilityEvidence.Status.NO_CALL_PATH
                : WorkspaceReachabilityEvidence.Status.NEEDS_REVIEW;
    }

    private WorkspaceReachabilityEvidence reachableEvidence(
            String module, ReachabilityWorkerResult.ComponentCoverage coverage) {
        List<List<String>> paths = coverage.displayPaths();
        String detail = "WALA observed %d compiled production method%s that can reach this library"
                .formatted(coverage.reachableMethods(), coverage.reachableMethods() == 1 ? "" : "s")
                + (coverage.directMethods() == 0 ? "."
                : "; %d %s directly into it."
                        .formatted(coverage.directMethods(), coverage.directMethods() == 1
                                ? "call crosses" : "calls cross"));
        if (paths.isEmpty()) {
            detail += " Coverage is positive, but no representative path fit within the bounded display search.";
        } else if (coverage.reachableMethods() > paths.size() || coverage.representativePathsLimited()) {
            detail += " Showing up to %d shortest representative path%s; coverage is computed independently."
                    .formatted(paths.size(), paths.size() == 1 ? "" : "s");
        }
        return new WorkspaceReachabilityEvidence(coverage.purl(), module,
                WorkspaceReachabilityEvidence.Status.REACHABLE, paths,
                coverage.reachableMethods(), coverage.directMethods(), paths.size(), detail);
    }

    private List<WorkspaceReachabilityEvidence> unmappedEvidence(
            WorkspaceModuleMapper.ModuleMapping mapping, List<StoredComponent> components) {
        return externalMavenComponents(components).stream()
                .map(component -> new WorkspaceReachabilityEvidence(component.purl(), mapping.label(),
                        WorkspaceReachabilityEvidence.Status.NEEDS_REVIEW, List.of(), 0, 0, 0, mapping.reason()))
                .toList();
    }

    private List<WorkspaceReachabilityEvidence> unavailableEvidence(WorkspaceAnalysisInputs discovered,
                                                                      List<StoredComponent> components) {
        String detail = discovered.missingInputs().isEmpty()
                ? "No compiled production output is available. Run the workspace's normal build first."
                : String.join(" ", discovered.missingInputs());
        return externalMavenComponents(components).stream()
                .map(component -> new WorkspaceReachabilityEvidence(component.purl(), null,
                        WorkspaceReachabilityEvidence.Status.UNAVAILABLE, List.of(), 0, 0, 0, detail))
                .toList();
    }

    private List<WorkspaceAnalysisModule> storedModules(List<WorkspaceModuleMapper.ModuleMapping> mappings) {
        return mappings.stream().map(mapping -> new WorkspaceAnalysisModule(
                mapping.label(), mapping.output().toString(),
                mapping.mapped() ? mapping.component().bomRef() : null,
                mapping.mapped() ? WorkspaceAnalysisModule.MappingStatus.MAPPED
                        : WorkspaceAnalysisModule.MappingStatus.UNMAPPED,
                mapping.reason())).toList();
    }

    private List<StoredComponent> externalMavenComponents(List<StoredComponent> components) {
        return new ArrayList<>(components.stream()
                .filter(component -> component.purl() != null && component.purl().startsWith("pkg:maven/"))
                .filter(component -> component.scope() != dev.sbomscope.sbom.DependencyScope.APPLICATION)
                .filter(component -> component.type() == null || !component.type().equalsIgnoreCase("pom"))
                .collect(java.util.stream.Collectors.toMap(
                        StoredComponent::purl, component -> component, (left, right) -> left,
                        java.util.LinkedHashMap::new)).values());
    }

    static List<StoredComponent> dependencyClosure(
            StoredComponent root, List<StoredComponent> components,
            List<dev.sbomscope.sbom.ParsedSbom.DependencyEdge> edges) {
        Map<String, StoredComponent> byRef = components.stream()
                .collect(java.util.stream.Collectors.toMap(
                        StoredComponent::bomRef, component -> component, (left, right) -> left));
        Map<String, List<String>> children = new HashMap<>();
        edges.forEach(edge -> children.computeIfAbsent(edge.fromBomRef(), unused -> new ArrayList<>())
                .add(edge.toBomRef()));
        Set<String> visited = new LinkedHashSet<>();
        Deque<String> queue = new ArrayDeque<>();
        queue.add(root.bomRef());
        visited.add(root.bomRef());
        while (!queue.isEmpty()) {
            for (String child : children.getOrDefault(queue.removeFirst(), List.of())) {
                if (visited.add(child)) queue.addLast(child);
            }
        }
        return visited.stream().map(byRef::get).filter(java.util.Objects::nonNull).toList();
    }

    private boolean reusable(WorkspaceAnalysisRun run, String fingerprint) {
        return reusable(run, fingerprint, run != null && tasks.containsKey(run.id()));
    }

    static boolean reusable(WorkspaceAnalysisRun run, String fingerprint, boolean activeLocally) {
        if (run == null || !fingerprint.equals(run.inputFingerprint())) return false;
        if (run.status() == WorkspaceAnalysisRun.Status.COMPLETED) return true;
        return activeLocally && (run.status() == WorkspaceAnalysisRun.Status.QUEUED
                || run.status() == WorkspaceAnalysisRun.Status.RUNNING);
    }

    private String analysisFingerprint(WorkspaceAnalysisInputs discovered,
                                       List<WorkspaceModuleMapper.ModuleMapping> mappings,
                                       WorkspaceAnalysisSettings analysisSettings) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            updateFingerprint(digest, "engine=" + WalaReachabilityEngine.ENGINE);
            updateFingerprint(digest, "algorithm=" + WalaReachabilityEngine.ALGORITHM);
            updateFingerprint(digest, "inputs=" + discovered.fingerprint());
            updateFingerprint(digest, "repository=" + analysisSettings.mavenLocalRepository());
            updateFingerprint(digest, "minutes=" + analysisSettings.maxRunMinutes());
            updateFingerprint(digest, "heap=" + analysisSettings.maxHeapMegabytes());
            mappings.stream().sorted(Comparator.comparing(WorkspaceModuleMapper.ModuleMapping::label))
                    .forEach(mapping -> updateFingerprint(digest, String.join("|",
                            mapping.label(), mapping.output().toString(),
                            mapping.mapped() ? mapping.component().bomRef() : "unmapped",
                            mapping.reason() == null ? "" : mapping.reason())));
            return HexFormat.of().formatHex(digest.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 must be available in every supported Java runtime", e);
        }
    }

    private void updateFingerprint(MessageDigest digest, String value) {
        digest.update(value.getBytes(StandardCharsets.UTF_8));
        digest.update((byte) 0);
    }

    private String negativeBlockerDetail(WorkspaceAnalysisInputs discovered) {
        Collection<CompletenessBlocker> blockers = discovered.blockers();
        if (blockers.contains(CompletenessBlocker.SPRING_OR_AOP_PRESENT)
                || blockers.contains(CompletenessBlocker.REFLECTION_REFERENCED)) {
            return "A Spring/AOP/proxy or reflection marker is present. WALA-only negative evidence needs review."
                    + " A positive bytecode path remains actionable.";
        }
        return discovered.missingInputs().isEmpty()
                ? "The available inputs cannot support a complete negative result."
                : String.join(" ", discovered.missingInputs());
    }

    private WorkspaceComponentAnalysis view(WorkspaceAnalysisRun run, String purl) {
        WorkspaceComponentAnalysis.State state = WorkspaceComponentAnalysis.State.valueOf(run.status().name());
        String message = switch (run.status()) {
            case QUEUED -> "Workspace analysis is queued.";
            case RUNNING -> "Workspace analysis is running locally.";
            case COMPLETED -> "Workspace analysis is current for the compiled inputs.";
            case STOPPED -> "Workspace analysis was stopped.";
            case FAILED -> run.errorMessage();
        };
        List<WorkspaceReachabilityEvidence> evidence = run.status() == WorkspaceAnalysisRun.Status.COMPLETED
                ? repository.evidence(run.id(), purl) : List.of();
        return new WorkspaceComponentAnalysis(state, run.requestedAt(), run.finishedAt(), message, evidence);
    }

    private String conciseMessage(Exception exception) {
        String message = exception.getMessage();
        return message == null || message.isBlank() ? exception.getClass().getSimpleName() : message;
    }

    @PreDestroy
    void stop() {
        tasks.values().forEach(task -> {
            if (!isTerminal(task.state)) cancel(task.run.id());
        });
        worker.shutdownNow();
    }
}
