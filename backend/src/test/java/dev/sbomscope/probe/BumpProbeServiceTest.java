package dev.sbomscope.probe;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import org.junit.jupiter.api.Test;

import dev.sbomscope.logging.ActivityLogger;
import dev.sbomscope.sbom.ComponentGraph;
import dev.sbomscope.sbom.DependencyScope;
import dev.sbomscope.sbom.GraphNode;
import dev.sbomscope.sbom.StoredComponent;
import dev.sbomscope.scanner.OsvArchiveMatcher;
import dev.sbomscope.scanner.UpgradeAdvice.AdvisoryFix;
import dev.sbomscope.scanner.UpgradeAdviceService;
import dev.sbomscope.settings.MavenToolSettings;

import tools.jackson.databind.ObjectMapper;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Exercises the whole-module probe and its hierarchical search against a fake
 * {@link DependencyResolver}, so none of it needs a real {@code mvn} on the machine running
 * the tests.
 */
class BumpProbeServiceTest {

    private static final MavenToolSettings MAVEN_SETTINGS = new MavenToolSettings(
            true, "/usr/bin/mvn", MavenToolSettings.DEFAULT_MAX_PROBES, MavenToolSettings.DEFAULT_RUN_BUDGET_MINUTES,
            null, MavenToolSettings.DEFAULT_DEPENDENCY_PLUGIN_VERSION,
            MavenToolSettings.DEFAULT_HELP_PLUGIN_VERSION);
    private static final MavenArtifact TARGET = new MavenArtifact("com.example", "target-lib");

    private BumpProbeService service(DependencyResolver resolver) {
        return new BumpProbeService(resolver, new EffectivePomCache(), new ActivityLogger(new ObjectMapper()));
    }

    private GraphNode node(String coordinates, String version, DependencyScope scope) {
        int colon = coordinates.indexOf(':');
        String purl = "pkg:maven/%s/%s@%s".formatted(
                coordinates.substring(0, colon), coordinates.substring(colon + 1), version);
        return new GraphNode(coordinates + "-ref", coordinates, version, purl, false, scope, false);
    }

    /** One module, one route: module -> ancestor -> target. */
    private ComponentGraph singleAncestorGraph(String ancestorCoordinates, String ancestorVersion) {
        GraphNode module = node("dev.sbomscope.vulntest:module-a", "1.0.0", DependencyScope.APPLICATION);
        GraphNode ancestor = node(ancestorCoordinates, ancestorVersion, DependencyScope.DIRECT);
        GraphNode target = node(TARGET.groupId() + ":" + TARGET.artifactId(), "3.1.4", DependencyScope.TRANSITIVE);
        List<GraphNode> route = List.of(module, ancestor, target);
        ComponentGraph.ModuleRoutes routes = new ComponentGraph.ModuleRoutes(module, List.of(route), 1, false);
        return new ComponentGraph(List.of(routes), 1, false, null);
    }

    /** One module, two routes reaching the same target through two different ancestors. */
    private ComponentGraph twoAncestorGraph(String aCoordinates, String aVersion, String bCoordinates, String bVersion) {
        GraphNode module = node("dev.sbomscope.vulntest:module-a", "1.0.0", DependencyScope.APPLICATION);
        GraphNode ancestorA = node(aCoordinates, aVersion, DependencyScope.DIRECT);
        GraphNode ancestorB = node(bCoordinates, bVersion, DependencyScope.DIRECT);
        GraphNode target = node(TARGET.groupId() + ":" + TARGET.artifactId(), "3.1.4", DependencyScope.TRANSITIVE);
        List<GraphNode> routeA = List.of(module, ancestorA, target);
        List<GraphNode> routeB = List.of(module, ancestorB, target);
        ComponentGraph.ModuleRoutes routes = new ComponentGraph.ModuleRoutes(module, List.of(routeA, routeB), 2, false);
        return new ComponentGraph(List.of(routes), 1, false, null);
    }

    private StoredComponent transitiveTarget(String version) {
        return new StoredComponent(UUID.randomUUID(), TARGET.groupId() + ":" + TARGET.artifactId() + "-ref",
                TARGET.groupId(), TARGET.artifactId(), version,
                "pkg:maven/%s/%s@%s".formatted(TARGET.groupId(), TARGET.artifactId(), version),
                "library", false, DependencyScope.TRANSITIVE);
    }

    private UpgradeAdviceService.TargetEvaluator evaluatorWhereCleanVersionsAre(String... cleanVersions) {
        List<String> clean = List.of(cleanVersions);
        return version -> Optional.of(clean.contains(version)
                ? List.of()
                : List.of(new OsvArchiveMatcher.AdvisoryHit("GHSA-test", "CVE-2024-0001", "HIGH")));
    }

    private BumpRequest request(StoredComponent target, ComponentGraph graph,
                                 UpgradeAdviceService.TargetEvaluator evaluator) {
        List<GraphNode> moduleDeps = graph.reachedFrom().isEmpty()
                ? List.of()
                : graph.reachedFrom().getFirst().routes().stream()
                        .filter(route -> route.size() >= 2)
                        .map(route -> route.get(1))
                        .distinct()
                        .toList();
        return new BumpRequest(UUID.randomUUID(), target, graph, moduleDeps,
                List.of(new AdvisoryFix("GHSA-test", "CVE-2024-0001", null, "3.1.9")), null, evaluator);
    }

    private BumpProgress awaitCompletion(BumpProbeService service, StoredComponent component, ComponentGraph graph)
            throws InterruptedException {
        long deadline = System.currentTimeMillis() + 5000;
        while (System.currentTimeMillis() < deadline) {
            BumpProgress progress = service.progress(component, graph);
            if (progress.state() == BumpProgress.State.COMPLETED || progress.state() == BumpProgress.State.FAILED) {
                return progress;
            }
            Thread.sleep(20);
        }
        throw new AssertionError("Bump probe did not complete within the test timeout");
    }

    /** Canonical key for a set of overrides, matching what the fake resolver is keyed by. */
    private String overrideKey(Map<MavenArtifact, String> overrides) {
        if (overrides.isEmpty()) {
            return "calibration";
        }
        return overrides.entrySet().stream()
                .map(entry -> entry.getKey().groupId() + ":" + entry.getKey().artifactId() + "@" + entry.getValue())
                .sorted()
                .collect(Collectors.joining("+"));
    }

    private DependencyResolver fakeResolver(Map<String, ProbeOutcome> byOverrideKey, List<String> knownVersions) {
        return new DependencyResolver() {
            @Override
            public ProbeOutcome resolve(List<ModuleDependency> moduleDependencies, Map<MavenArtifact, String> overrides,
                                         MavenArtifact target, ProbeContext context) {
                String key = overrideKey(overrides);
                ProbeOutcome outcome = byOverrideKey.get(key);
                if (outcome == null) {
                    throw new AssertionError("Unexpected overrides probed: " + key);
                }
                return outcome;
            }

            @Override
            public List<String> knownVersions(MavenArtifact declaring, ProbeContext context) {
                return knownVersions;
            }
        };
    }

    @Test
    void resolverFailureAtCalibrationFallsBackToAnUnavailableRemedy() throws InterruptedException {
        DependencyResolver resolver = fakeResolver(
                Map.of("calibration", ProbeOutcome.failed(ProbeFailureReason.NOT_FOUND, "not found anywhere")),
                List.of());
        BumpProbeService service = service(resolver);
        ComponentGraph graph = singleAncestorGraph("org.keycloak:keycloak-core", "4.8.3.Final");
        StoredComponent target = transitiveTarget("3.1.4");
        BumpRequest request = request(target, graph, evaluatorWhereCleanVersionsAre("3.1.9"));

        service.start(request, MAVEN_SETTINGS);
        BumpProgress result = awaitCompletion(service, target, graph);

        assertThat(result.remedy().available()).isFalse();
        assertThat(result.remedy().note()).contains("Not found in any configured repository");
    }

    @Test
    void calibrationMismatchRecommendsAPinInsteadOfAGuessedBump() throws InterruptedException {
        // The whole module resolves the target to 3.1.9 in isolation, but the SBOM says 3.1.4 —
        // something outside the module's own declarations overrides it, so no bump through
        // this module can be trusted.
        DependencyResolver resolver = fakeResolver(
                Map.of("calibration", ProbeOutcome.resolved(Map.of(), "3.1.9")),
                List.of());
        BumpProbeService service = service(resolver);
        ComponentGraph graph = singleAncestorGraph("org.keycloak:keycloak-core", "4.8.3.Final");
        StoredComponent target = transitiveTarget("3.1.4");
        BumpRequest request = request(target, graph, evaluatorWhereCleanVersionsAre("3.1.9"));

        service.start(request, MAVEN_SETTINGS);
        BumpProgress result = awaitCompletion(service, target, graph);

        assertThat(result.remedy().available()).isFalse();
        assertThat(result.remedy().note()).contains("does not reproduce this project's resolved version");
    }

    @Test
    void archiveNotIndexedFailsHonestlyRatherThanGuessingClean() throws InterruptedException {
        DependencyResolver resolver = fakeResolver(Map.of(), List.of());
        BumpProbeService service = service(resolver);
        ComponentGraph graph = singleAncestorGraph("org.keycloak:keycloak-core", "4.8.3.Final");
        StoredComponent target = transitiveTarget("3.1.4");
        UpgradeAdviceService.TargetEvaluator unavailable = version -> Optional.empty();
        BumpRequest request = request(target, graph, unavailable);

        service.start(request, MAVEN_SETTINGS);
        BumpProgress result = awaitCompletion(service, target, graph);

        assertThat(result.remedy().available()).isFalse();
        assertThat(result.remedy().note()).contains("not indexed");
    }

    @Test
    void notApplicableForADirectlyDeclaredComponent() {
        StoredComponent direct = new StoredComponent(UUID.randomUUID(), "ref", "com.acme", "lib", "1.0",
                "pkg:maven/com.acme/lib@1.0", "library", false, DependencyScope.DIRECT);
        BumpProbeService service = service(fakeResolver(Map.of(), List.of()));

        BumpProgress result = service.start(
                request(direct, singleAncestorGraph("com.acme:lib", "1.0"), evaluatorWhereCleanVersionsAre()),
                MAVEN_SETTINGS);

        assertThat(result.state()).isEqualTo(BumpProgress.State.FAILED);
        assertThat(result.message()).contains("Nothing pulls this in on your behalf");
    }

    @Test
    void ranksOneCandidatePerMajorLine() throws InterruptedException {
        MavenArtifact ancestor = new MavenArtifact("com.acme", "module-a");
        Map<String, ProbeOutcome> responses = Map.of(
                "calibration", ProbeOutcome.resolved(Map.of(), "3.1.4"),
                "com.acme:module-a@[4.1.5,)", ProbeOutcome.resolved(Map.of(ancestor, "5.0.0"), "3.1.9"),
                "com.acme:module-a@[4.1.9]", ProbeOutcome.resolved(Map.of(ancestor, "4.1.9"), "3.1.9"),
                "com.acme:module-a@[5.0.0]", ProbeOutcome.resolved(Map.of(ancestor, "5.0.0"), "3.1.9"));

        List<String> knownVersions = List.of("4.1.5", "4.1.9", "5.0.0");
        BumpProbeService service = service(fakeResolver(responses, knownVersions));
        ComponentGraph graph = singleAncestorGraph("com.acme:module-a", "4.1.5");
        StoredComponent target = transitiveTarget("3.1.4");
        BumpRequest request = request(target, graph, evaluatorWhereCleanVersionsAre("3.1.9"));

        service.start(request, MAVEN_SETTINGS);
        BumpProgress result = awaitCompletion(service, target, graph);

        assertThat(result.remedy()).isNull(); // no single verdict -- the ranked list is the answer
        assertThat(result.candidates()).hasSize(2);

        BumpCandidate stay = result.candidates().get(0);
        assertThat(stay.label()).isEqualTo("Stay on 4.x");
        assertThat(stay.version()).isEqualTo("4.1.9");
        assertThat(stay.clean()).isTrue();
        // The counterpart to the cut-short test below: a walk that finished is never marked.
        assertThat(stay.higherReleasesUnchecked()).isFalse();

        BumpCandidate move = result.candidates().get(1);
        assertThat(move.label()).isEqualTo("Move to 5.x (latest)");
        assertThat(move.version()).isEqualTo("5.0.0");
        assertThat(move.clean()).isTrue();
    }

    /**
     * Regression test for a bug found live: a bounded range like {@code [3.0.0,4.0.0)}
     * resolved to {@code 4.0.0-RC2} -- a pre-release of the <em>next</em> major, which Maven's
     * ordering ranks above every real 3.x release, silently skipping major 3 entirely rather
     * than merely offering a milestone as the answer. The fix replaced every tier probe past
     * feasibility with an exact probe of the actual highest known release, so this test also
     * covers the ordinary "descend past a major's own highest" case the bug was found while
     * exercising.
     */
    @Test
    void descendsIntoALaterMajorsMinorLinesForTheEarliestCleanVersion() throws InterruptedException {
        MavenArtifact ancestor = new MavenArtifact("com.acme", "module-a");
        Map<String, ProbeOutcome> responses = Map.ofEntries(
                Map.entry("calibration", ProbeOutcome.resolved(Map.of(), "3.1.4")),
                // Feasibility: something out there fixes it.
                Map.entry("com.acme:module-a@[2.1.0,)", ProbeOutcome.resolved(Map.of(ancestor, "4.1.0"), "1.0.0")),
                // Current major (2) is entirely affected, at both its known minor lines.
                Map.entry("com.acme:module-a@[2.1.9]", ProbeOutcome.resolved(Map.of(ancestor, "2.1.9"), "3.1.4")),
                Map.entry("com.acme:module-a@[2.7.18]", ProbeOutcome.resolved(Map.of(ancestor, "2.7.18"), "3.1.4")),
                // Major 3's only known release is also affected.
                Map.entry("com.acme:module-a@[3.5.0]", ProbeOutcome.resolved(Map.of(ancestor, "3.5.0"), "2.0.0")),
                // Major 4: the earlier 4.0.x line is clean, so the ascending walk should stop
                // there and never need to probe 4.1.0 at all.
                Map.entry("com.acme:module-a@[4.0.5]", ProbeOutcome.resolved(Map.of(ancestor, "4.0.5"), "1.0.0")));

        List<String> knownVersions = List.of("2.1.0", "2.1.9", "2.7.18", "3.5.0", "4.0.5", "4.1.0");
        BumpProbeService service = service(fakeResolver(responses, knownVersions));
        ComponentGraph graph = singleAncestorGraph("com.acme:module-a", "2.1.0");
        StoredComponent target = transitiveTarget("3.1.4");
        BumpRequest request = request(target, graph, evaluatorWhereCleanVersionsAre("1.0.0"));

        service.start(request, MAVEN_SETTINGS);
        BumpProgress result = awaitCompletion(service, target, graph);

        assertThat(result.candidates()).hasSize(3);
        assertThat(result.candidates().get(0)).satisfies(c -> {
            assertThat(c.label()).isEqualTo("Stay on 2.x");
            assertThat(c.version()).isEqualTo("2.7.18");
            assertThat(c.clean()).isFalse();
        });
        assertThat(result.candidates().get(1)).satisfies(c -> {
            assertThat(c.label()).isEqualTo("Move to 3.x");
            assertThat(c.version()).isEqualTo("3.5.0");
            assertThat(c.clean()).isFalse();
        });
        assertThat(result.candidates().get(2)).satisfies(c -> {
            assertThat(c.label()).isEqualTo("Move to 4.x (latest)");
            // 4.0.5, not 4.1.0 -- the earlier minor line the ascending walk should find first.
            assertThat(c.version()).isEqualTo("4.0.5");
            assertThat(c.clean()).isTrue();
        });
    }

    /**
     * The defect pass C exists to fix: the first pass treated "the global latest is still
     * affected" as proof nothing works, and stopped without checking anything in between. Found
     * live against {@code keycloak-core}, whose own latest release (26.7.0) still left
     * jackson-databind affected, while an intermediate release may not have. This test pins the
     * fix directly: feasibility comes back affected, but an intermediate major is clean and
     * must still be reported.
     */
    @Test
    void feasibilityBeingAffectedDoesNotStopTheSearchOfIntermediateMajors() throws InterruptedException {
        MavenArtifact ancestor = new MavenArtifact("com.acme", "module-a");
        Map<String, ProbeOutcome> responses = Map.of(
                "calibration", ProbeOutcome.resolved(Map.of(), "3.1.4"),
                // The global latest (major 3) is still affected -- the first pass would have
                // stopped here and reported "nothing fixes this".
                "com.acme:module-a@[1.0.0,)", ProbeOutcome.resolved(Map.of(ancestor, "3.0.0"), "3.1.4"),
                "com.acme:module-a@[1.0.0]", ProbeOutcome.resolved(Map.of(ancestor, "1.0.0"), "3.1.4"),
                // Major 2, in between, is clean.
                "com.acme:module-a@[2.0.0]", ProbeOutcome.resolved(Map.of(ancestor, "2.0.0"), "3.1.9"),
                "com.acme:module-a@[3.0.0]", ProbeOutcome.resolved(Map.of(ancestor, "3.0.0"), "3.1.4"));

        List<String> knownVersions = List.of("1.0.0", "2.0.0", "3.0.0");
        BumpProbeService service = service(fakeResolver(responses, knownVersions));
        ComponentGraph graph = singleAncestorGraph("com.acme:module-a", "1.0.0");
        StoredComponent target = transitiveTarget("3.1.4");
        BumpRequest request = request(target, graph, evaluatorWhereCleanVersionsAre("3.1.9"));

        service.start(request, MAVEN_SETTINGS);
        BumpProgress result = awaitCompletion(service, target, graph);

        assertThat(result.candidates()).hasSize(3);
        assertThat(result.candidates().get(0).clean()).isFalse(); // major 1: still affected
        assertThat(result.candidates().get(1)).satisfies(c -> {   // major 2: clean, found anyway
            assertThat(c.label()).isEqualTo("Move to 2.x");
            assertThat(c.version()).isEqualTo("2.0.0");
            assertThat(c.clean()).isTrue();
        });
        assertThat(result.candidates().get(2).clean()).isFalse(); // major 3: the latest, still affected
        assertThat(result.remedy()).isNull(); // a clean candidate exists, so no combination is needed
    }

    @Test
    void combinationOfTwoAncestorsIsOfferedWhenNeitherWorksAlone() throws InterruptedException {
        MavenArtifact ancestorA = new MavenArtifact("com.acme", "module-a");
        MavenArtifact ancestorB = new MavenArtifact("com.acme", "module-b");
        Map<String, ProbeOutcome> responses = Map.of(
                "calibration", ProbeOutcome.resolved(Map.of(), "3.1.4"),
                "com.acme:module-a@[1.0.0,)", ProbeOutcome.resolved(Map.of(ancestorA, "1.5.0"), "3.1.4"),
                "com.acme:module-a@[1.0.0]", ProbeOutcome.resolved(Map.of(ancestorA, "1.0.0"), "3.1.4"),
                "com.acme:module-a@[1.5.0]", ProbeOutcome.resolved(Map.of(ancestorA, "1.5.0"), "3.1.4"),
                "com.acme:module-b@[2.0.0,)", ProbeOutcome.resolved(Map.of(ancestorB, "2.5.0"), "3.1.4"),
                "com.acme:module-a@[1.0.0,)+com.acme:module-b@[2.0.0,)",
                ProbeOutcome.resolved(Map.of(ancestorA, "1.5.0", ancestorB, "2.5.0"), "3.1.9"));

        List<String> knownVersions = List.of("1.0.0", "1.5.0");
        BumpProbeService service = service(fakeResolver(responses, knownVersions));
        ComponentGraph graph = twoAncestorGraph("com.acme:module-a", "1.0.0", "com.acme:module-b", "2.0.0");
        StoredComponent target = transitiveTarget("3.1.4");
        BumpRequest request = request(target, graph, evaluatorWhereCleanVersionsAre("3.1.9"));

        service.start(request, MAVEN_SETTINGS);
        BumpProgress result = awaitCompletion(service, target, graph);

        // The primary ancestor's own ranked candidates are still shown, alongside the combined
        // remedy -- ranking is scoped to it, but that does not hide the data already gathered.
        assertThat(result.candidates()).hasSize(1);
        assertThat(result.candidates().getFirst().clean()).isFalse();

        assertThat(result.remedy().available()).isTrue();
        assertThat(result.remedy().note()).contains("No single ancestor resolves this alone");
        assertThat(result.remedy().note()).contains("module-a").contains("module-b");
    }

    /**
     * The single background thread means a probe started while another is in flight does not
     * run alongside it -- it waits. Reporting that as RUNNING would claim Maven is being
     * probed right now for something that has not started, so {@code start} must report
     * QUEUED for it instead, and the record must flip to RUNNING once it actually gets its
     * turn -- not stay QUEUED for its own entire run.
     */
    @Test
    void aSecondProbeQueuesRatherThanReportingRunningWhileAnotherIsInFlight() throws InterruptedException {
        CountDownLatch aStarted = new CountDownLatch(1);
        CountDownLatch releaseA = new CountDownLatch(1);

        DependencyResolver resolver = new DependencyResolver() {
            @Override
            public ProbeOutcome resolve(List<ModuleDependency> moduleDependencies,
                                         Map<MavenArtifact, String> overrides, MavenArtifact target,
                                         ProbeContext context) {
                if (target.artifactId().equals("target-lib")) {
                    // Every resolve() call within run A lands here, not only calibration --
                    // signalling and blocking on latches already at their terminal state is a
                    // harmless no-op, so this only pauses the run once, at its first call.
                    aStarted.countDown();
                    try {
                        releaseA.await();
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                    return ProbeOutcome.resolved(Map.of(), "3.1.4");
                }
                return ProbeOutcome.resolved(Map.of(), "9.9.9");
            }

            @Override
            public List<String> knownVersions(MavenArtifact declaring, ProbeContext context) {
                return List.of();
            }
        };

        BumpProbeService service = service(resolver);
        ComponentGraph graphA = singleAncestorGraph("com.acme:module-a", "4.1.5");
        StoredComponent componentA = transitiveTarget("3.1.4");
        BumpRequest requestA = request(componentA, graphA, evaluatorWhereCleanVersionsAre("3.1.9"));

        ComponentGraph graphB = singleAncestorGraph("com.acme:module-a", "4.1.5");
        StoredComponent componentB = new StoredComponent(UUID.randomUUID(), "target-lib-2-ref",
                "com.example", "target-lib-2", "9.9.9", "pkg:maven/com.example/target-lib-2@9.9.9",
                "library", false, DependencyScope.TRANSITIVE);
        BumpRequest requestB = request(componentB, graphB, evaluatorWhereCleanVersionsAre("9.9.9"));

        service.start(requestA, MAVEN_SETTINGS);
        assertThat(aStarted.await(5, TimeUnit.SECONDS)).isTrue();

        BumpProgress startedB = service.start(requestB, MAVEN_SETTINGS);
        assertThat(startedB.state()).isEqualTo(BumpProgress.State.QUEUED);
        assertThat(startedB.message()).contains("Queued");
        // Reading it back through the normal poll path must agree with what start() returned.
        assertThat(service.progress(componentB, graphB).state()).isEqualTo(BumpProgress.State.QUEUED);

        releaseA.countDown();
        awaitCompletion(service, componentA, graphA);
        BumpProgress finishedB = awaitCompletion(service, componentB, graphB);

        assertThat(finishedB.state()).isEqualTo(BumpProgress.State.COMPLETED);
    }

    /**
     * A major whose walk the budget cut short must not read as a verdict on that major.
     * "Highest is 1.1.0, still carries X" and "we got as far as 1.1.0 and stopped" are
     * different claims — the second says nothing about the releases above it, one of which may
     * be clean — and the row has to say which one it is.
     */
    @Test
    void aMajorCutShortByTheBudgetSaysSoRatherThanReadingAsItsHighest() throws InterruptedException {
        MavenArtifact ancestor = new MavenArtifact("com.acme", "module-a");
        Map<String, ProbeOutcome> responses = Map.of(
                "calibration", ProbeOutcome.resolved(Map.of(), "3.1.4"),
                "com.acme:module-a@[1.0.0,)", ProbeOutcome.resolved(Map.of(ancestor, "1.3.0"), "3.1.4"),
                "com.acme:module-a@[1.0.0]", ProbeOutcome.resolved(Map.of(ancestor, "1.0.0"), "3.1.4"),
                "com.acme:module-a@[1.1.0]", ProbeOutcome.resolved(Map.of(ancestor, "1.1.0"), "3.1.4"));

        // Four minor lines, but only enough budget for calibration, feasibility and two of them.
        List<String> knownVersions = List.of("1.0.0", "1.1.0", "1.2.0", "1.3.0");
        MavenToolSettings tightBudget = new MavenToolSettings(
                true, "/usr/bin/mvn", 4, MavenToolSettings.DEFAULT_RUN_BUDGET_MINUTES, null,
                MavenToolSettings.DEFAULT_DEPENDENCY_PLUGIN_VERSION, MavenToolSettings.DEFAULT_HELP_PLUGIN_VERSION);

        BumpProbeService service = service(fakeResolver(responses, knownVersions));
        ComponentGraph graph = singleAncestorGraph("com.acme:module-a", "1.0.0");
        StoredComponent target = transitiveTarget("3.1.4");
        BumpRequest request = request(target, graph, evaluatorWhereCleanVersionsAre("3.1.9"));

        service.start(request, tightBudget);
        BumpProgress result = awaitCompletion(service, target, graph);

        assertThat(result.candidates()).hasSize(1);
        assertThat(result.candidates().getFirst()).satisfies(candidate -> {
            assertThat(candidate.probed()).isTrue();
            assertThat(candidate.version()).isEqualTo("1.1.0");
            assertThat(candidate.clean()).isFalse();
            // 1.2.0 and 1.3.0 were never looked at, and the row must not imply otherwise.
            assertThat(candidate.higherReleasesUnchecked()).isTrue();
        });
    }

    /**
     * A cached run that produced no rows must not be a dead end. Reported live: with Maven
     * unconfigured the probe is refused, and after configuring it from the linked Settings page
     * the component it was started from could not be asked again short of restarting the
     * application — {@code start} keeps returning the cached COMPLETED. Continuing a run that
     * ranked nothing has nothing to preserve, so it starts over.
     */
    @Test
    void continuingARunThatRankedNothingStartsItOverRatherThanReturningTheDeadEnd()
            throws InterruptedException {
        ComponentGraph graph = singleAncestorGraph("com.acme:module-a", "1.0.0");
        StoredComponent target = transitiveTarget("3.1.4");

        Map<String, ProbeOutcome> responses = new java.util.HashMap<>(Map.of(
                "calibration", ProbeOutcome.failed(ProbeFailureReason.NOT_RUNNABLE, "mvn is not where you said")));
        BumpProbeService service = service(fakeResolver(responses, List.of("1.0.0")));
        BumpRequest request = request(target, graph, evaluatorWhereCleanVersionsAre("3.1.9"));

        service.start(request, MAVEN_SETTINGS);
        BumpProgress deadEnd = awaitCompletion(service, target, graph);
        assertThat(deadEnd.candidates()).isEmpty();
        assertThat(deadEnd.remedy().available()).isFalse();

        // start() alone still refuses — the cached result is what it is meant to return.
        assertThat(service.start(request, MAVEN_SETTINGS).remedy()).isNotNull();

        // Whatever was wrong is now fixed; continuing runs it again rather than replaying it.
        responses.clear();
        responses.putAll(Map.of(
                "calibration", ProbeOutcome.resolved(Map.of(), "3.1.4"),
                "com.acme:module-a@[1.0.0,)",
                ProbeOutcome.resolved(Map.of(new MavenArtifact("com.acme", "module-a"), "1.0.0"), "3.1.9"),
                "com.acme:module-a@[1.0.0]",
                ProbeOutcome.resolved(Map.of(new MavenArtifact("com.acme", "module-a"), "1.0.0"), "3.1.9")));

        service.continueRun(request, MAVEN_SETTINGS);
        BumpProgress retried = awaitCompletion(service, target, graph);

        assertThat(retried.candidates()).hasSize(1);
        assertThat(retried.candidates().getFirst().clean()).isTrue();
    }

    /**
     * Continuing picks up above where the budget stopped, keeps rows already settled, and does
     * not repeat calibration or feasibility. The fake resolver throws on any probe it was not
     * told to expect, so "1.0.0 and the two setup probes are not re-run" is enforced by the
     * absence of those keys rather than by counting.
     */
    @Test
    void continuingResumesAboveTheStopPointInsteadOfStartingOver() throws InterruptedException {
        MavenArtifact ancestor = new MavenArtifact("com.acme", "module-a");
        Map<String, ProbeOutcome> firstPass = Map.of(
                "calibration", ProbeOutcome.resolved(Map.of(), "3.1.4"),
                "com.acme:module-a@[1.0.0,)", ProbeOutcome.resolved(Map.of(ancestor, "1.3.0"), "3.1.4"),
                "com.acme:module-a@[1.0.0]", ProbeOutcome.resolved(Map.of(ancestor, "1.0.0"), "3.1.4"),
                "com.acme:module-a@[1.1.0]", ProbeOutcome.resolved(Map.of(ancestor, "1.1.0"), "3.1.4"));

        List<String> knownVersions = List.of("1.0.0", "1.1.0", "1.2.0", "1.3.0");
        ComponentGraph graph = singleAncestorGraph("com.acme:module-a", "1.0.0");
        StoredComponent target = transitiveTarget("3.1.4");
        BumpRequest request = request(target, graph, evaluatorWhereCleanVersionsAre("3.1.9"));

        // Mutable so the continue pass can be given a different, deliberately narrower map.
        Map<String, ProbeOutcome> responses = new java.util.HashMap<>(firstPass);
        BumpProbeService service = service(fakeResolver(responses, knownVersions));

        service.start(request, new MavenToolSettings(
                true, "/usr/bin/mvn", 4, MavenToolSettings.DEFAULT_RUN_BUDGET_MINUTES, null,
                MavenToolSettings.DEFAULT_DEPENDENCY_PLUGIN_VERSION, MavenToolSettings.DEFAULT_HELP_PLUGIN_VERSION));
        BumpProgress cutShort = awaitCompletion(service, target, graph);
        assertThat(cutShort.candidates().getFirst().higherReleasesUnchecked()).isTrue();
        assertThat(cutShort.candidates().getFirst().version()).isEqualTo("1.1.0");

        // Only the releases above 1.1.0 may be probed now. Calibration, [1.0.0,) and [1.0.0]
        // are removed, so re-running any of them fails the test rather than passing quietly.
        responses.clear();
        responses.put("com.acme:module-a@[1.2.0]", ProbeOutcome.resolved(Map.of(ancestor, "1.2.0"), "3.1.9"));

        service.continueRun(request, MAVEN_SETTINGS);
        BumpProgress resumed = awaitCompletion(service, target, graph);

        assertThat(resumed.candidates()).hasSize(1);
        assertThat(resumed.candidates().getFirst()).satisfies(candidate -> {
            assertThat(candidate.version()).isEqualTo("1.2.0");
            assertThat(candidate.clean()).isTrue();
            // The walk found its earliest clean release, so nothing is left dangling.
            assertThat(candidate.higherReleasesUnchecked()).isFalse();
        });
    }

    /**
     * Calibration can succeed while the very next probe fails — the isolated repository has
     * enough cached to resolve the module as declared, but not to resolve a version range.
     * That path used to return an empty candidate list, which completed the run showing
     * nothing whatsoever: no rows, no remedy, no error, indistinguishable in the panel from
     * "probed everything, found no upgrade". Reported live from an air-gapped machine as
     * "does not produce usable probes"; the reason must reach the reader.
     */
    @Test
    void aFailedFeasibilityProbeReportsWhyRatherThanCompletingEmpty() throws InterruptedException {
        Map<String, ProbeOutcome> responses = Map.of(
                "calibration", ProbeOutcome.resolved(Map.of(), "3.1.4"),
                "com.acme:module-a@[1.0.0,)", ProbeOutcome.failed(ProbeFailureReason.PLUGIN_UNAVAILABLE,
                        "No plugin found for prefix 'dependency'"));

        BumpProbeService service = service(fakeResolver(responses, List.of()));
        ComponentGraph graph = singleAncestorGraph("com.acme:module-a", "1.0.0");
        StoredComponent target = transitiveTarget("3.1.4");
        BumpRequest request = request(target, graph, evaluatorWhereCleanVersionsAre("3.1.9"));

        service.start(request, MAVEN_SETTINGS);
        BumpProgress result = awaitCompletion(service, target, graph);

        assertThat(result.candidates()).isEmpty();
        assertThat(result.remedy()).isNotNull();
        assertThat(result.remedy().available()).isFalse();
        // Names the actual obstacle and where to read more, rather than blaming the component.
        assertThat(result.remedy().note())
                .contains("could not obtain the plugin")
                .contains("sbomscope.log");
    }

    @Test
    void neitherSingleNorCombinationReportsAnHonestUnavailable() throws InterruptedException {
        MavenArtifact ancestorA = new MavenArtifact("com.acme", "module-a");
        MavenArtifact ancestorB = new MavenArtifact("com.acme", "module-b");
        Map<String, ProbeOutcome> responses = Map.of(
                "calibration", ProbeOutcome.resolved(Map.of(), "3.1.4"),
                "com.acme:module-a@[1.0.0,)", ProbeOutcome.resolved(Map.of(ancestorA, "1.5.0"), "3.1.4"),
                "com.acme:module-a@[1.0.0]", ProbeOutcome.resolved(Map.of(ancestorA, "1.0.0"), "3.1.4"),
                "com.acme:module-a@[1.5.0]", ProbeOutcome.resolved(Map.of(ancestorA, "1.5.0"), "3.1.4"),
                "com.acme:module-b@[2.0.0,)", ProbeOutcome.resolved(Map.of(ancestorB, "2.5.0"), "3.1.4"),
                "com.acme:module-a@[1.0.0,)+com.acme:module-b@[2.0.0,)",
                ProbeOutcome.resolved(Map.of(ancestorA, "1.5.0", ancestorB, "2.5.0"), "3.1.4"));

        List<String> knownVersions = List.of("1.0.0", "1.5.0");
        BumpProbeService service = service(fakeResolver(responses, knownVersions));
        ComponentGraph graph = twoAncestorGraph("com.acme:module-a", "1.0.0", "com.acme:module-b", "2.0.0");
        StoredComponent target = transitiveTarget("3.1.4");
        BumpRequest request = request(target, graph, evaluatorWhereCleanVersionsAre("3.1.9"));

        service.start(request, MAVEN_SETTINGS);
        BumpProgress result = awaitCompletion(service, target, graph);

        assertThat(result.remedy().available()).isFalse();
        assertThat(result.remedy().note()).contains("No single ancestor, and no combination of");
    }
}
