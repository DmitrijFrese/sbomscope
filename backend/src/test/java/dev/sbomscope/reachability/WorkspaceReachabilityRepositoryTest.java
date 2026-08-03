package dev.sbomscope.reachability;

import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.simple.JdbcClient;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@SpringBootTest
class WorkspaceReachabilityRepositoryTest {

    @Autowired WorkspaceReachabilityRepository repository;
    @Autowired JdbcClient jdbc;

    private UUID sbomId;

    @AfterEach
    void cleanUp() {
        if (sbomId != null) jdbc.sql("DELETE FROM sbom WHERE id = ?").param(sbomId).update();
    }

    @Test
    void rollsBackModulesAndEvidenceWhenCompletingTheRunFails() {
        WorkspaceAnalysisRun run = runningRun();
        WorkspaceAnalysisModule module = new WorkspaceAnalysisModule(
                "module-a", "module-a/target/classes", "module-a-ref",
                WorkspaceAnalysisModule.MappingStatus.MAPPED, null);
        WorkspaceReachabilityEvidence invalid = new WorkspaceReachabilityEvidence(
                "pkg:maven/example/library@1", "module-a",
                WorkspaceReachabilityEvidence.Status.REACHABLE, List.of(), 1, 1, 0,
                "x".repeat(5_000));

        assertThatThrownBy(() -> repository.complete(run.id(), "WALA", "0-CFA", Instant.now(),
                List.of(module), List.of(invalid))).isInstanceOf(RuntimeException.class);

        assertThat(count("workspace_analysis_module", run.id())).isZero();
        assertThat(count("workspace_reachability_evidence", run.id())).isZero();
        assertThat(repository.latest(sbomId).orElseThrow().status()).isEqualTo(WorkspaceAnalysisRun.Status.RUNNING);
    }

    @Test
    void aStopWinsOverACompleteThatArrivesLater() {
        WorkspaceAnalysisRun run = runningRun();
        repository.stop(run.id(), Instant.now());

        assertThatThrownBy(() -> repository.complete(run.id(), "WALA", "0-CFA", Instant.now(),
                List.of(new WorkspaceAnalysisModule("module-a", "out", "ref",
                        WorkspaceAnalysisModule.MappingStatus.MAPPED, null)),
                List.of())).isInstanceOf(IllegalStateException.class);

        assertThat(count("workspace_analysis_module", run.id())).isZero();
        assertThat(repository.latest(sbomId).orElseThrow().status()).isEqualTo(WorkspaceAnalysisRun.Status.STOPPED);
    }

    @Test
    void reconcilesDurableRunsThatHaveNoLiveWorkerAfterRestart() {
        WorkspaceAnalysisRun run = queuedRun();

        assertThat(repository.failAbandoned(Instant.now())).isGreaterThanOrEqualTo(1);

        WorkspaceAnalysisRun reconciled = repository.latest(sbomId).orElseThrow();
        assertThat(reconciled.status()).isEqualTo(WorkspaceAnalysisRun.Status.FAILED);
        assertThat(reconciled.errorMessage()).contains("retried implicitly");
    }

    private WorkspaceAnalysisRun runningRun() {
        WorkspaceAnalysisRun run = queuedRun();
        assertThat(repository.markRunning(run.id(), Instant.now())).isTrue();
        return run;
    }

    private WorkspaceAnalysisRun queuedRun() {
        sbomId = UUID.randomUUID();
        jdbc.sql("""
                INSERT INTO sbom (id, filename, uploaded_at, component_count)
                VALUES (?, ?, ?, 0)
                """).params(sbomId, "reachability-test.cdx.json", Instant.now().atOffset(ZoneOffset.UTC)).update();
        WorkspaceAnalysisRun run = new WorkspaceAnalysisRun(
                UUID.randomUUID(), sbomId, "fingerprint", WorkspaceAnalysisRun.Status.QUEUED,
                null, null, List.of(), null, Instant.now(), null, null);
        repository.insertQueued(run);
        return run;
    }

    private long count(String table, UUID runId) {
        return jdbc.sql("SELECT COUNT(*) FROM " + table + " WHERE analysis_run_id = ?")
                .param(runId).query(Long.class).single();
    }
}
