package dev.sbomscope.reachability;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

/** JDBC storage for immutable workspace-analysis results. */
@Repository
public class WorkspaceReachabilityRepository {

    private final JdbcClient jdbc;
    private final ObjectMapper mapper;

    WorkspaceReachabilityRepository(JdbcClient jdbc, ObjectMapper mapper) {
        this.jdbc = jdbc;
        this.mapper = mapper;
    }

    public Optional<WorkspaceAnalysisRun> latest(UUID sbomId) {
        return jdbc.sql("""
                SELECT * FROM workspace_analysis_run WHERE sbom_id = ?
                ORDER BY requested_at DESC LIMIT 1
                """)
                .param(sbomId)
                .query((rs, row) -> run(rs))
                .optional();
    }

    public void insertQueued(WorkspaceAnalysisRun run) {
        jdbc.sql("""
                INSERT INTO workspace_analysis_run
                    (id, sbom_id, input_fingerprint, status, blockers, requested_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """)
                .params(run.id(), run.sbomId(), run.inputFingerprint(), run.status().name(),
                        String.join("|", run.blockers()), at(run.requestedAt()))
                .update();
    }

    public boolean markRunning(UUID runId, Instant startedAt) {
        return jdbc.sql("""
                UPDATE workspace_analysis_run SET status = 'RUNNING', started_at = ?
                WHERE id = ? AND status = 'QUEUED'
                """)
                .params(at(startedAt), runId)
                .update() == 1;
    }

    private void storeModules(UUID runId, List<WorkspaceAnalysisModule> modules) {
        for (WorkspaceAnalysisModule module : modules) {
            jdbc.sql("""
                    INSERT INTO workspace_analysis_module
                        (id, analysis_run_id, module_path, production_output, application_bom_ref,
                         mapping_status, mapping_detail)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """)
                    .params(UUID.randomUUID(), runId, module.modulePath(), module.productionOutput(),
                            module.applicationBomRef(), module.mappingStatus().name(), module.mappingDetail())
                    .update();
        }
    }

    @Transactional
    public void complete(UUID runId, String engine, String algorithm, Instant finishedAt,
                         List<WorkspaceAnalysisModule> modules,
                         List<WorkspaceReachabilityEvidence> evidence) {
        storeModules(runId, modules);
        for (WorkspaceReachabilityEvidence item : evidence) {
            jdbc.sql("""
                INSERT INTO workspace_reachability_evidence
                        (id, analysis_run_id, purl, module_path, status, method_paths,
                         reachable_method_count, direct_method_count, displayed_path_count, detail)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """)
                    .params(UUID.randomUUID(), runId, item.purl(), item.modulePath(), item.status().name(),
                            writePaths(item.methodPaths()), item.reachableMethodCount(), item.directMethodCount(),
                            item.displayedPathCount(), item.detail())
                    .update();
        }
        int updated = jdbc.sql("""
                UPDATE workspace_analysis_run
                SET status = 'COMPLETED', engine = ?, algorithm = ?, finished_at = ?
                WHERE id = ? AND status = 'RUNNING'
                """)
                .params(engine, algorithm, at(finishedAt), runId)
                .update();
        if (updated != 1) {
            throw new IllegalStateException("Workspace analysis is no longer running; results were not stored.");
        }
    }

    public void fail(UUID runId, String message, Instant finishedAt) {
        jdbc.sql("""
                UPDATE workspace_analysis_run
                SET status = 'FAILED', error_message = ?, finished_at = ?
                WHERE id = ? AND status IN ('QUEUED', 'RUNNING')
                """)
                .params(message, at(finishedAt), runId)
                .update();
    }

    public void stop(UUID runId, Instant finishedAt) {
        jdbc.sql("""
                UPDATE workspace_analysis_run SET status = 'STOPPED', finished_at = ?
                WHERE id = ? AND status IN ('QUEUED', 'RUNNING')
                """)
                .params(at(finishedAt), runId).update();
    }

    public int failAbandoned(Instant finishedAt) {
        return jdbc.sql("""
                UPDATE workspace_analysis_run
                SET status = 'FAILED', error_message = ?, finished_at = ?
                WHERE status IN ('QUEUED', 'RUNNING')
                """)
                .params("The application stopped before this workspace analysis finished; it can be retried implicitly.",
                        at(finishedAt))
                .update();
    }

    public List<WorkspaceReachabilityEvidence> evidence(UUID runId, String purl) {
        return jdbc.sql("""
                SELECT purl, module_path, status, method_paths, reachable_method_count,
                       direct_method_count, displayed_path_count, detail
                FROM workspace_reachability_evidence
                WHERE analysis_run_id = ? AND purl = ?
                ORDER BY module_path NULLS FIRST
                """)
                .params(runId, purl)
                .query((rs, row) -> new WorkspaceReachabilityEvidence(
                        rs.getString("purl"),
                        rs.getString("module_path"),
                        WorkspaceReachabilityEvidence.Status.valueOf(rs.getString("status")),
                        readPaths(rs.getString("method_paths")),
                        rs.getInt("reachable_method_count"),
                        rs.getInt("direct_method_count"),
                        rs.getInt("displayed_path_count"),
                        rs.getString("detail")))
                .list();
    }

    private WorkspaceAnalysisRun run(ResultSet rs) throws SQLException {
        String blockers = rs.getString("blockers");
        return new WorkspaceAnalysisRun(
                rs.getObject("id", UUID.class),
                rs.getObject("sbom_id", UUID.class),
                rs.getString("input_fingerprint"),
                WorkspaceAnalysisRun.Status.valueOf(rs.getString("status")),
                rs.getString("engine"),
                rs.getString("algorithm"),
                blockers == null || blockers.isBlank() ? List.of() : Arrays.asList(blockers.split("\\|")),
                rs.getString("error_message"),
                instant(rs.getObject("requested_at", OffsetDateTime.class)),
                instant(rs.getObject("started_at", OffsetDateTime.class)),
                instant(rs.getObject("finished_at", OffsetDateTime.class)));
    }

    private String writePaths(List<List<String>> paths) {
        try {
            return mapper.writeValueAsString(paths);
        } catch (Exception e) {
            throw new IllegalStateException("Could not store workspace method paths", e);
        }
    }

    private List<List<String>> readPaths(String json) {
        if (json == null || json.isBlank()) {
            return List.of();
        }
        try {
            return mapper.readValue(json, new TypeReference<>() {});
        } catch (Exception e) {
            throw new IllegalStateException("Stored workspace method paths are invalid", e);
        }
    }

    private OffsetDateTime at(Instant instant) {
        return instant == null ? null : instant.atOffset(ZoneOffset.UTC);
    }

    private Instant instant(OffsetDateTime time) {
        return time == null ? null : time.toInstant();
    }
}
