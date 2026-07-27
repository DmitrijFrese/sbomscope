package dev.sbomscope.sbom;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import dev.sbomscope.sbom.ParsedSbom.DependencyEdge;
import dev.sbomscope.sbom.ParsedSbom.ParsedComponent;

/**
 * Storage for SBOMs, their components and the dependency graph.
 *
 * <p>Reads go through {@link JdbcClient} for readability; the two bulk inserts use
 * {@link JdbcTemplate} batching, because a real project SBOM routinely carries a few
 * thousand components and row-at-a-time inserts are noticeably slower.
 */
@Repository
public class SbomRepository {

    private final JdbcClient jdbc;
    private final JdbcTemplate jdbcTemplate;

    SbomRepository(JdbcClient jdbc, JdbcTemplate jdbcTemplate) {
        this.jdbc = jdbc;
        this.jdbcTemplate = jdbcTemplate;
    }

    private static final RowMapper<StoredSbom> SBOM_MAPPER = (ResultSet rs, int row) -> new StoredSbom(
            rs.getObject("id", UUID.class),
            rs.getString("filename"),
            toInstant(rs.getObject("uploaded_at", OffsetDateTime.class)),
            rs.getString("workspace_path"),
            rs.getString("spec_version"),
            rs.getInt("component_count"));

    private static final RowMapper<StoredComponent> COMPONENT_MAPPER =
            (ResultSet rs, int row) -> new StoredComponent(
                    rs.getObject("id", UUID.class),
                    rs.getString("bom_ref"),
                    rs.getString("group_name"),
                    rs.getString("name"),
                    rs.getString("version"),
                    rs.getString("purl"),
                    rs.getString("component_type"),
                    rs.getBoolean("is_root"),
                    DependencyScope.parse(rs.getString("dependency_scope")));

    private static Instant toInstant(OffsetDateTime value) throws SQLException {
        return value == null ? null : value.toInstant();
    }

    public void insertSbom(StoredSbom sbom) {
        jdbc.sql("""
                INSERT INTO sbom (id, filename, uploaded_at, workspace_path, spec_version, component_count)
                VALUES (?, ?, ?, ?, ?, ?)
                """)
                .params(
                        sbom.id(),
                        sbom.filename(),
                        sbom.uploadedAt().atOffset(ZoneOffset.UTC),
                        sbom.workspacePath(),
                        sbom.specVersion(),
                        sbom.componentCount())
                .update();
    }

    public void insertComponents(UUID sbomId, List<ParsedComponent> components) {
        jdbcTemplate.batchUpdate("""
                INSERT INTO component
                    (id, sbom_id, bom_ref, group_name, name, version, purl, component_type,
                     is_root, dependency_scope)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                components,
                components.size(),
                (ps, component) -> {
                    ps.setObject(1, UUID.randomUUID());
                    ps.setObject(2, sbomId);
                    ps.setString(3, component.bomRef());
                    ps.setString(4, component.group());
                    ps.setString(5, component.name());
                    ps.setString(6, component.version());
                    ps.setString(7, component.purl());
                    ps.setString(8, component.type());
                    ps.setBoolean(9, component.root());
                    ps.setString(10, component.scope().name());
                });
    }

    public void insertEdges(UUID sbomId, List<DependencyEdge> edges) {
        if (edges.isEmpty()) {
            return;
        }
        jdbcTemplate.batchUpdate("""
                INSERT INTO component_dependency (sbom_id, from_bom_ref, to_bom_ref)
                VALUES (?, ?, ?)
                """,
                edges,
                edges.size(),
                (ps, edge) -> {
                    ps.setObject(1, sbomId);
                    ps.setString(2, edge.fromBomRef());
                    ps.setString(3, edge.toBomRef());
                });
    }

    public List<StoredSbom> findAll() {
        return jdbc.sql("SELECT * FROM sbom ORDER BY uploaded_at DESC")
                .query(SBOM_MAPPER)
                .list();
    }

    public Optional<StoredSbom> findById(UUID id) {
        return jdbc.sql("SELECT * FROM sbom WHERE id = ?")
                .param(id)
                .query(SBOM_MAPPER)
                .optional();
    }

    public List<StoredComponent> findComponents(UUID sbomId) {
        return jdbc.sql("""
                SELECT * FROM component
                WHERE sbom_id = ?
                ORDER BY is_root DESC,
                         CASE dependency_scope
                             WHEN 'APPLICATION' THEN 0 WHEN 'DIRECT' THEN 1 ELSE 2 END,
                         group_name NULLS FIRST, name
                """)
                .param(sbomId)
                .query(COMPONENT_MAPPER)
                .list();
    }

    /** Components and edges disappear with it, via ON DELETE CASCADE. */
    public boolean deleteById(UUID id) {
        return jdbc.sql("DELETE FROM sbom WHERE id = ?").param(id).update() > 0;
    }
}
