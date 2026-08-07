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
            rs.getInt("component_count"),
            rs.getObject("folder_id", UUID.class));

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
                INSERT INTO sbom (id, filename, uploaded_at, workspace_path, spec_version,
                                  component_count, folder_id, sort_order)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """)
                .params(
                        sbom.id(),
                        sbom.filename(),
                        sbom.uploadedAt().atOffset(ZoneOffset.UTC),
                        sbom.workspacePath(),
                        sbom.specVersion(),
                        sbom.componentCount(),
                        sbom.folderId(),
                        topOfGroup(sbom.folderId()))
                .update();
    }

    /**
     * One below the lowest value in the destination group, so a new or moved document lands
     * at the top of it — see {@code V10__manual_ordering.sql} for why MIN - 1 rather than a
     * shift of every sibling.
     */
    private int topOfGroup(UUID folderId) {
        String sql = folderId == null
                ? "SELECT COALESCE(MIN(sort_order), 0) - 1 FROM sbom WHERE folder_id IS NULL"
                : "SELECT COALESCE(MIN(sort_order), 0) - 1 FROM sbom WHERE folder_id = ?";
        Integer value = folderId == null
                ? jdbc.sql(sql).query(Integer.class).single()
                : jdbc.sql(sql).param(folderId).query(Integer.class).single();
        return value == null ? 0 : value;
    }

    /**
     * Files a document into a folder, or out of every folder when {@code folderId} is null,
     * placing it at the top of the destination.
     */
    public void updateFolder(UUID sbomId, UUID folderId) {
        jdbc.sql("UPDATE sbom SET folder_id = ?, sort_order = ? WHERE id = ?")
                .params(folderId, topOfGroup(folderId), sbomId)
                .update();
    }

    /** Rewrites one folder's documents to a dense 0..n-1 sequence in the order given. */
    public void reorder(List<UUID> orderedIds) {
        for (int position = 0; position < orderedIds.size(); position++) {
            jdbc.sql("UPDATE sbom SET sort_order = ? WHERE id = ?")
                    .params(position, orderedIds.get(position))
                    .update();
        }
    }

    /** Every document directly inside {@code folderId}, in display order. */
    public List<StoredSbom> childrenOf(UUID folderId) {
        String sql = folderId == null
                ? "SELECT * FROM sbom WHERE folder_id IS NULL ORDER BY sort_order, uploaded_at DESC"
                : "SELECT * FROM sbom WHERE folder_id = ? ORDER BY sort_order, uploaded_at DESC";
        return folderId == null
                ? jdbc.sql(sql).query(SBOM_MAPPER).list()
                : jdbc.sql(sql).param(folderId).query(SBOM_MAPPER).list();
    }

    /**
     * Sets, changes or clears the attached workspace (B20).
     *
     * <p>Clearing matters as much as setting: a path that has moved is worse than no path,
     * because analysis then answers confidently about a directory that is no longer the
     * project.
     */
    public int updateWorkspacePath(UUID sbomId, String workspacePath) {
        return jdbc.sql("UPDATE sbom SET workspace_path = ? WHERE id = ?")
                .params(workspacePath, sbomId)
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
        // Manual order first, newest-first as the tie-break — which is what a group that has
        // never been arranged by hand still gets, so nothing looks reshuffled.
        return jdbc.sql("SELECT * FROM sbom ORDER BY sort_order, uploaded_at DESC")
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

    /**
     * The dependency graph as the document declared it.
     *
     * <p>By bom-ref rather than joined to components, because that is how the edges are
     * stored: an edge can name a ref no component row exists for, and a malformed document
     * should cost a missing node rather than a failed query.
     */
    public List<ParsedSbom.DependencyEdge> findEdges(UUID sbomId) {
        return jdbc.sql("""
                SELECT from_bom_ref, to_bom_ref FROM component_dependency
                WHERE sbom_id = ?
                """)
                .param(sbomId)
                .query((ResultSet rs, int row) -> new ParsedSbom.DependencyEdge(
                        rs.getString("from_bom_ref"), rs.getString("to_bom_ref")))
                .list();
    }

    /** Components and edges disappear with it, via ON DELETE CASCADE. */
    public boolean deleteById(UUID id) {
        return jdbc.sql("DELETE FROM sbom WHERE id = ?").param(id).update() > 0;
    }
}
