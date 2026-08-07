package dev.sbomscope.sbom;

import java.sql.ResultSet;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/** Storage for the sidebar's projects and folders (V9). */
@Repository
public class FolderRepository {

    private final JdbcClient jdbc;

    FolderRepository(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    private static final RowMapper<StoredFolder> MAPPER = (ResultSet rs, int row) -> new StoredFolder(
            rs.getObject("id", UUID.class),
            rs.getString("name"),
            rs.getObject("parent_id", UUID.class),
            toInstant(rs.getObject("created_at", OffsetDateTime.class)));

    private static Instant toInstant(OffsetDateTime value) {
        return value == null ? null : value.toInstant();
    }

    public void insert(StoredFolder folder) {
        jdbc.sql("INSERT INTO folder (id, name, parent_id, created_at, sort_order) VALUES (?, ?, ?, ?, ?)")
                .params(folder.id(), folder.name(), folder.parentId(),
                        folder.createdAt().atOffset(ZoneOffset.UTC),
                        topOfGroup(folder.parentId()))
                .update();
    }

    /**
     * One below the lowest value in the sibling group, so a new folder lands at the top of it.
     *
     * <p>Taking MIN - 1 rather than shifting every sibling down keeps a create to a single
     * row write. Values drift negative over time and that is fine: only the relative order is
     * ever read, and an explicit reorder rewrites the group to a dense sequence.
     */
    private int topOfGroup(UUID parentId) {
        String sql = parentId == null
                ? "SELECT COALESCE(MIN(sort_order), 0) - 1 FROM folder WHERE parent_id IS NULL"
                : "SELECT COALESCE(MIN(sort_order), 0) - 1 FROM folder WHERE parent_id = ?";
        Integer value = parentId == null
                ? jdbc.sql(sql).query(Integer.class).single()
                : jdbc.sql(sql).param(parentId).query(Integer.class).single();
        return value == null ? 0 : value;
    }

    /**
     * Rewrites one sibling group to a dense 0..n-1 sequence in the order given.
     *
     * <p>The whole group rather than the moved row alone: a single row cannot express "between
     * these two" without either fractional values or renumbering anyway, and a sibling group in
     * a sidebar is small enough that rewriting it is cheaper than the arithmetic to avoid it.
     */
    public void reorder(List<UUID> orderedIds) {
        for (int position = 0; position < orderedIds.size(); position++) {
            jdbc.sql("UPDATE folder SET sort_order = ? WHERE id = ?")
                    .params(position, orderedIds.get(position))
                    .update();
        }
    }

    /** Every folder directly inside {@code parentId}, in display order. */
    public List<StoredFolder> childrenOf(UUID parentId) {
        String sql = parentId == null
                ? "SELECT * FROM folder WHERE parent_id IS NULL ORDER BY sort_order, LOWER(name)"
                : "SELECT * FROM folder WHERE parent_id = ? ORDER BY sort_order, LOWER(name)";
        return parentId == null
                ? jdbc.sql(sql).query(MAPPER).list()
                : jdbc.sql(sql).param(parentId).query(MAPPER).list();
    }

    /** Puts a folder at the top of its new group, so a move lands where the reader is looking. */
    public void updateParentToTop(UUID id, UUID parentId) {
        jdbc.sql("UPDATE folder SET parent_id = ?, sort_order = ? WHERE id = ?")
                .params(parentId, topOfGroup(parentId), id)
                .update();
    }

    /**
     * Every folder, ordered for display.
     *
     * <p>The whole table, deliberately: the tree is assembled in memory because a sidebar
     * holds tens of folders rather than thousands, and depth and cycle checks need the
     * complete parent chain anyway. A recursive CTE would buy nothing at this size and would
     * have to be written twice — once for reading and once for validating.
     */
    public List<StoredFolder> findAll() {
        // sort_order first, name as the tie-break so a group that has never been arranged by
        // hand still reads alphabetically rather than in insertion order.
        return jdbc.sql("SELECT * FROM folder ORDER BY sort_order, LOWER(name)").query(MAPPER).list();
    }

    public Optional<StoredFolder> findById(UUID id) {
        return jdbc.sql("SELECT * FROM folder WHERE id = ?").param(id).query(MAPPER).optional();
    }

    public void rename(UUID id, String name) {
        jdbc.sql("UPDATE folder SET name = ? WHERE id = ?").params(name, id).update();
    }

    public void updateParent(UUID id, UUID parentId) {
        jdbc.sql("UPDATE folder SET parent_id = ? WHERE id = ?").params(parentId, id).update();
    }

    /**
     * Re-parents every folder directly inside {@code folderId}.
     *
     * <p>Used by delete, which relocates rather than cascades. A cascade would delete the
     * user's uploaded documents as a side effect of tidying the sidebar.
     */
    public void reparentChildren(UUID folderId, UUID newParentId) {
        jdbc.sql("UPDATE folder SET parent_id = ? WHERE parent_id = ?")
                .params(newParentId, folderId)
                .update();
    }

    /** Re-files every document directly inside {@code folderId}. Same reasoning as above. */
    public void reassignSboms(UUID folderId, UUID newFolderId) {
        jdbc.sql("UPDATE sbom SET folder_id = ? WHERE folder_id = ?")
                .params(newFolderId, folderId)
                .update();
    }

    public boolean deleteById(UUID id) {
        return jdbc.sql("DELETE FROM folder WHERE id = ?").param(id).update() > 0;
    }

    /**
     * Whether a sibling already carries this name, compared case-insensitively.
     *
     * <p>Written in Java rather than left to {@code uq_folder_sibling_name} because H2 treats
     * NULL parents as distinct, so the index does not constrain top-level projects at all —
     * and because a unique-index violation surfaces as an opaque integrity error where this
     * can say which name is taken.
     */
    public boolean siblingNameExists(UUID parentId, String name, UUID excludingId) {
        String sql = parentId == null
                ? "SELECT COUNT(*) FROM folder WHERE parent_id IS NULL AND LOWER(name) = LOWER(?) AND (? IS NULL OR id <> ?)"
                : "SELECT COUNT(*) FROM folder WHERE parent_id = ? AND LOWER(name) = LOWER(?) AND (? IS NULL OR id <> ?)";
        var query = parentId == null
                ? jdbc.sql(sql).params(name, excludingId, excludingId)
                : jdbc.sql(sql).params(parentId, name, excludingId, excludingId);
        Integer count = query.query(Integer.class).single();
        return count != null && count > 0;
    }
}
