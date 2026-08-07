package dev.sbomscope.sbom;

import java.time.Instant;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import dev.sbomscope.logging.ActivityLogger;

/**
 * Projects and folders for the sidebar (B19).
 *
 * <p><b>The depth limit lives here rather than in the schema</b> because it is a judgement
 * about how deep a 280px column stays readable — a product rule — and not a statement about
 * what a tree is. Expressed as a CHECK constraint it would surface as an opaque integrity
 * violation; here it can say what the limit is and which operation exceeded it.
 *
 * <p><b>Deleting a folder never deletes a document.</b> Children and documents are relocated
 * to the deleted folder's parent, which is why {@code fk_folder_parent} has no cascade. The
 * purge design already establishes the reasoning: targets differ by what they cost to undo,
 * and an upload lost to a mis-clicked folder delete takes its scan history with it.
 */
@Service
public class FolderService {

    /**
     * A project, plus two levels beneath it. Depth 1 is a project.
     *
     * <p>Asked for as "a project can contain two levels of subfolders", which is this.
     */
    public static final int MAX_DEPTH = 3;

    private static final int MAX_NAME_LENGTH = 256;

    private final FolderRepository folders;
    private final SbomRepository sboms;
    private final ActivityLogger activityLog;

    FolderService(FolderRepository folders, SbomRepository sboms, ActivityLogger activityLog) {
        this.folders = folders;
        this.sboms = sboms;
        this.activityLog = activityLog;
    }

    public List<StoredFolder> findAll() {
        return folders.findAll();
    }

    @Transactional
    public StoredFolder create(String rawName, UUID parentId) {
        String name = validName(rawName);
        Map<UUID, StoredFolder> byId = byId();

        if (parentId != null) {
            StoredFolder parent = require(byId, parentId);
            int parentDepth = depthOf(byId, parent.id());
            if (parentDepth >= MAX_DEPTH) {
                throw new IllegalArgumentException(
                        ("Folders go %d levels deep — a project plus two levels inside it — and "
                                + "\"%s\" is already at level %d.").formatted(
                                MAX_DEPTH, parent.name(), parentDepth));
            }
        }
        requireNameFree(parentId, name, null, byId);

        StoredFolder folder = new StoredFolder(UUID.randomUUID(), name, parentId, Instant.now());
        folders.insert(folder);
        activityLog.record(ActivityLogger.Category.DATA, "FOLDER", "CREATED",
                parentId == null ? "Project \"%s\"".formatted(name)
                        : "Folder \"%s\" in \"%s\"".formatted(name, require(byId, parentId).name()));
        return folder;
    }

    @Transactional
    public StoredFolder rename(UUID id, String rawName) {
        String name = validName(rawName);
        Map<UUID, StoredFolder> byId = byId();
        StoredFolder folder = require(byId, id);
        requireNameFree(folder.parentId(), name, id, byId);

        folders.rename(id, name);
        activityLog.record(ActivityLogger.Category.DATA, "FOLDER", "RENAMED",
                "\"%s\" to \"%s\"".formatted(folder.name(), name));
        return new StoredFolder(folder.id(), name, folder.parentId(), folder.createdAt());
    }

    /**
     * Moves a folder under a new parent, or to the top level when {@code newParentId} is null.
     *
     * <p>Two checks that are easy to forget and both produce a corrupt tree rather than an
     * error message. A folder may not move <b>into its own descendant</b>, which would detach
     * the whole subtree from every root and make it unreachable in the sidebar while remaining
     * perfectly valid rows. And the depth limit applies to the moved subtree's <b>height</b>,
     * not to the folder alone: moving a two-level branch under a level-2 folder would put its
     * leaves at level 4.
     */
    @Transactional
    public StoredFolder move(UUID id, UUID newParentId) {
        Map<UUID, StoredFolder> byId = byId();
        StoredFolder folder = require(byId, id);

        if (newParentId != null) {
            if (newParentId.equals(id)) {
                throw new IllegalArgumentException("A folder cannot be moved into itself.");
            }
            StoredFolder target = require(byId, newParentId);
            if (isDescendant(byId, newParentId, id)) {
                throw new IllegalArgumentException(
                        "\"%s\" cannot be moved into \"%s\", which is inside it."
                                .formatted(folder.name(), target.name()));
            }
            int targetDepth = depthOf(byId, newParentId);
            int subtreeHeight = heightOf(byId, id);
            if (targetDepth + subtreeHeight > MAX_DEPTH) {
                throw new IllegalArgumentException(
                        ("That move would nest folders %d levels deep, and the limit is %d — "
                                + "a project plus two levels inside it.").formatted(
                                targetDepth + subtreeHeight, MAX_DEPTH));
            }
        }
        requireNameFree(newParentId, folder.name(), id, byId);

        folders.updateParentToTop(id, newParentId);
        activityLog.record(ActivityLogger.Category.DATA, "FOLDER", "MOVED",
                newParentId == null ? "\"%s\" to the top level".formatted(folder.name())
                        : "\"%s\" into \"%s\"".formatted(folder.name(), require(byId, newParentId).name()));
        return new StoredFolder(folder.id(), folder.name(), newParentId, folder.createdAt());
    }

    /**
     * Deletes a folder and relocates everything inside it to that folder's parent.
     *
     * <p>Never deletes a document, and never deletes a nested folder. Deleting a project
     * therefore moves its contents to the top level, where they are still visible — the
     * sidebar's flat state is the ordinary one, so nothing becomes unreachable.
     */
    @Transactional
    public boolean delete(UUID id) {
        Optional<StoredFolder> existing = folders.findById(id);
        if (existing.isEmpty()) {
            return false;
        }
        StoredFolder folder = existing.get();

        folders.reparentChildren(id, folder.parentId());
        folders.reassignSboms(id, folder.parentId());
        folders.deleteById(id);

        activityLog.record(ActivityLogger.Category.DATA, "FOLDER", "DELETED",
                "\"%s\" — its contents moved %s".formatted(folder.name(),
                        folder.parentId() == null ? "to the top level" : "up one level"));
        return true;
    }

    /**
     * Rewrites the display order of one sibling group.
     *
     * <p><b>The ids must be exactly that group's current members.</b> A reorder that accepted
     * a foreign id would be a move wearing a reorder's clothes — it would skip the depth,
     * cycle and name checks that {@link #move} exists to apply. Checking set equality is what
     * keeps the two operations honestly separate.
     */
    @Transactional
    public void reorderFolders(UUID parentId, List<UUID> orderedIds) {
        List<UUID> current = folders.childrenOf(parentId).stream().map(StoredFolder::id).toList();
        requireSameMembers(current, orderedIds, "folders");
        folders.reorder(orderedIds);
    }

    /** The same, for the documents directly inside one folder. */
    @Transactional
    public void reorderSboms(UUID folderId, List<UUID> orderedIds) {
        List<UUID> current = sboms.childrenOf(folderId).stream().map(StoredSbom::id).toList();
        requireSameMembers(current, orderedIds, "documents");
        sboms.reorder(orderedIds);
    }

    /**
     * Restores alphabetical order within one level, for both groups.
     *
     * <p>The escape hatch for a hand-arranged list that has stopped being useful. It
     * overwrites the manual order deliberately and only for the level asked about — sorting
     * the whole tree from one menu item would be a much larger action than the menu it sits in
     * suggests.
     */
    @Transactional
    public void sortByName(UUID parentId) {
        folders.reorder(folders.childrenOf(parentId).stream()
                .sorted(Comparator.comparing(folder -> folder.name().toLowerCase(Locale.ROOT)))
                .map(StoredFolder::id)
                .toList());
        sboms.reorder(sboms.childrenOf(parentId).stream()
                .sorted(Comparator.comparing(sbom -> sbom.filename().toLowerCase(Locale.ROOT)))
                .map(StoredSbom::id)
                .toList());
        activityLog.record(ActivityLogger.Category.DATA, "FOLDER", "SORTED",
                parentId == null ? "the top level" : "inside a folder");
    }

    private static void requireSameMembers(List<UUID> current, List<UUID> requested, String what) {
        if (current.size() != requested.size() || !Set.copyOf(current).equals(Set.copyOf(requested))) {
            throw new IllegalArgumentException(
                    "That ordering does not list exactly the %s in this level.".formatted(what));
        }
    }

    /** Files a document into a folder, or out of every folder when {@code folderId} is null. */
    @Transactional
    public void moveSbom(UUID sbomId, UUID folderId) {
        if (sboms.findById(sbomId).isEmpty()) {
            throw new IllegalArgumentException("No such SBOM.");
        }
        if (folderId != null && folders.findById(folderId).isEmpty()) {
            throw new IllegalArgumentException("No such folder.");
        }
        sboms.updateFolder(sbomId, folderId);
    }

    // --- tree arithmetic, all against the in-memory map ---

    private Map<UUID, StoredFolder> byId() {
        Map<UUID, StoredFolder> byId = new HashMap<>();
        for (StoredFolder folder : folders.findAll()) {
            byId.put(folder.id(), folder);
        }
        return byId;
    }

    private static StoredFolder require(Map<UUID, StoredFolder> byId, UUID id) {
        StoredFolder folder = byId.get(id);
        if (folder == null) {
            throw new IllegalArgumentException("No such folder.");
        }
        return folder;
    }

    /** 1 for a project. Bounded by {@link #MAX_DEPTH} + 1 so a corrupt cycle cannot hang. */
    private static int depthOf(Map<UUID, StoredFolder> byId, UUID id) {
        int depth = 0;
        UUID cursor = id;
        while (cursor != null && depth <= MAX_DEPTH) {
            depth++;
            StoredFolder folder = byId.get(cursor);
            cursor = folder == null ? null : folder.parentId();
        }
        return depth;
    }

    /** 1 for a folder with no children — the number of levels the subtree occupies. */
    private static int heightOf(Map<UUID, StoredFolder> byId, UUID id) {
        int height = 1;
        for (StoredFolder candidate : byId.values()) {
            if (id.equals(candidate.parentId())) {
                height = Math.max(height, 1 + heightOf(byId, candidate.id()));
            }
        }
        return height;
    }

    private static boolean isDescendant(Map<UUID, StoredFolder> byId, UUID candidate, UUID ancestor) {
        UUID cursor = candidate;
        int guard = 0;
        while (cursor != null && guard++ <= MAX_DEPTH + 1) {
            if (ancestor.equals(cursor)) {
                return true;
            }
            StoredFolder folder = byId.get(cursor);
            cursor = folder == null ? null : folder.parentId();
        }
        return false;
    }

    private String validName(String raw) {
        String name = raw == null ? "" : raw.strip();
        if (name.isEmpty()) {
            throw new IllegalArgumentException("A folder needs a name.");
        }
        if (name.length() > MAX_NAME_LENGTH) {
            throw new IllegalArgumentException(
                    "That name is longer than the %d characters a folder name may hold."
                            .formatted(MAX_NAME_LENGTH));
        }
        return name;
    }

    private void requireNameFree(UUID parentId, String name, UUID excludingId,
                                 Map<UUID, StoredFolder> byId) {
        if (folders.siblingNameExists(parentId, name, excludingId)) {
            throw new IllegalArgumentException(parentId == null
                    ? "There is already a project called \"%s\".".formatted(name)
                    : "\"%s\" already contains a folder called \"%s\"."
                            .formatted(require(byId, parentId).name(), name));
        }
    }
}
