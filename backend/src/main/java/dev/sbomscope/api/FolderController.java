package dev.sbomscope.api;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import dev.sbomscope.sbom.FolderService;
import dev.sbomscope.sbom.StoredFolder;

/**
 * Projects and folders for the sidebar (B19).
 *
 * <p>Flat list in, tree assembled in the browser. The sidebar already holds every SBOM and
 * has to interleave them with the folders at each level, so shipping a nested structure would
 * mean the client rebuilding it anyway to merge in the documents.
 */
@RestController
@RequestMapping("/api/folders")
class FolderController {

    private final FolderService folders;

    FolderController(FolderService folders) {
        this.folders = folders;
    }

    record FolderResponse(UUID id, String name, UUID parentId, Instant createdAt) {
        static FolderResponse from(StoredFolder folder) {
            return new FolderResponse(folder.id(), folder.name(), folder.parentId(),
                    folder.createdAt());
        }
    }

    /**
     * @param parentId null creates a project — a folder at the top level
     */
    record CreateRequest(String name, UUID parentId) {}

    record RenameRequest(String name) {}

    /**
     * @param parentId null moves the folder to the top level, making it a project
     */
    record MoveRequest(UUID parentId) {}

    @GetMapping
    List<FolderResponse> list() {
        return folders.findAll().stream().map(FolderResponse::from).toList();
    }

    @PostMapping
    ResponseEntity<FolderResponse> create(@RequestBody CreateRequest request) {
        StoredFolder created = folders.create(request.name(), request.parentId());
        return ResponseEntity.status(HttpStatus.CREATED).body(FolderResponse.from(created));
    }

    @PatchMapping("/{id}/name")
    FolderResponse rename(@PathVariable("id") UUID id, @RequestBody RenameRequest request) {
        return FolderResponse.from(folders.rename(id, request.name()));
    }

    /**
     * Moving is its own endpoint rather than a field on a general update, because the checks
     * it needs — no cycles, and the subtree still fits inside the depth limit — have nothing
     * to do with renaming and would otherwise run on every edit.
     */
    @PatchMapping("/{id}/parent")
    FolderResponse move(@PathVariable("id") UUID id, @RequestBody MoveRequest request) {
        return FolderResponse.from(folders.move(id, request.parentId()));
    }

    /**
     * @param parentId  the level being reordered; null is the top level
     * @param folderIds every folder in that level, in the order to display them
     * @param sbomIds   every document in that level, likewise. Either may be omitted when
     *                  that group did not change
     */
    record ReorderRequest(UUID parentId, List<UUID> folderIds, List<UUID> sbomIds) {}

    /**
     * Rewrites the manual order of one level.
     *
     * <p>One endpoint for both groups because a drag lands in exactly one level and the
     * client already knows both lists — two round trips would let the tree be briefly
     * half-reordered.
     */
    @PatchMapping("/order")
    ResponseEntity<Void> reorder(@RequestBody ReorderRequest request) {
        if (request.folderIds() != null) {
            folders.reorderFolders(request.parentId(), request.folderIds());
        }
        if (request.sbomIds() != null) {
            folders.reorderSboms(request.parentId(), request.sbomIds());
        }
        return ResponseEntity.noContent().build();
    }

    /** Restores alphabetical order within one level, overwriting the manual order there. */
    @PostMapping("/sort-by-name")
    ResponseEntity<Void> sortByName(@RequestBody(required = false) ReorderRequest request) {
        folders.sortByName(request == null ? null : request.parentId());
        return ResponseEntity.noContent().build();
    }

    /**
     * Deletes a folder. Its contents move up to the parent; <b>no document is ever deleted</b>.
     *
     * <p>204 rather than 200 for the same reason the SBOM delete does: there is nothing
     * meaningful to return, and the sidebar refetches.
     */
    @DeleteMapping("/{id}")
    ResponseEntity<Void> delete(@PathVariable("id") UUID id) {
        return folders.delete(id)
                ? ResponseEntity.noContent().build()
                : ResponseEntity.notFound().build();
    }
}
