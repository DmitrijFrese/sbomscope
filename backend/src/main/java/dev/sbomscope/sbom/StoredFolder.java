package dev.sbomscope.sbom;

import java.time.Instant;
import java.util.UUID;

/**
 * A project, or a folder inside one.
 *
 * <p>There is no separate notion of a project: <b>a project is a folder with no parent</b>.
 * Two types would have made "an SBOM may sit at any level" three cases in every query that
 * walks the tree, instead of a property of the model.
 *
 * @param parentId the folder this one sits in, or {@code null} when it is a project
 */
public record StoredFolder(
        UUID id,
        String name,
        UUID parentId,
        Instant createdAt) {

    /** A folder with no parent is a project — the root of one tree in the sidebar. */
    public boolean isProject() {
        return parentId == null;
    }
}
