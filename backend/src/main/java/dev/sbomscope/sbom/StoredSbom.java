package dev.sbomscope.sbom;

import java.time.Instant;
import java.util.UUID;

/**
 * An SBOM as held in local storage.
 *
 * @param workspacePath absolute path to the source tree this SBOM describes, or
 *                      {@code null} when the user uploaded it without one — workspace
 *                      analysis is optional by design. Settable after the fact (B20);
 *                      it was upload-only until 2026-08-06
 * @param folderId      the project or folder this document is filed under, or {@code null}
 *                      when it sits outside every project. Null is the ordinary state
 *                      rather than a missing value, and such documents stay first-class
 *                      in the sidebar beside the folders
 */
public record StoredSbom(
        UUID id,
        String filename,
        Instant uploadedAt,
        String workspacePath,
        String specVersion,
        int componentCount,
        UUID folderId) {

    /**
     * A document filed nowhere — the ordinary state on import.
     *
     * <p>Kept so the call sites that create an SBOM before it has been filed anywhere do
     * not each have to pass a null they have no opinion about.
     */
    public StoredSbom(UUID id, String filename, Instant uploadedAt, String workspacePath,
                      String specVersion, int componentCount) {
        this(id, filename, uploadedAt, workspacePath, specVersion, componentCount, null);
    }
}
