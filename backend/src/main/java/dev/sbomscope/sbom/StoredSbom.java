package dev.sbomscope.sbom;

import java.time.Instant;
import java.util.UUID;

/**
 * An SBOM as held in local storage.
 *
 * @param workspacePath absolute path to the source tree this SBOM describes, or
 *                      {@code null} when the user uploaded it without one — workspace
 *                      usage detection is optional by design
 */
public record StoredSbom(
        UUID id,
        String filename,
        Instant uploadedAt,
        String workspacePath,
        String specVersion,
        int componentCount) {}
