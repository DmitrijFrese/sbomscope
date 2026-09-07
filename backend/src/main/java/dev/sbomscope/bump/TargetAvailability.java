package dev.sbomscope.bump;

import dev.sbomscope.scanner.VersionOrder;

import java.util.List;

/**
 * Whether a version this screen recommends appears in the release metadata already on disk.
 *
 * <p>The question exists because an advisory's fix version can be real and still be out of reach:
 * once an open-source line goes end-of-life, several vendors publish the remaining patches to a
 * commercial repository. Measured 2026-09-07, spring-security-crypto 6.1.14 — the fix named for
 * CVE-2024-22228 — is not in Maven Central at all, so writing it into a pom stops the build
 * resolving.
 *
 * <p><b>This is the free half of that answer.</b> It reads the {@code maven-metadata*.xml} the
 * probe repository already holds — no process, no network, so it costs nothing and may be computed
 * whenever a plan is built. The paid half is
 * {@code dev.sbomscope.probe.ArtifactAvailability}, which asks the user's own {@code mvn} and can
 * answer for any artifact; this one answers only where somebody has already probed.
 */
public enum TargetAvailability {

    /** The version is listed in the metadata on disk. */
    KNOWN,

    /**
     * The metadata on disk lists this artifact's releases and this version is not among them,
     * while older *and* newer ones are. As close to "you cannot get this" as local files can say.
     */
    ABSENT,

    /** Nothing on disk can answer. Never rendered as a claim — absent rather than guessed. */
    UNKNOWN;

    /**
     * Classifies {@code target} against the versions read back from local metadata.
     *
     * <p>Two guards keep this from crying wolf, and both are about what
     * {@code DependencyResolver.knownVersions} actually returns.
     *
     * <p><b>A pre-release is never ABSENT.</b> That method filters out every version containing a
     * hyphen, so a milestone or release candidate could not appear in the list even when the
     * repository has it.
     *
     * <p><b>A version above everything known is never ABSENT either.</b> Metadata is a snapshot
     * from whenever a probe last downloaded it, so a target newer than the highest version on disk
     * says our copy is behind — not that the version does not exist. Only a target that sits
     * *below* the highest known release and is still missing is genuinely unaccounted for, which is
     * exactly the shape of a line whose later patches went commercial.
     */
    public static TargetAvailability of(String target, List<String> knownVersions) {
        if (target == null || target.isBlank() || knownVersions == null || knownVersions.isEmpty()) {
            return UNKNOWN;
        }
        if (knownVersions.contains(target)) {
            return KNOWN;
        }
        if (target.contains("-")) {
            return UNKNOWN;
        }
        String highest = knownVersions.stream().max(VersionOrder.INSTANCE).orElse(null);
        if (highest == null || VersionOrder.INSTANCE.compare(target, highest) > 0) {
            return UNKNOWN;
        }
        return ABSENT;
    }
}
