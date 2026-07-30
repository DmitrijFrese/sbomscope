package dev.sbomscope.probe;

import java.util.List;
import java.util.Map;

/**
 * Resolves a module's full direct dependency set, with some of them overridden to a candidate
 * version or range, and reports what a target component resolves to within that tree.
 *
 * <p>Kept behind an interface per the standing convention on engine integrations: Maven is the
 * only implementation today, but Gradle and npm are the same shape with a different probe
 * script, and call sites should not care which one answers.
 */
public interface DependencyResolver {

    /**
     * @param moduleDependencies the owning module's full direct dependency set, each at its
     *                           currently-declared version — the fixed context a candidate is
     *                           evaluated within. Maven's nearest-wins resolution depends on
     *                           all of them, not only the one route reaching the target
     * @param overrides          which of those dependencies to resolve at a different version
     *                           (exact, e.g. {@code 4.2.0}, or a range, e.g.
     *                           {@code [4.1.0,4.2.0)}) instead of their current one — one entry
     *                           for a single-ancestor bump, several for combination testing
     * @param target             the vulnerable component being watched for inside the resolved
     *                           tree
     */
    ProbeOutcome resolve(List<ModuleDependency> moduleDependencies, Map<MavenArtifact, String> overrides,
                         MavenArtifact target, ProbeContext context);

    /**
     * Every version {@code declaring} has released, read back from the local repository's own
     * metadata after a range probe has caused Maven to download it — never a direct query of
     * our own. Pre-release versions (milestones, release candidates, snapshots) are excluded:
     * naming one as an upgrade target would be a wrong answer, not merely a stale one.
     *
     * @return empty when the metadata is not on disk yet, which is not the same as "no
     *         versions exist"
     */
    List<String> knownVersions(MavenArtifact declaring, ProbeContext context);
}
