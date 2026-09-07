package dev.sbomscope.probe;

import dev.sbomscope.logging.ActivityLogger;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Puts one artifact's release metadata into the probe repository, so the free availability check
 * has something to read.
 *
 * <p>{@link dev.sbomscope.bump.TargetAvailability} costs nothing because it reads
 * {@code maven-metadata*.xml} that is already on disk — which makes coverage its whole limitation.
 * Nothing had been putting those files there on purpose: the only thing that primed them was the
 * feasibility range probe in {@code BumpProbeService}, as a side effect of looking for an upgrade.
 *
 * <p><b>{@code dependency:get} of a concrete version does not write metadata.</b> Measured
 * 2026-09-07 on a fresh local repository, asking for {@code spring-security-crypto:6.3.8:pom}
 * leaves the POM, its checksum and {@code _remote.repositories}, and no metadata anywhere. The
 * {@code RELEASE} metaversion does: Maven cannot resolve it without asking each repository for the
 * version list, and it writes that list down — {@code maven-metadata-central.xml}, 9.6 KB and 267
 * versions for that artifact, which is exactly the file {@code knownVersions} reads.
 *
 * <h2>One coordinate per invocation</h2>
 *
 * <p>Not a concession to simplicity. A synthetic POM naming many coordinates resolves atomically,
 * so one unreachable supplier artifact takes down every row with it — the failure this project has
 * repeatedly hit on real workspaces. Measured back to back in one repository, a fabricated
 * {@code com.acme.internal:billing-core} fails and {@code com.squareup.okio:okio} immediately after
 * it succeeds and writes its metadata. A coordinate that fails, fails alone, so there is no partial
 * batch to rebuild and no "middle" to fail in.
 *
 * <p>The price is a Maven startup each: measured warm, five real coordinates took 5120, 5411, 4976,
 * 5264 and 5029 ms. That is JVM and Maven startup rather than the payload, and it is why callers
 * prime the rows of a plan and never every component of a document.
 *
 * <h2>The POM carries repositories and nothing else</h2>
 *
 * <p>A supplier's Nexus is usually declared in the project rather than in {@code settings.xml}, and
 * {@code dependency:get} honours a project's {@code <repositories>} — measured, Maven asks
 * {@code central} and then the lifted repository for the metadata. So the generated POM exists only
 * to carry {@link EffectivePomFragments#repositoriesXml()}. It declares <b>no dependencies</b>,
 * which is what keeps the isolation above true: there is nothing in it that can fail to resolve.
 *
 * <p>Constraint 1 category 3 like the rest of this package: the question names an artifact, so the
 * user's own {@code mvn} is asked rather than a repository queried directly. A plain HTTPS GET of
 * the same file would be roughly a hundred times faster; it is their mirrors, credentials and
 * supplier repositories that make the answer right, so the cost is accepted rather than avoided.
 */
public class MetadataPrimer {

    /**
     * @param primed whether metadata for the artifact is on disk now — read from the filesystem
     *               after the run rather than inferred from the exit code, because a repository
     *               that answers while another is unreachable still fails the build and still
     *               leaves a usable version list behind
     * @param detail why not, in a sentence fit for the screen; null when {@code primed}
     */
    public record Result(boolean primed, String detail) {

        /** The only shape a success takes: on disk, nothing to explain. */
        static final Result PRIMED = new Result(true, null);
    }

    private final ActivityLogger activityLog;

    public MetadataPrimer(ActivityLogger activityLog) {
        this.activityLog = activityLog;
    }

    /**
     * Fetches the version list for one artifact into the isolated probe repository.
     *
     * <p>Returns immediately when the metadata is already there. Refreshing it would cost a Maven
     * run to learn that a list which only changes when a release is cut has probably not changed,
     * and {@code TargetAvailability} is already built to treat a target above everything on disk as
     * "our copy is behind" rather than as an absence.
     */
    public Result prime(MavenArtifact artifact, ProbeContext context) {
        if (artifact == null) {
            return new Result(false, "No artifact was given to prime.");
        }
        if (hasMetadata(artifact, context)) {
            return Result.PRIMED;
        }

        Path workingDirectory;
        try {
            workingDirectory = Files.createTempDirectory("sbomscope-metadata-");
            Files.writeString(workingDirectory.resolve("pom.xml"), repositoriesOnlyPom(context),
                    StandardCharsets.UTF_8);
        } catch (IOException e) {
            return new Result(false, "Could not prepare a working directory: " + e.getMessage());
        }

        String coordinates = artifact.groupId() + ":" + artifact.artifactId();
        try {
            List<String> command = new ArrayList<>(List.of(
                    context.mvnExecutable(),
                    "-B",
                    "-Dmaven.repo.local=" + context.isolatedRepository(),
                    ArtifactAvailability.dependencyGetGoal(context.dependencyTreeGoal()),
                    "-Dartifact=" + coordinates + ":RELEASE:pom",
                    "-Dtransitive=false"));
            command.addAll(context.profileArgs());

            activityLog.record(ActivityLogger.Category.PROCESS, "METADATA_PRIME",
                    "Asking your configured mvn for the released versions of " + coordinates);

            MavenInvocation.Result result = MavenInvocation.run("metadata " + coordinates, command,
                    workingDirectory, context.timeout());

            // Deliberately the filesystem and not result.ok(). Maven fails the build when any
            // configured repository cannot be reached, even though the one that answered has
            // already written a perfectly usable version list.
            if (hasMetadata(artifact, context)) {
                activityLog.record(ActivityLogger.Category.PROCESS, "METADATA_PRIME",
                        "PRIMED", coordinates);
                return Result.PRIMED;
            }

            activityLog.record(ActivityLogger.Category.PROCESS, "METADATA_PRIME",
                    "NOT PRIMED", coordinates);
            return new Result(false, "Could not fetch the released versions of " + coordinates
                    + ". " + result.failureSummary());
        } finally {
            deleteQuietly(workingDirectory);
        }
    }

    /**
     * Whether the probe repository already holds a version list for this artifact.
     *
     * <p>The same files {@code MavenDependencyResolver.knownVersions} reads, and named the same
     * way: Maven writes {@code maven-metadata-<repository id>.xml}, never the bare
     * {@code maven-metadata.xml}, which it merges in memory. Checksums are excluded — a
     * {@code .sha1} beside nothing would be a lie about coverage.
     */
    public boolean hasMetadata(MavenArtifact artifact, ProbeContext context) {
        Path directory = metadataDirectory(artifact, context);
        if (!Files.isDirectory(directory)) {
            return false;
        }
        try (var files = Files.list(directory)) {
            return files.anyMatch(path -> isMetadataFile(path.getFileName().toString()));
        } catch (IOException e) {
            return false;
        }
    }

    static boolean isMetadataFile(String fileName) {
        return fileName.startsWith("maven-metadata") && fileName.endsWith(".xml");
    }

    static Path metadataDirectory(MavenArtifact artifact, ProbeContext context) {
        return Path.of(context.isolatedRepository(),
                artifact.groupId().replace('.', '/'), artifact.artifactId());
    }

    /**
     * A project whose only content is the workspace's repositories.
     *
     * <p>{@code <packaging>pom</packaging>} so Maven never looks for sources, and no
     * {@code <dependencies>} element at all rather than an empty one — there is nothing to declare,
     * and an empty element invites someone to fill it.
     */
    static String repositoriesOnlyPom(ProbeContext context) {
        StringBuilder xml = new StringBuilder();
        xml.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        xml.append("<project xmlns=\"http://maven.apache.org/POM/4.0.0\">\n");
        xml.append("  <modelVersion>4.0.0</modelVersion>\n");
        xml.append("  <groupId>dev.sbomscope.probe</groupId>\n");
        xml.append("  <artifactId>metadata-probe</artifactId>\n");
        xml.append("  <version>0</version>\n");
        xml.append("  <packaging>pom</packaging>\n");
        if (context.hasWorkspaceLiftIn() && context.liftedXml().repositoriesXml() != null) {
            xml.append(context.liftedXml().repositoriesXml()).append('\n');
        }
        xml.append("</project>\n");
        return xml.toString();
    }

    private static void deleteQuietly(Path directory) {
        try (var paths = Files.walk(directory)) {
            for (Path path : paths.sorted((left, right) -> right.getNameCount() - left.getNameCount()).toList()) {
                Files.deleteIfExists(path);
            }
        } catch (IOException ignored) {
            // A leftover temp directory is untidy, not a failure worth surfacing.
        }
    }
}
