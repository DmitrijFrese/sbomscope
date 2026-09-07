package dev.sbomscope.probe;

import dev.sbomscope.logging.ActivityLogger;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Whether a version SBOMscope is about to recommend can actually be obtained.
 *
 * <p>OSV names the version an advisory was fixed in, and that version is real — but real is not the
 * same as reachable. Once an open-source line goes end-of-life, several vendors publish their
 * remaining patches to a commercial repository instead of the public one: measured 2026-09-07,
 * {@code spring-security-crypto:6.1.9} resolves from Maven Central and {@code 6.1.14}, the fix
 * named for CVE-2024-22228, does not. Writing that version into a pom does not merely fail to help,
 * it stops the build resolving.
 *
 * <p><b>This asks whether an artifact can be obtained, not what licence or support tier it carries.</b>
 * Encoding which vendors sell which support window would be judgment data with no source, and would
 * be wrong the first time a policy changed — constraint 6 keeps that kind of field out of this
 * product. Absence is a fact, it is measurable through the tooling the user already has, and it
 * covers every reason a version might be out of reach: commercial-only, yanked, never published to
 * their mirror, or simply mistyped.
 *
 * <p>Like the rest of this package it asks through the user's own {@code mvn}, in the isolated
 * probe repository, and writes to the activity log. Constraint 1 category 3: the question "does
 * {@code com.acme:billing:2.1} exist" names an artifact, so it is delegated to their build tool
 * rather than asked by us.
 */
public class ArtifactAvailability {

    /**
     * <p><b>{@code UNKNOWN} is not a soft {@code UNAVAILABLE}.</b> Maven says
     * <em>"was not found"</em> when a repository answered and had nothing, and
     * <em>"Could not transfer"</em> when it could not ask at all. Reporting the second as absent
     * would condemn a perfectly good version because a mirror blipped or a proxy refused, and the
     * reader would go looking for a replacement that does not need finding.
     */
    public enum Availability { AVAILABLE, UNAVAILABLE, UNKNOWN }

    /** @param detail why, in a sentence fit for the screen. Null when the answer is AVAILABLE. */
    public record Result(Availability availability, String detail) {

        static Result available() {
            return new Result(Availability.AVAILABLE, null);
        }
    }

    /**
     * Markers that mean the repository answered and had nothing — as opposed to not answering.
     *
     * <p>Substrings rather than one pattern because Maven words it differently depending on
     * whether the miss was fresh or replayed from a cached {@code .lastUpdated} marker.
     */
    private static final List<String> DEFINITELY_ABSENT = List.of(
            "was not found",
            "(absent)",
            "could not find artifact");

    private final ActivityLogger activityLog;

    public ArtifactAvailability(ActivityLogger activityLog) {
        this.activityLog = activityLog;
    }

    /**
     * Asks the user's Maven whether one exact version can be resolved.
     *
     * <p>Only the POM is requested, and without transitives: an artifact whose line has moved
     * behind a paywall has no POM in the public repository either, so fetching the jar as well
     * would cost bandwidth to learn the same thing.
     */
    public Result check(MavenArtifact artifact, String version, ProbeContext context) {
        if (version == null || version.isBlank()) {
            return new Result(Availability.UNKNOWN, "No version was given to check.");
        }

        Path workingDirectory;
        try {
            workingDirectory = Files.createTempDirectory("sbomscope-availability-");
        } catch (IOException e) {
            return new Result(Availability.UNKNOWN,
                    "Could not create a working directory: " + e.getMessage());
        }

        String coordinates = artifact.groupId() + ":" + artifact.artifactId() + ":" + version;
        try {
            List<String> command = new ArrayList<>(List.of(
                    context.mvnExecutable(),
                    "-B",
                    "-Dmaven.repo.local=" + context.isolatedRepository(),
                    dependencyGetGoal(context.dependencyTreeGoal()),
                    "-Dartifact=" + coordinates + ":pom",
                    "-Dtransitive=false"));
            if (context.profiles() != null && !context.profiles().isBlank()) {
                command.add("-P" + context.profiles());
            }

            activityLog.record(ActivityLogger.Category.PROCESS, "ARTIFACT_AVAILABILITY",
                    "Asking your configured mvn whether " + coordinates + " can be resolved");

            MavenInvocation.Result result =
                    MavenInvocation.run("availability " + coordinates, command, workingDirectory,
                            context.timeout());
            if (result.ok()) {
                activityLog.record(ActivityLogger.Category.PROCESS, "ARTIFACT_AVAILABILITY",
                        "AVAILABLE", coordinates);
                return Result.available();
            }

            if (classify(result) == Availability.UNAVAILABLE) {
                String detail = version + " is not available in the repositories your Maven is "
                        + "configured with. A fix version an advisory names can still be published "
                        + "only to a commercial repository once its line is end-of-life.";
                activityLog.record(ActivityLogger.Category.PROCESS, "ARTIFACT_AVAILABILITY",
                        "UNAVAILABLE", coordinates);
                return new Result(Availability.UNAVAILABLE, detail);
            }

            activityLog.record(ActivityLogger.Category.PROCESS, "ARTIFACT_AVAILABILITY",
                    "UNKNOWN", coordinates);
            return new Result(Availability.UNKNOWN,
                    "Could not tell whether " + version + " is available. " + result.failureSummary());
        } finally {
            deleteQuietly(workingDirectory);
        }
    }

    /**
     * The one reading of what a failed resolution means, so the test asserts the rule rather than
     * a copy of it.
     *
     * <p>Never {@code AVAILABLE}: a run that failed proves nothing about the artifact existing.
     * A start failure or a timeout is always {@code UNKNOWN} — Maven never got as far as asking.
     */
    static Availability classify(MavenInvocation.Result result) {
        if (result.ok()) {
            return Availability.AVAILABLE;
        }
        if (result.startFailed() || result.timedOut()) {
            return Availability.UNKNOWN;
        }
        String haystack = ((result.output() == null ? "" : result.output()) + " "
                + (result.startError() == null ? "" : result.startError())).toLowerCase(Locale.ROOT);
        return DEFINITELY_ABSENT.stream().anyMatch(haystack::contains)
                ? Availability.UNAVAILABLE
                : Availability.UNKNOWN;
    }

    /**
     * {@code dependency:get} is a goal of the same plugin as {@code dependency:tree}, so the version
     * the user pinned for one is the version to use for the other — the same derivation
     * {@link LinkageClasspathResolver} makes, and for the same reason: a second Settings field for a
     * choice nobody would make differently is worse than deriving it.
     */
    static String dependencyGetGoal(String dependencyTreeGoal) {
        String[] parts = dependencyTreeGoal == null ? new String[0] : dependencyTreeGoal.split(":");
        if (parts.length != 4 || !parts[3].equals("tree")) {
            throw new IllegalArgumentException(
                    "Expected a fully qualified group:artifact:version:tree goal, got: " + dependencyTreeGoal);
        }
        return parts[0] + ":" + parts[1] + ":" + parts[2] + ":get";
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
