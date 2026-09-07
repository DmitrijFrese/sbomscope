package dev.sbomscope.probe;

import dev.sbomscope.logging.ActivityLogger;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;

import java.util.List;
import java.util.Map;

/**
 * Resolves a dependency set to the jar files it actually puts on a classpath, for the linkage
 * check (B30 portion D).
 *
 * <p>This is the only part of the linkage feature that starts a process or can reach the network,
 * and it does so under the same rules as the rest of the probe package: the user's own configured
 * {@code mvn}, never a registry client of ours (constraint 1 category 3); the isolated
 * {@code ~/.sbomscope/probe-repo}, never their {@code ~/.m2}; and an activity-log entry every
 * time, because a process started on somebody's machine should be visible to them.
 *
 * <p>It answers for a <em>proposed</em> dependency set as readily as the current one — the
 * overrides map is how the "after" side of a differential is asked for — and that is the whole
 * reason it exists rather than reading a classpath the build already produced.
 */
public class LinkageClasspathResolver {

    /**
     * @param jars     the resolved compile classpath, in Maven's own order
     * @param complete false when Maven could not resolve the set — the caller must then report
     *                 the check as unchecked rather than drawing a conclusion from a partial
     *                 classpath, which is exactly how a linkage checker invents findings
     * @param detail   why an incomplete answer is incomplete, in a sentence fit for the UI
     */
    public record ResolvedClasspath(List<Path> jars, boolean complete, String detail) {

        public ResolvedClasspath {
            jars = List.copyOf(jars);
        }

        static ResolvedClasspath incomplete(String detail) {
            return new ResolvedClasspath(List.of(), false, detail);
        }
    }

    private final ActivityLogger activityLog;

    public LinkageClasspathResolver(ActivityLogger activityLog) {
        this.activityLog = activityLog;
    }

    /**
     * @param directDependencies the module's full direct dependency set at its current versions,
     *                           for the same reason {@link DependencyResolver} needs it: Maven's
     *                           nearest-wins resolution depends on all of them
     * @param overrides          which of those to resolve at a different version instead. Empty
     *                           for the "before" side of a differential; the plan's edits for
     *                           the "after" side
     */
    public ResolvedClasspath resolve(List<ModuleDependency> directDependencies,
                                     Map<MavenArtifact, String> overrides,
                                     ProbeContext context) {
        if (directDependencies.isEmpty() && overrides.isEmpty()) {
            return ResolvedClasspath.incomplete("There were no dependencies to resolve.");
        }

        Path workingDirectory;
        try {
            workingDirectory = Files.createTempDirectory("sbomscope-linkage-");
        } catch (IOException e) {
            return ResolvedClasspath.incomplete("Could not create a working directory: " + e.getMessage());
        }

        try {
            Path classpathFile = workingDirectory.resolve("classpath.txt");
            Files.writeString(workingDirectory.resolve("pom.xml"),
                    MavenDependencyResolver.generatePom(directDependencies, overrides, context));

            List<String> command = new ArrayList<>(List.of(
                    context.mvnExecutable(),
                    "-B",
                    "-Dmaven.repo.local=" + context.isolatedRepository(),
                    buildClasspathGoal(context.dependencyTreeGoal()),
                    "-Dmdep.outputFile=" + classpathFile,
                    // The linkage check reads what the application runs against, so test-only
                    // dependencies are not part of the question.
                    "-Dmdep.includeScope=runtime"));
            if (context.profiles() != null && !context.profiles().isBlank()) {
                command.add("-P" + context.profiles());
            }

            String description = "linkage classpath (" + directDependencies.size() + " direct, "
                    + overrides.size() + " overridden)";
            activityLog.record(ActivityLogger.Category.PROCESS, "LINKAGE_CLASSPATH",
                    "Resolving a classpath for the linkage check through your configured mvn: "
                            + description);

            MavenInvocation.Result result =
                    MavenInvocation.run(description, command, workingDirectory, context.timeout());
            if (!result.ok()) {
                String reason = failureReason(result);
                activityLog.record(ActivityLogger.Category.PROCESS, "LINKAGE_CLASSPATH", "FAILED", reason);
                return ResolvedClasspath.incomplete(reason);
            }
            if (!Files.exists(classpathFile)) {
                String reason = "Maven reported success but wrote no classpath file.";
                activityLog.record(ActivityLogger.Category.PROCESS, "LINKAGE_CLASSPATH", "FAILED", reason);
                return ResolvedClasspath.incomplete(reason);
            }

            List<Path> jars = parseClasspath(Files.readString(classpathFile));
            if (jars.isEmpty()) {
                // A resolver that returns nothing is a tooling failure, never an empty classpath
                // that happens to be fine — the same rule the differential applies to itself.
                String reason = "Maven resolved no jars for this dependency set.";
                activityLog.record(ActivityLogger.Category.PROCESS, "LINKAGE_CLASSPATH", "FAILED", reason);
                return ResolvedClasspath.incomplete(reason);
            }
            activityLog.record(ActivityLogger.Category.PROCESS, "LINKAGE_CLASSPATH", "OK",
                    "Resolved " + jars.size() + " jars for " + description);
            return new ResolvedClasspath(jars, true, null);
        } catch (IOException e) {
            return ResolvedClasspath.incomplete("Could not read the resolved classpath: " + e.getMessage());
        } finally {
            deleteQuietly(workingDirectory);
        }
    }

    /**
     * {@code build-classpath} and {@code tree} are goals of the same plugin, so the version the
     * user pinned for one is the version to use for the other. Deriving it keeps a second
     * user-facing setting out of Settings for a choice nobody would make differently.
     */
    static String buildClasspathGoal(String dependencyTreeGoal) {
        // Fully qualified means group:artifact:version:goal — four parts. The bare
        // "dependency:tree" prefix also ends in ":tree" and would pass a looser check, which is
        // precisely the case MavenToolSettings pins a version to avoid: a prefix lets Maven
        // choose the plugin version from metadata, so the goal we run stops being the one the
        // user configured.
        String[] parts = dependencyTreeGoal == null ? new String[0] : dependencyTreeGoal.split(":");
        if (parts.length != 4 || !parts[3].equals("tree")) {
            throw new IllegalArgumentException(
                    "Expected a fully qualified group:artifact:version:tree goal, got: " + dependencyTreeGoal);
        }
        return parts[0] + ":" + parts[1] + ":" + parts[2] + ":build-classpath";
    }

    /**
     * Maven writes the classpath with {@link java.io.File#pathSeparator}, and it is split on
     * exactly that.
     *
     * <p>Splitting on {@code [;:]} instead would be wrong on Windows, where it tears
     * {@code C:\repo\x.jar} in half at the drive letter and yields a path that exists nowhere.
     * The separator is the platform's because the Maven that wrote the file ran on this machine.
     *
     * <p>Entries that are not jars are dropped rather than trusted — a directory entry is a
     * reactor module, which a generated single-project POM cannot produce but which costs
     * nothing to ignore.
     */
    static List<Path> parseClasspath(String written) {
        List<Path> jars = new ArrayList<>();
        for (String entry : written.trim().split(java.util.regex.Pattern.quote(java.io.File.pathSeparator))) {
            String trimmed = entry.trim();
            if (trimmed.toLowerCase(java.util.Locale.ROOT).endsWith(".jar")) {
                jars.add(Path.of(trimmed));
            }
        }
        return jars;
    }

    /**
     * Says what actually went wrong, rather than that something did.
     *
     * <p>This quoted only the exit code until 2026-09-07, when a check run against a real
     * workspace reported <em>"Maven exited with 1 while resolving the classpath"</em> for a
     * failure whose captured output said {@code PKIX path building failed} — a diagnosable
     * problem presented undiagnosably. {@code Result.failureSummary()} is the existing reading of
     * a failed Maven run, already written to skip the four lines of advice Maven ends with; a
     * second reading here was the duplication this repository's conventions warn about.
     */
    private static String failureReason(MavenInvocation.Result result) {
        if (result.startFailed()) {
            return "Could not start your configured mvn: " + result.startError();
        }
        if (result.timedOut()) {
            return "Resolving the classpath timed out.";
        }
        return "Maven could not resolve the classpath. " + result.failureSummary();
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
