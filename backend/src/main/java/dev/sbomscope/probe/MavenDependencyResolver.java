package dev.sbomscope.probe;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import dev.sbomscope.logging.ActivityLogger;
import dev.sbomscope.scanner.VersionOrder;
import dev.sbomscope.settings.MavenToolSettings;

import static dev.sbomscope.settings.SettingsService.defaultProbeRepository;

/**
 * Drives the user's own {@code mvn} to answer "if I bump A to version V, what does C resolve
 * to?" — a question no SBOM or advisory database can answer, because it needs A's *resolved*
 * dependencies at a version nobody has installed yet.
 *
 * <p>A generated POM declaring the owning module's <em>whole</em> direct dependency set — every
 * one of them at its current version, except the ones under test, which take the candidate
 * version or range — is resolved with {@code dependency:tree} into an isolated local
 * repository, never the user's own {@code ~/.m2}. Declaring the whole set, not just the
 * dependency being bumped, is what lets Maven's own nearest-wins resolution decide which
 * declaration wins when a component is reached by more than one route — the question a
 * single-dependency POM cannot answer, because the SBOM itself does not record which
 * declaration was honoured. No settings are parsed and no credentials are read here: Maven
 * reads its own {@code settings.xml}, so mirrors and authentication come along for free and
 * this class never learns them.
 */
@Component
public class MavenDependencyResolver implements DependencyResolver {

    private static final Logger log = LoggerFactory.getLogger(MavenDependencyResolver.class);

    private static final Duration VERSION_TIMEOUT = Duration.ofSeconds(20);

    /** Generous: the first run downloads the plugin and its dependencies into an empty repo. */
    private static final Duration PLUGIN_CHECK_TIMEOUT = Duration.ofSeconds(120);

    // The goal itself, version and all, comes in on the ProbeContext — see
    // MavenToolSettings.dependencyTreeGoal() for why it is pinned and why that is configurable.

    private final ActivityLogger activityLog;

    /** Runs {@code mvn --version}, both to confirm the path works and to record what ran. */
    public String version(String executablePath) {
        MavenInvocation.Result result =
                MavenInvocation.run("--version", List.of(executablePath, "--version"), null, VERSION_TIMEOUT);
        if (result.startFailed()) {
            throw new MavenProbeException("Could not start mvn at " + executablePath + ": " + result.startError());
        }
        if (result.timedOut() || result.exitCode() != 0) {
            throw new MavenProbeException(
                    "That file did not respond to --version. " + result.lastMeaningfulLine());
        }
        // The banner line, not necessarily the first line: a JVM that prints something of its
        // own first — "Picked up JAVA_TOOL_OPTIONS", common where a corporate agent is
        // installed — would otherwise make a perfectly good Maven look like the wrong binary.
        // mvn.cmd writes CRLF on Windows, so the \r is stripped per line, not just at the ends.
        String banner = result.output().lines()
                .map(String::strip)
                .filter(line -> line.toLowerCase(Locale.ROOT).contains("apache maven"))
                .findFirst()
                .orElse(null);
        if (banner == null) {
            throw new MavenProbeException("That binary does not identify itself as Maven. It reported: "
                    + result.lastMeaningfulLine());
        }
        return banner;
    }

    MavenDependencyResolver(ActivityLogger activityLog) {
        this.activityLog = activityLog;
    }

    /**
     * Resolves and runs the plugins the probe drives, against a throwaway empty project.
     *
     * <p>{@link #version} proves the binary is Maven; it proves nothing about whether a probe
     * can work. Those are different questions with different answers: on a machine that cannot
     * reach a repository, {@code --version} succeeds and reports a perfectly good Maven while
     * every probe fails, because the isolated probe repository has no copy of
     * {@code maven-dependency-plugin} and no route to one. Reporting "Working" there is worse
     * than useless — it sends the reader looking for the problem everywhere except where it is.
     *
     * <p>Deliberately run against the <em>configured</em> goals and the <em>real</em> probe
     * repository, so a green result means the exact invocations a probe makes have been made
     * once and worked, not that something similar might.
     *
     * @return what was verified, for display
     * @throws MavenProbeException naming the plugin that could not be obtained
     */
    public String verifyProbePlugins(MavenToolSettings settings) {
        Path tempDir;
        try {
            tempDir = Files.createTempDirectory("sbomscope-plugin-check-");
        } catch (IOException e) {
            throw new MavenProbeException("Could not create a working directory: " + e.getMessage());
        }

        try {
            Files.writeString(tempDir.resolve("pom.xml"), EMPTY_PROJECT_POM);
            // The dependency plugin is what every probe runs; the help plugin only matters when
            // an SBOM has a workspace path, but checking it here costs one invocation and turns
            // a later silent "the probe ran isolated" into something known now.
            runPluginCheck("dependency plugin", settings.dependencyTreeGoal(), settings, tempDir,
                    "-DoutputFile=" + tempDir.resolve("tree.txt"), "-DoutputType=text");
            runPluginCheck("help plugin", settings.effectivePomGoal(), settings, tempDir,
                    "-Doutput=" + tempDir.resolve("effective.xml"));
            return "%s and %s resolve and run".formatted(
                    settings.dependencyTreeGoal(), settings.effectivePomGoal());
        } catch (IOException e) {
            throw new MavenProbeException("Could not write the check project: " + e.getMessage());
        } finally {
            deleteRecursively(tempDir);
        }
    }

    private void runPluginCheck(String label, String goal, MavenToolSettings settings, Path workingDirectory,
                                 String... extraArgs) {
        List<String> command = new ArrayList<>(List.of(
                settings.executablePath(), "-B", "-q", goal,
                "-Dmaven.repo.local=" + defaultProbeRepository()));
        command.addAll(List.of(extraArgs));
        if (settings.hasProfiles()) {
            command.add("-P" + settings.profiles().trim());
        }

        MavenInvocation.Result result = MavenInvocation.run("check " + label, command, workingDirectory, PLUGIN_CHECK_TIMEOUT);
        if (result.ok()) {
            return;
        }
        if (result.startFailed()) {
            throw new MavenProbeException("Could not start mvn: " + result.startError());
        }
        if (result.timedOut()) {
            throw new MavenProbeException(
                    "The %s did not resolve within %d seconds. If this machine reaches its repository "
                            .formatted(label, PLUGIN_CHECK_TIMEOUT.toSeconds())
                            + "through a slow mirror, the first fetch can be slow; try again.");
        }
        throw new MavenProbeException(
                ("Maven runs, but the %s (%s) could not be obtained. The probe resolves into its own "
                        + "repository (%s), never your ~/.m2, so it has to fetch this itself — on a "
                        + "machine with no route to a repository it cannot. Full output is in "
                        + "sbomscope.log. Maven said: %s")
                        .formatted(label, goal, defaultProbeRepository(), result.lastMeaningfulLine()));
    }

    /** No dependencies: the check is about the tooling, not about resolving anything. */
    private static final String EMPTY_PROJECT_POM = """
            <?xml version="1.0" encoding="UTF-8"?>
            <project xmlns="http://maven.apache.org/POM/4.0.0">
              <modelVersion>4.0.0</modelVersion>
              <groupId>dev.sbomscope.probe</groupId>
              <artifactId>plugin-check</artifactId>
              <version>0</version>
              <packaging>pom</packaging>
            </project>
            """;

    @Override
    public ProbeOutcome resolve(List<ModuleDependency> moduleDependencies, Map<MavenArtifact, String> overrides,
                                 MavenArtifact target, ProbeContext context) {
        Path tempDir;
        try {
            tempDir = Files.createTempDirectory("sbomscope-probe-");
        } catch (IOException e) {
            return ProbeOutcome.failed(ProbeFailureReason.OTHER,
                    "Could not create a working directory: " + e.getMessage());
        }

        try {
            Files.writeString(tempDir.resolve("pom.xml"), generatePom(moduleDependencies, overrides, context));
            Path treeOutput = tempDir.resolve("tree.txt");

            List<String> command = new ArrayList<>(List.of(
                    context.mvnExecutable(),
                    "-B", "-q",
                    context.dependencyTreeGoal(),
                    "-Dmaven.repo.local=" + context.isolatedRepository(),
                    "-DoutputFile=" + treeOutput,
                    "-DoutputType=text"));
            command.addAll(context.profileArgs());

            MavenInvocation.Result result = MavenInvocation.run(
                    "dependency:tree for " + describeOverrides(overrides), command, tempDir, context.timeout());
            ProbeOutcome outcome = outcomeFor(result, treeOutput, overrides, target);

            activityLog.record(ActivityLogger.Category.PROCESS, "MAVEN_PROBE",
                    outcome.resolved() ? "SUCCESS" : "FAILURE",
                    "%s → %s%s".formatted(describeOverrides(overrides),
                            outcome.resolved() ? describeResolved(outcome.resolvedVersions()) : "failed",
                            outcome.resolved() ? "" : ": " + outcome.detail()));
            return outcome;

        } catch (IOException e) {
            return ProbeOutcome.failed(ProbeFailureReason.OTHER, e.getMessage());
        } finally {
            deleteRecursively(tempDir);
        }
    }

    private ProbeOutcome outcomeFor(MavenInvocation.Result result, Path treeOutput,
                                     Map<MavenArtifact, String> overrides, MavenArtifact target) throws IOException {
        if (result.startFailed()) {
            return ProbeOutcome.failed(ProbeFailureReason.NOT_RUNNABLE,
                    "Could not start mvn at the configured path: " + result.startError());
        }
        if (result.timedOut()) {
            return ProbeOutcome.failed(ProbeFailureReason.TIMEOUT,
                    "mvn did not finish within the probe timeout.");
        }
        if (result.exitCode() != 0 || !Files.isRegularFile(treeOutput)) {
            return classifyFailure(result);
        }

        String tree = Files.readString(treeOutput);

        Map<MavenArtifact, String> resolvedVersions = new LinkedHashMap<>();
        for (MavenArtifact overridden : overrides.keySet()) {
            String resolvedVersion = findVersion(tree, overridden);
            if (resolvedVersion == null) {
                return ProbeOutcome.failed(ProbeFailureReason.NOT_FOUND,
                        "%s did not appear in the resolved tree.".formatted(
                                overridden.gav(overrides.get(overridden))));
            }
            resolvedVersions.put(overridden, resolvedVersion);
        }
        return ProbeOutcome.resolved(
                resolvedVersions, findVersion(tree, target), declaringDependencyOf(tree, target));
    }

    private String describeOverrides(Map<MavenArtifact, String> overrides) {
        return overrides.entrySet().stream()
                .map(entry -> entry.getKey().gav(entry.getValue()))
                .reduce((a, b) -> a + " + " + b)
                .orElse("(no overrides)");
    }

    private String describeResolved(Map<MavenArtifact, String> resolvedVersions) {
        return resolvedVersions.entrySet().stream()
                .map(entry -> entry.getKey().gav(entry.getValue()))
                .reduce((a, b) -> a + " + " + b)
                .orElse("(nothing overridden)");
    }

    /**
     * Maven caches this per remote repository — {@code maven-metadata-central.xml} for the
     * usual case, named after whatever repository id resolved it — never the bare
     * {@code maven-metadata.xml}, which is a merged file Maven builds in memory but does not
     * necessarily write to the local repo. Every {@code maven-metadata*.xml} is read and
     * merged, deliberately excluding the {@code .sha1}/{@code .md5} checksum siblings.
     *
     * <p>Pre-release versions are excluded. Maven's convention marks them with a {@code -}
     * qualifier ({@code 4.1.0-M1}, {@code 4.1.0-RC1}, {@code 2.0.0-SNAPSHOT}) — a real range
     * probe never happens to land on one, since ranges resolve to the highest matching
     * <em>release</em> by default, but a candidate probe constructed directly from this list
     * could, and naming a milestone as an upgrade target would be a wrong answer, not a stale
     * one.
     */
    @Override
    public List<String> knownVersions(MavenArtifact declaring, ProbeContext context) {
        Path directory = Path.of(context.isolatedRepository(),
                declaring.groupId().replace('.', '/'), declaring.artifactId());
        if (!Files.isDirectory(directory)) {
            return List.of();
        }

        Set<String> versions = new LinkedHashSet<>();
        try (var files = Files.list(directory)) {
            List<Path> metadataFiles = files
                    .filter(path -> {
                        String name = path.getFileName().toString();
                        return name.startsWith("maven-metadata") && name.endsWith(".xml");
                    })
                    .toList();
            for (Path metadataFile : metadataFiles) {
                versions.addAll(readVersions(metadataFile));
            }
        } catch (IOException e) {
            log.warn("Could not list {}", directory, e);
            return List.of();
        }

        List<String> sorted = new ArrayList<>(versions.stream().filter(version -> !version.contains("-")).toList());
        sorted.sort(VersionOrder.INSTANCE);
        return sorted;
    }

    private List<String> readVersions(Path metadataFile) {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document document = builder.parse(metadataFile.toFile());

            NodeList versionNodes = document.getElementsByTagName("version");
            List<String> versions = new ArrayList<>();
            for (int i = 0; i < versionNodes.getLength(); i++) {
                versions.add(versionNodes.item(i).getTextContent().strip());
            }
            return versions;
        } catch (Exception e) {
            log.warn("Could not read {}", metadataFile, e);
            return List.of();
        }
    }

    // --- POM generation ------------------------------------------------------------------

    /**
     * Declares every one of the module's direct dependencies, at its current version — except
     * those named in {@code overrides}, which take the candidate version or range instead. The
     * rest exist only so Maven's own nearest-wins resolution has the same competing
     * declarations the real build has; nothing about them is being asked.
     */
    private String generatePom(List<ModuleDependency> moduleDependencies, Map<MavenArtifact, String> overrides,
                                ProbeContext context) {
        StringBuilder xml = new StringBuilder();
        xml.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        xml.append("<project xmlns=\"http://maven.apache.org/POM/4.0.0\">\n");
        xml.append("  <modelVersion>4.0.0</modelVersion>\n");
        xml.append("  <groupId>dev.sbomscope.probe</groupId>\n");
        xml.append("  <artifactId>probe</artifactId>\n");
        xml.append("  <version>0</version>\n");
        xml.append("  <packaging>pom</packaging>\n");

        if (context.hasWorkspaceLiftIn()) {
            EffectivePomFragments lifted = context.liftedXml();
            if (lifted.repositoriesXml() != null) {
                xml.append(lifted.repositoriesXml()).append('\n');
            }
            if (lifted.dependencyManagementXml() != null) {
                xml.append(lifted.dependencyManagementXml()).append('\n');
            }
        }

        xml.append("  <dependencies>\n");
        for (ModuleDependency dependency : moduleDependencies) {
            String version = overrides.getOrDefault(dependency.artifact(), dependency.version());
            xml.append("    <dependency>\n");
            xml.append("      <groupId>").append(dependency.artifact().groupId()).append("</groupId>\n");
            xml.append("      <artifactId>").append(dependency.artifact().artifactId()).append("</artifactId>\n");
            xml.append("      <version>").append(version).append("</version>\n");
            xml.append("    </dependency>\n");
        }
        // An override naming an artifact the module does not itself declare (should not
        // happen, given the caller derives overrides from the same module's routes, but a
        // generated POM missing the one thing being asked about would fail silently rather
        // than loudly, so it is added defensively rather than assumed).
        for (Map.Entry<MavenArtifact, String> entry : overrides.entrySet()) {
            if (moduleDependencies.stream().noneMatch(d -> d.artifact().equals(entry.getKey()))) {
                xml.append("    <dependency>\n");
                xml.append("      <groupId>").append(entry.getKey().groupId()).append("</groupId>\n");
                xml.append("      <artifactId>").append(entry.getKey().artifactId()).append("</artifactId>\n");
                xml.append("      <version>").append(entry.getValue()).append("</version>\n");
                xml.append("    </dependency>\n");
            }
        }
        xml.append("  </dependencies>\n");
        xml.append("</project>\n");
        return xml.toString();
    }

    // --- dependency:tree parsing -----------------------------------------------------------

    /**
     * The generated POM declares exactly one dependency, so the resolved tree <em>is</em> its
     * whole subtree — no filtering by depth or branch is needed, only a scan for the artifact's
     * own line.
     */
    String findVersion(String tree, MavenArtifact artifact) {
        String prefix = artifact.groupId() + ":" + artifact.artifactId() + ":";
        for (String rawLine : tree.split("\n")) {
            String line = rawLine.replaceFirst("^[\\s|+\\\\-]*", "").strip();
            if (line.startsWith(prefix)) {
                String[] parts = line.split(":");
                if (parts.length >= 4) {
                    return parts[3];
                }
            }
        }
        return null;
    }

    /**
     * Which of the generated POM's own direct dependencies the artifact hangs under in the
     * resolved tree, as {@code group:artifact}.
     *
     * <p><b>This is the declaration Maven actually honoured</b>, and it is a different question
     * from which route is shortest in the SBOM — the one the search used to pick by. When a
     * component is reached through several direct dependencies, only the winning one can change
     * what it resolves to; bumping any other moves nothing, which is a result that reads as
     * "upstream has not fixed it" unless the panel can say otherwise.
     *
     * <p>It costs no extra invocation: {@code -DoutputType=text} already writes the tree to a
     * file this class reads, and <b>the indentation is the parent chain</b>. Maven writes three
     * characters per level ({@code "+- "}, {@code "\- "}, {@code "|  "}, {@code "   "}), so
     * depth is the width of that prefix over three, and the answer is the nearest line above the
     * artifact at depth 1. {@link #findVersion} scans the same file and throws all of this away,
     * which is why the question looked like it needed a second probe.
     *
     * @return null when the artifact is absent, is itself a direct dependency, or the tree is
     *         shaped in a way this cannot read — in every case the caller says less rather than
     *         guessing at a declaration
     */
    String declaringDependencyOf(String tree, MavenArtifact artifact) {
        String prefix = artifact.groupId() + ":" + artifact.artifactId() + ":";
        String[] lines = tree.split("\n");

        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];
            String stripped = line.replaceFirst("^[\\s|+\\\\-]*", "");
            if (!stripped.startsWith(prefix)) {
                continue;
            }
            int depth = (line.length() - stripped.length()) / 3;
            if (depth <= 1) {
                // Depth 0 is the generated project itself; depth 1 means the target *is* a
                // direct dependency, so nothing declares it on the reader's behalf.
                return null;
            }
            for (int j = i - 1; j >= 0; j--) {
                String candidate = lines[j];
                String candidateStripped = candidate.replaceFirst("^[\\s|+\\\\-]*", "");
                if (candidateStripped.isBlank()) {
                    continue;
                }
                if ((candidate.length() - candidateStripped.length()) / 3 == 1) {
                    String[] parts = candidateStripped.strip().split(":");
                    return parts.length >= 2 ? parts[0] + ":" + parts[1] : null;
                }
            }
            return null;
        }
        return null;
    }

    private ProbeOutcome classifyFailure(MavenInvocation.Result result) {
        String output = result.output().toLowerCase(Locale.ROOT);
        String detail = result.lastMeaningfulLine();

        // A plugin that cannot be resolved is not a fact about the component being probed —
        // it means the isolated repository has no copy and no way to get one, which on a
        // machine with no route to a repository is a setup problem, not a dependency problem.
        // Classified apart so the panel stops blaming the artifact for it.
        if (output.contains("no plugin found for prefix")
                || output.contains("could not resolve plugin")
                || output.contains("plugin org.apache.maven.plugins")) {
            return ProbeOutcome.failed(ProbeFailureReason.PLUGIN_UNAVAILABLE, detail);
        }
        if (output.contains("could not find artifact")
                || output.contains("could not resolve dependencies")
                || output.contains("could not transfer artifact")
                || output.contains("no versions available")) {
            return ProbeOutcome.failed(ProbeFailureReason.NOT_FOUND, detail);
        }
        if (output.contains("401") || output.contains("403")
                || output.contains("not authorized") || output.contains("authentication")) {
            return ProbeOutcome.failed(ProbeFailureReason.AUTHENTICATION, detail);
        }
        return ProbeOutcome.failed(ProbeFailureReason.OTHER, detail);
    }

    private void deleteRecursively(Path directory) {
        try (var paths = Files.walk(directory)) {
            paths.sorted(Comparator.reverseOrder()).forEach(path -> {
                try {
                    Files.delete(path);
                } catch (IOException e) {
                    log.debug("Could not delete probe scratch file {}", path, e);
                }
            });
        } catch (IOException e) {
            log.debug("Could not clean up probe directory {}", directory, e);
        }
    }
}
