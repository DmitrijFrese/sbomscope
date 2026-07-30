package dev.sbomscope.probe;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
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
import java.util.concurrent.TimeUnit;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import dev.sbomscope.logging.ActivityLogger;
import dev.sbomscope.scanner.VersionOrder;

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

    private final ActivityLogger activityLog;

    /** Runs {@code mvn --version}, both to confirm the path works and to record what ran. */
    public String version(String executablePath) {
        ProcessResult result = run(List.of(executablePath, "--version"), null, VERSION_TIMEOUT);
        if (result.startFailed()) {
            throw new MavenProbeException("Could not start mvn at " + executablePath + ": " + result.stderr());
        }
        if (result.timedOut() || result.exitCode() != 0) {
            throw new MavenProbeException(
                    "That file did not respond to --version. " + lastMeaningfulLine(result));
        }
        // mvn.cmd writes CRLF on Windows; strip() on the whole string only trims the ends,
        // not the line boundary the split introduces, so the \r must be stripped per line too.
        String firstLine = result.stdout().isBlank() ? "" : result.stdout().strip().split("\n")[0].strip();
        if (!firstLine.toLowerCase(Locale.ROOT).contains("apache maven")) {
            throw new MavenProbeException("That binary does not identify itself as Maven. It reported: " + firstLine);
        }
        return firstLine;
    }

    MavenDependencyResolver(ActivityLogger activityLog) {
        this.activityLog = activityLog;
    }

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
                    "dependency:tree",
                    "-Dmaven.repo.local=" + context.isolatedRepository(),
                    "-DoutputFile=" + treeOutput,
                    "-DoutputType=text"));
            command.addAll(context.profileArgs());

            ProcessResult result = run(command, tempDir, context.timeout());
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

    private ProbeOutcome outcomeFor(ProcessResult result, Path treeOutput, Map<MavenArtifact, String> overrides,
                                     MavenArtifact target) throws IOException {
        if (result.startFailed()) {
            return ProbeOutcome.failed(ProbeFailureReason.NOT_RUNNABLE,
                    "Could not start mvn at the configured path: " + result.stderr());
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
        return ProbeOutcome.resolved(resolvedVersions, findVersion(tree, target));
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

    private ProbeOutcome classifyFailure(ProcessResult result) {
        String combined = (result.stdout() + "\n" + result.stderr()).toLowerCase(Locale.ROOT);
        String detail = lastMeaningfulLine(result);

        if (combined.contains("could not find artifact")
                || combined.contains("could not resolve dependencies")
                || combined.contains("could not transfer artifact")
                || combined.contains("no versions available")) {
            return ProbeOutcome.failed(ProbeFailureReason.NOT_FOUND, detail);
        }
        if (combined.contains("401") || combined.contains("403")
                || combined.contains("not authorized") || combined.contains("authentication")) {
            return ProbeOutcome.failed(ProbeFailureReason.AUTHENTICATION, detail);
        }
        return ProbeOutcome.failed(ProbeFailureReason.OTHER, detail);
    }

    /** The last non-blank line of either stream — Maven's own [ERROR] summary comes last. */
    private String lastMeaningfulLine(ProcessResult result) {
        String combined = (result.stdout() + "\n" + result.stderr()).strip();
        if (combined.isEmpty()) {
            return "mvn exited " + result.exitCode() + " with no output.";
        }
        String[] lines = combined.split("\n");
        for (int i = lines.length - 1; i >= 0; i--) {
            if (!lines[i].isBlank()) {
                return lines[i].strip();
            }
        }
        return combined;
    }

    // --- process invocation ----------------------------------------------------------------

    private record ProcessResult(
            boolean startFailed, boolean timedOut, int exitCode, String stdout, String stderr) {}

    private ProcessResult run(List<String> command, Path workingDirectory, Duration timeout) {
        ProcessBuilder builder = new ProcessBuilder(command);
        if (workingDirectory != null) {
            builder.directory(workingDirectory.toFile());
        }

        Process process;
        try {
            process = builder.start();
        } catch (IOException e) {
            return new ProcessResult(true, false, -1, "", e.getMessage());
        }

        try {
            String stdout = read(process.getInputStream());
            String stderr = read(process.getErrorStream());

            if (!process.waitFor(timeout.toMillis(), TimeUnit.MILLISECONDS)) {
                process.destroyForcibly();
                return new ProcessResult(false, true, -1, stdout, stderr);
            }
            return new ProcessResult(false, false, process.exitValue(), stdout, stderr);

        } catch (IOException e) {
            process.destroyForcibly();
            return new ProcessResult(false, false, -1, "", "Failed while reading mvn output: " + e.getMessage());
        } catch (InterruptedException e) {
            process.destroyForcibly();
            Thread.currentThread().interrupt();
            return new ProcessResult(false, false, -1, "", "Interrupted while waiting for mvn.");
        }
    }

    private String read(InputStream stream) throws IOException {
        try (stream) {
            return new String(stream.readAllBytes(), StandardCharsets.UTF_8);
        }
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
