package dev.sbomscope.bump;

import static dev.sbomscope.settings.SettingsService.defaultProbeRepository;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import dev.sbomscope.bump.PomScanner.PropertyDefinition;
import dev.sbomscope.bump.PomScanner.RawDependency;
import dev.sbomscope.bump.PomWorkspace.ScannedPom;
import dev.sbomscope.bump.PomWorkspace.WorkspaceScan;
import dev.sbomscope.linkage.ClassMemberIndex;
import dev.sbomscope.linkage.LinkageDiff;
import dev.sbomscope.linkage.LinkageDiffer;
import dev.sbomscope.linkage.LinkageVerdict;
import dev.sbomscope.linkage.MemberResolver;
import dev.sbomscope.linkage.PlatformClasses;
import dev.sbomscope.logging.ActivityLogger;
import dev.sbomscope.probe.EffectivePomCache;
import dev.sbomscope.probe.EffectivePomFragments;
import dev.sbomscope.probe.LinkageClasspathResolver;
import dev.sbomscope.probe.MavenArtifact;
import dev.sbomscope.probe.ModuleDependency;
import dev.sbomscope.probe.ProbeContext;
import dev.sbomscope.scanner.VersionOrder;
import dev.sbomscope.settings.MavenToolSettings;
import dev.sbomscope.settings.SettingsService;

/** Assembles the current and selected Maven dependency sets for the linkage differential. */
@Service
public class LinkageCheckService {

    private static final Duration CHECK_TIMEOUT = Duration.ofSeconds(60);

    private final PomWorkspace workspaces;
    private final LinkageClasspathResolver classpaths;
    private final EffectivePomCache effectivePoms;
    private final SettingsService settings;

    @Autowired
    LinkageCheckService(EffectivePomCache effectivePoms, SettingsService settings,
                        ActivityLogger activityLog) {
        this(new PomWorkspace(), new LinkageClasspathResolver(activityLog), effectivePoms, settings);
    }

    public LinkageCheckService(PomWorkspace workspaces, LinkageClasspathResolver classpaths,
                               EffectivePomCache effectivePoms, SettingsService settings) {
        this.workspaces = workspaces;
        this.classpaths = classpaths;
        this.effectivePoms = effectivePoms;
        this.settings = settings;
    }

    /**
     * Checks whether the selected Maven version edits introduce member references that no longer
     * resolve. Structural and non-Maven edits stay explicit omissions rather than approximations.
     */
    public LinkageCheck check(BumpPlan plan, List<BumpEdit> edits) {
        List<String> notes = new ArrayList<>();
        Map<MavenArtifact, String> overrides = overrides(plan.rows(), edits, notes);
        if (overrides.isEmpty()) {
            notes.add("There were no Maven dependency edits to check.");
            return unchecked(notes);
        }

        WorkspaceScan workspace = workspaces.discover(Path.of(plan.workspace()));
        List<ModuleDependency> current = currentDependencies(workspace, notes);
        MavenToolSettings maven = settings.mavenSettings();
        ProbeContext context = context(plan.workspace(), maven, notes);

        LinkageClasspathResolver.ResolvedClasspath before = classpaths.resolve(current, Map.of(), context);
        if (!before.complete()) {
            notes.add(before.detail());
            return unchecked(notes);
        }
        LinkageClasspathResolver.ResolvedClasspath after = classpaths.resolve(current, overrides, context);
        if (!after.complete()) {
            notes.add(after.detail());
            return unchecked(notes);
        }

        List<ClassMemberIndex> beforeJars = indexes(before.jars(), notes);
        List<ClassMemberIndex> afterJars = indexes(after.jars(), notes);
        List<ClassMemberIndex> workspaceClasses = workspaceClasses(workspace, notes);
        // Asked of what was actually indexed rather than by repeating the directory walk:
        // where a build output was located is one rule, and a second reading of it is the
        // convention this repository has paid most to learn. It is also the stronger question —
        // a target/classes left behind by a clean exists and contains nothing, and a verdict
        // must not count that as having checked application code.
        boolean hasWorkspaceClasses = workspaceClasses.stream()
                .anyMatch(index -> !index.classes().isEmpty());
        if (!hasWorkspaceClasses) {
            notes.add("The project has not been built; application classes were not checked.");
        }

        List<ClassMemberIndex> platform;
        try {
            platform = PlatformClasses.indexes();
        } catch (IOException e) {
            notes.add("Could not read platform classes: " + e.getMessage());
            return unchecked(notes);
        }
        MemberResolver beforeResolver = MemberResolver.over(withPlatform(beforeJars, platform));
        MemberResolver afterResolver = MemberResolver.over(withPlatform(afterJars, platform));
        LinkageDiff diff = LinkageDiffer.between(withWorkspace(beforeJars, workspaceClasses), beforeResolver,
                withWorkspace(afterJars, workspaceClasses), afterResolver);
        notes.addAll(diff.warnings());

        LinkageVerdict verdict = !diff.newlyMissing().isEmpty()
                ? LinkageVerdict.ERRORS_FOUND
                : diff.verdict() == LinkageVerdict.UNCHECKED || !hasWorkspaceClasses
                ? LinkageVerdict.UNCHECKED
                : LinkageVerdict.CLEAN;
        return new LinkageCheck(verdict, diff.newlyMissing(), diff.referencesChecked(), List.copyOf(notes));
    }

    private Map<MavenArtifact, String> overrides(List<BumpRow> rows, List<BumpEdit> edits,
                                                  List<String> notes) {
        Map<MavenArtifact, String> result = new LinkedHashMap<>();
        for (BumpEdit edit : edits) {
            if (edit.structural()) {
                notes.add("Skipped structural edit for " + edit.siteId() + ".");
                continue;
            }
            for (BumpRow row : rows) {
                DeclarationSite site = row.site();
                if (!site.id().equals(edit.siteId())) {
                    continue;
                }
                if (site.ecosystem() != Ecosystem.MAVEN) {
                    notes.add("Skipped non-Maven edit for " + edit.siteId() + ".");
                    continue;
                }
                result.put(new MavenArtifact(site.groupId(), site.artifactId()), edit.newVersion());
            }
        }
        return result;
    }

    private List<ModuleDependency> currentDependencies(WorkspaceScan workspace, List<String> notes) {
        Map<String, String> allProperties = properties(workspace.poms());
        Map<MavenArtifact, String> selected = new LinkedHashMap<>();
        for (ScannedPom pom : workspace.poms()) {
            if (!pom.contained()) {
                continue;
            }
            for (RawDependency dependency : pom.scan().dependencies()) {
                if ("test".equals(dependency.scope())) {
                    continue;
                }
                MavenArtifact artifact = new MavenArtifact(dependency.groupId(), dependency.artifactId());
                String version = version(dependency, pom, allProperties, notes);
                if (version == null) {
                    continue;
                }
                String existing = selected.get(artifact);
                if (existing == null) {
                    selected.put(artifact, version);
                } else if (VersionOrder.INSTANCE.compare(existing, version) != 0) {
                    String kept = VersionOrder.INSTANCE.compare(existing, version) >= 0 ? existing : version;
                    selected.put(artifact, kept);
                    notes.add("Modules declare " + artifact.groupId() + ":" + artifact.artifactId()
                            + " at both " + existing + " and " + version + "; using " + kept + ".");
                }
            }
        }
        return selected.entrySet().stream()
                .map(entry -> new ModuleDependency(entry.getKey(), entry.getValue())).toList();
    }

    private Map<String, String> properties(List<ScannedPom> poms) {
        Map<String, String> properties = new LinkedHashMap<>();
        for (ScannedPom pom : poms) {
            for (PropertyDefinition property : pom.scan().properties().values()) {
                properties.putIfAbsent(property.name(), property.value());
            }
        }
        return properties;
    }

    private String version(RawDependency dependency, ScannedPom pom, Map<String, String> allProperties,
                           List<String> notes) {
        String literal = dependency.versionLiteral();
        String coordinate = dependency.groupId() + ":" + dependency.artifactId();
        if (literal == null) {
            notes.add("Dropped " + coordinate + " because its version is managed by a BOM.");
            return null;
        }
        String resolved = literal;
        if (literal.startsWith("${") && literal.endsWith("}") && literal.length() > 3) {
            String name = literal.substring(2, literal.length() - 1);
            PropertyDefinition own = pom.scan().properties().get(name);
            resolved = own == null ? allProperties.get(name) : own.value();
        }
        if (resolved == null || resolved.isBlank() || resolved.startsWith("${")) {
            notes.add("Dropped " + coordinate + " because version " + literal + " could not be resolved.");
            return null;
        }
        return resolved;
    }

    private ProbeContext context(String workspace, MavenToolSettings maven, List<String> notes) {
        String repository = defaultProbeRepository();
        Optional<EffectivePomFragments> lifted = effectivePoms.forWorkspace(workspace,
                maven.executablePath(), repository, CHECK_TIMEOUT, maven.profiles(), maven.effectivePomGoal());
        if (lifted.isEmpty()) {
            notes.add("Could not lift the workspace effective POM; resolving the classpath in isolation.");
        }
        return new ProbeContext(maven.executablePath(), repository, lifted.orElse(null), CHECK_TIMEOUT,
                maven.profiles(), maven.dependencyTreeGoal());
    }

    private List<ClassMemberIndex> indexes(List<Path> artifacts, List<String> notes) {
        List<ClassMemberIndex> indexes = new ArrayList<>();
        for (Path artifact : artifacts) {
            try {
                ClassMemberIndex index = ClassMemberIndex.read(artifact, Runtime.version().feature());
                indexes.add(index);
                index.skipped().forEach(entry -> notes.add("Skipped unreadable class in "
                        + artifact + ": " + entry));
            } catch (IOException e) {
                notes.add("Skipped unreadable linkage artifact " + artifact + ": " + e.getMessage());
            }
        }
        return indexes;
    }

    private List<ClassMemberIndex> workspaceClasses(WorkspaceScan workspace, List<String> notes) {
        List<Path> directories = workspace.poms().stream().filter(ScannedPom::contained)
                .map(ScannedPom::absolutePath).map(Path::getParent)
                .map(directory -> directory.resolve("target/classes"))
                .filter(Files::isDirectory).toList();
        return indexes(directories, notes);
    }

    private List<ClassMemberIndex> withPlatform(List<ClassMemberIndex> jars, List<ClassMemberIndex> platform) {
        List<ClassMemberIndex> classpath = new ArrayList<>(jars);
        classpath.addAll(platform);
        return classpath;
    }

    private List<ClassMemberIndex> withWorkspace(List<ClassMemberIndex> jars,
                                                 List<ClassMemberIndex> workspaceClasses) {
        List<ClassMemberIndex> consumers = new ArrayList<>(jars);
        consumers.addAll(workspaceClasses);
        return consumers;
    }

    private LinkageCheck unchecked(List<String> notes) {
        return new LinkageCheck(LinkageVerdict.UNCHECKED, List.of(), 0, List.copyOf(notes));
    }
}
