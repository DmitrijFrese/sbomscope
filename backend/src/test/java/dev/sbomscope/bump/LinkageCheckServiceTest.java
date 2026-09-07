package dev.sbomscope.bump;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;

import javax.tools.JavaCompiler;
import javax.tools.ToolProvider;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;

import dev.sbomscope.linkage.LinkageVerdict;
import dev.sbomscope.linkage.MemberRef;
import dev.sbomscope.probe.EffectivePomCache;
import dev.sbomscope.probe.LinkageClasspathResolver;
import dev.sbomscope.probe.LinkageClasspathResolver.ResolvedClasspath;
import dev.sbomscope.probe.MavenArtifact;
import dev.sbomscope.probe.ModuleDependency;
import dev.sbomscope.settings.MavenToolSettings;
import dev.sbomscope.settings.SettingsService;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("unchecked") // Mockito's Class token cannot retain List<ModuleDependency>.
class LinkageCheckServiceTest {

    @Test
    void returnsUncheckedWithoutMavenEditsAndDoesNotResolve(@TempDir Path workspace) throws IOException {
        writePom(workspace, "<dependencies/>" );
        LinkageClasspathResolver classpaths = mock(LinkageClasspathResolver.class);

        LinkageCheck result = service(classpaths).check(plan(workspace, npmRow("npm-site")), List.of());

        assertThat(result.verdict()).isEqualTo(LinkageVerdict.UNCHECKED);
        assertThat(result.notes()).anyMatch(note -> note.contains("no Maven dependency edits"));
        verify(classpaths, never()).resolve(anyList(), anyMap(), any());
    }

    @Test
    void skipsStructuralEditsWithoutResolving(@TempDir Path workspace) throws IOException {
        writePom(workspace, "<dependencies/>" );
        LinkageClasspathResolver classpaths = mock(LinkageClasspathResolver.class);

        LinkageCheck result = service(classpaths).check(plan(workspace, mavenRow("new-site")),
                List.of(new BumpEdit("new-site", "2.0.0", true)));

        assertThat(result.verdict()).isEqualTo(LinkageVerdict.UNCHECKED);
        assertThat(result.notes()).anyMatch(note -> note.contains("structural edit") && note.contains("new-site"));
        verify(classpaths, never()).resolve(anyList(), anyMap(), any());
    }

    @Test
    void skipsNpmEditsWithoutResolving(@TempDir Path workspace) throws IOException {
        writePom(workspace, "<dependencies/>" );
        LinkageClasspathResolver classpaths = mock(LinkageClasspathResolver.class);

        LinkageCheck result = service(classpaths).check(plan(workspace, npmRow("npm-site")),
                List.of(new BumpEdit("npm-site", "2.0.0", false)));

        assertThat(result.verdict()).isEqualTo(LinkageVerdict.UNCHECKED);
        assertThat(result.notes()).anyMatch(note -> note.contains("non-Maven edit") && note.contains("npm-site"));
        verify(classpaths, never()).resolve(anyList(), anyMap(), any());
    }

    @Test
    void doesNotJudgeAnIncompleteClasspath(@TempDir Path workspace) throws IOException {
        writePom(workspace, dependency("example", "library", "1.0.0", null));
        LinkageClasspathResolver classpaths = mock(LinkageClasspathResolver.class);
        when(classpaths.resolve(anyList(), anyMap(), any()))
                .thenReturn(new ResolvedClasspath(List.of(), false, "Maven could not resolve library."));

        LinkageCheck result = service(classpaths).check(plan(workspace, mavenRow("site")),
                List.of(new BumpEdit("site", "2.0.0", false)));

        assertThat(result.verdict()).isEqualTo(LinkageVerdict.UNCHECKED);
        assertThat(result.notes()).contains("Maven could not resolve library.");
        verify(classpaths, times(1)).resolve(anyList(), anyMap(), any());
    }

    @Test
    void resolvesVersionsFromTheSamePomAndItsContainedParent(@TempDir Path workspace) throws IOException {
        writePom(workspace, """
                <properties><own.version>1.0.0</own.version><parent.version>2.0.0</parent.version></properties>
                <modules><module>child</module></modules>
                <dependencies><dependency><groupId>example</groupId><artifactId>own</artifactId>
                <version>${own.version}</version></dependency></dependencies>
                """);
        Path child = Files.createDirectories(workspace.resolve("child"));
        writePom(child, """
                <parent><relativePath>../pom.xml</relativePath></parent>
                <dependencies><dependency><groupId>example</groupId><artifactId>parent</artifactId>
                <version>${parent.version}</version></dependency></dependencies>
                """);
        LinkageClasspathResolver classpaths = mock(LinkageClasspathResolver.class);
        when(classpaths.resolve(anyList(), anyMap(), any()))
                .thenReturn(new ResolvedClasspath(List.of(), false, "stop here"));

        service(classpaths).check(plan(workspace, mavenRow("site")), List.of(new BumpEdit("site", "2", false)));

        ArgumentCaptor<List<ModuleDependency>> dependencies = ArgumentCaptor.forClass(List.class);
        verify(classpaths).resolve(dependencies.capture(), anyMap(), any());
        assertThat(dependencies.getValue()).containsExactlyInAnyOrder(
                new ModuleDependency(new MavenArtifact("example", "own"), "1.0.0"),
                new ModuleDependency(new MavenArtifact("example", "parent"), "2.0.0"));
    }

    @Test
    void dropsAnUnresolvedPropertyInsteadOfPassingItsLiteralToMaven(@TempDir Path workspace) throws IOException {
        writePom(workspace, dependency("example", "library", "${missing.version}", null));
        LinkageClasspathResolver classpaths = mock(LinkageClasspathResolver.class);
        when(classpaths.resolve(anyList(), anyMap(), any()))
                .thenReturn(new ResolvedClasspath(List.of(), false, "stop here"));

        LinkageCheck result = service(classpaths).check(plan(workspace, mavenRow("site")),
                List.of(new BumpEdit("site", "2", false)));

        ArgumentCaptor<List<ModuleDependency>> dependencies = ArgumentCaptor.forClass(List.class);
        verify(classpaths).resolve(dependencies.capture(), anyMap(), any());
        assertThat(dependencies.getValue()).isEmpty();
        assertThat(result.notes()).anyMatch(note -> note.contains("example:library") && note.contains("missing.version"));
    }

    @Test
    void dropsBomManagedDependenciesWithoutAVersion(@TempDir Path workspace) throws IOException {
        writePom(workspace, """
                <dependencies><dependency><groupId>example</groupId><artifactId>managed</artifactId></dependency></dependencies>
                """);
        LinkageClasspathResolver classpaths = mock(LinkageClasspathResolver.class);
        when(classpaths.resolve(anyList(), anyMap(), any()))
                .thenReturn(new ResolvedClasspath(List.of(), false, "stop here"));

        LinkageCheck result = service(classpaths).check(plan(workspace, mavenRow("site")),
                List.of(new BumpEdit("site", "2", false)));

        ArgumentCaptor<List<ModuleDependency>> dependencies = ArgumentCaptor.forClass(List.class);
        verify(classpaths).resolve(dependencies.capture(), anyMap(), any());
        assertThat(dependencies.getValue()).isEmpty();
        assertThat(result.notes()).anyMatch(note -> note.contains("example:managed") && note.contains("managed by a BOM"));
    }

    @Test
    void excludesTestDependenciesButKeepsProvidedOnes(@TempDir Path workspace) throws IOException {
        writePom(workspace, """
                <dependencies>
                  <dependency><groupId>example</groupId><artifactId>tests</artifactId><version>1</version><scope>test</scope></dependency>
                  <dependency><groupId>example</groupId><artifactId>provided</artifactId><version>2</version><scope>provided</scope></dependency>
                </dependencies>
                """);
        LinkageClasspathResolver classpaths = mock(LinkageClasspathResolver.class);
        when(classpaths.resolve(anyList(), anyMap(), any()))
                .thenReturn(new ResolvedClasspath(List.of(), false, "stop here"));

        service(classpaths).check(plan(workspace, mavenRow("site")), List.of(new BumpEdit("site", "2", false)));

        ArgumentCaptor<List<ModuleDependency>> dependencies = ArgumentCaptor.forClass(List.class);
        verify(classpaths).resolve(dependencies.capture(), anyMap(), any());
        assertThat(dependencies.getValue()).containsExactly(
                new ModuleDependency(new MavenArtifact("example", "provided"), "2"));
    }

    @Test
    void keepsTheHighestVersionAcrossModulesAndExplainsIt(@TempDir Path workspace) throws IOException {
        writePom(workspace, "<modules><module>one</module><module>two</module></modules>");
        writePom(Files.createDirectories(workspace.resolve("one")), dependency("example", "library", "1.0.0", null));
        writePom(Files.createDirectories(workspace.resolve("two")), dependency("example", "library", "2.0.0", null));
        LinkageClasspathResolver classpaths = mock(LinkageClasspathResolver.class);
        when(classpaths.resolve(anyList(), anyMap(), any()))
                .thenReturn(new ResolvedClasspath(List.of(), false, "stop here"));

        LinkageCheck result = service(classpaths).check(plan(workspace, mavenRow("site")),
                List.of(new BumpEdit("site", "3", false)));

        ArgumentCaptor<List<ModuleDependency>> dependencies = ArgumentCaptor.forClass(List.class);
        verify(classpaths).resolve(dependencies.capture(), anyMap(), any());
        assertThat(dependencies.getValue()).containsExactly(
                new ModuleDependency(new MavenArtifact("example", "library"), "2.0.0"));
        assertThat(result.notes()).anyMatch(note -> note.contains("example:library")
                && note.contains("1.0.0") && note.contains("2.0.0"));
    }

    @Test
    void marksAnUnbuiltWorkspaceUnchecked(@TempDir Path workspace) throws IOException {
        writePom(workspace, dependency("example", "library", "1", null));
        LinkageClasspathResolver classpaths = mock(LinkageClasspathResolver.class);
        when(classpaths.resolve(anyList(), anyMap(), any()))
                .thenReturn(new ResolvedClasspath(List.of(), true, null));

        LinkageCheck result = service(classpaths).check(plan(workspace, mavenRow("site")),
                List.of(new BumpEdit("site", "2", false)));

        assertThat(result.verdict()).isEqualTo(LinkageVerdict.UNCHECKED);
        assertThat(result.notes()).anyMatch(note -> note.contains("application classes were not checked"));
    }

    @Test
    void findsAMemberThatDisappearsFromTheProposedClasspath(@TempDir Path workspace) throws Exception {
        writePom(workspace, dependency("example", "library", "1", null));
        Path beforeClasses = compile(workspace.resolve("before"), "example.Library", """
                package example; public class Library { public static void removed() {} }
                """, null);
        Path applicationClasses = compile(workspace.resolve("application"), "example.Consumer", """
                package example; public class Consumer { public void call() { Library.removed(); } }
                """, beforeClasses);
        Path targetClasses = Files.createDirectories(workspace.resolve("target/classes"));
        copyClasses(applicationClasses, targetClasses);
        Path afterClasses = compile(workspace.resolve("after"), "example.Library", """
                package example; public class Library { public static void replacement() {} }
                """, null);
        Path beforeJar = jar(workspace.resolve("before.jar"), beforeClasses);
        Path afterJar = jar(workspace.resolve("after.jar"), afterClasses);

        LinkageClasspathResolver classpaths = mock(LinkageClasspathResolver.class);
        when(classpaths.resolve(anyList(), anyMap(), any())).thenReturn(
                new ResolvedClasspath(List.of(beforeJar), true, null),
                new ResolvedClasspath(List.of(afterJar), true, null));

        LinkageCheck result = service(classpaths).check(plan(workspace, mavenRow("site")),
                List.of(new BumpEdit("site", "2", false)));

        assertThat(result.verdict()).isEqualTo(LinkageVerdict.ERRORS_FOUND);
        assertThat(result.newlyMissing()).extracting(finding -> finding.reference())
                .contains(new MemberRef("example/Library", "removed", "()V"));
    }

    private LinkageCheckService service(LinkageClasspathResolver classpaths) {
        EffectivePomCache effectivePoms = mock(EffectivePomCache.class);
        when(effectivePoms.forWorkspace(any(), any(), any(), any(), any(), any())).thenReturn(Optional.empty());
        SettingsService settings = mock(SettingsService.class);
        when(settings.mavenSettings()).thenReturn(new MavenToolSettings(true, "mvn", 20, 8, null, null, null));
        return new LinkageCheckService(new PomWorkspace(), classpaths, effectivePoms, settings);
    }

    private BumpPlan plan(Path workspace, BumpRow row) {
        return new BumpPlan(null, workspace.toString(), List.of(), List.of(row), List.of(), List.of());
    }

    private BumpRow mavenRow(String siteId) {
        return row(siteId, Ecosystem.MAVEN);
    }

    private BumpRow npmRow(String siteId) {
        return row(siteId, Ecosystem.NPM);
    }

    private BumpRow row(String siteId, Ecosystem ecosystem) {
        DeclarationSite site = new DeclarationSite(siteId, "pom.xml", "", SiteKind.DIRECT,
                "example", ecosystem == Ecosystem.MAVEN ? "library" : "npm-library", "jar", "",
                "1", null, List.of(), List.of(), null, null, ecosystem, "1", false);
        return new BumpRow(site, "2", null, List.of(), "High", null, null, null, null);
    }

    private void writePom(Path directory, String body) throws IOException {
        Files.writeString(directory.resolve("pom.xml"), "<project><modelVersion>4.0.0</modelVersion>"
                + body + "</project>");
    }

    private String dependency(String group, String artifact, String version, String scope) {
        return "<dependencies><dependency><groupId>" + group + "</groupId><artifactId>" + artifact
                + "</artifactId><version>" + version + "</version>"
                + (scope == null ? "" : "<scope>" + scope + "</scope>")
                + "</dependency></dependencies>";
    }

    private Path compile(Path directory, String className, String source, Path classpath) throws IOException {
        Path sourceDirectory = Files.createDirectories(directory.resolve("src"));
        Path sourceFile = sourceDirectory.resolve(className.replace('.', '/') + ".java");
        Files.createDirectories(sourceFile.getParent());
        Files.writeString(sourceFile, source);
        Path output = Files.createDirectories(directory.resolve("classes"));
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        assertThat(compiler).as("a JDK compiler is available to compile bytecode fixtures").isNotNull();
        List<String> options = new java.util.ArrayList<>(List.of("-d", output.toString()));
        if (classpath != null) {
            options.addAll(List.of("-classpath", classpath.toString()));
        }
        options.add(sourceFile.toString());
        assertThat(compiler.run(null, null, null, options.toArray(String[]::new))).isZero();
        return output;
    }

    private void copyClasses(Path from, Path to) throws IOException {
        try (var paths = Files.walk(from)) {
            for (Path source : paths.filter(Files::isRegularFile).toList()) {
                Path target = to.resolve(from.relativize(source));
                Files.createDirectories(target.getParent());
                Files.copy(source, target);
            }
        }
    }

    private Path jar(Path jar, Path classes) throws IOException {
        try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(jar));
             var paths = Files.walk(classes)) {
            for (Path file : paths.filter(Files::isRegularFile).toList()) {
                output.putNextEntry(new JarEntry(classes.relativize(file).toString().replace('\\', '/')));
                output.write(Files.readAllBytes(file));
                output.closeEntry();
            }
        }
        return jar;
    }
}
