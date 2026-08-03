package dev.sbomscope.reachability;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;

import javax.tools.JavaCompiler;
import javax.tools.ToolProvider;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class WalaReachabilityEngineTest {

    private final Path temp = Path.of("target", "wala-reachability-test-" + UUID.randomUUID());

    @AfterEach
    void cleanUp() throws IOException {
        if (!Files.exists(temp)) return;
        try (var files = Files.walk(temp)) {
            files.sorted(Comparator.reverseOrder()).forEach(path -> {
                try {
                    Files.deleteIfExists(path);
                } catch (IOException ignored) {
                    // A WALA JarFile can briefly retain a Windows handle after the assertion.
                }
            });
        }
    }

    @Test
    void findsAnInspectableApplicationToDependencyMethodEdgeWithoutExecutingEither() throws Exception {
        Path libraryClasses = compile("fixture.direct.DirectLibrary", """
                package fixture.direct;
                public final class DirectLibrary {
                    public static String vulnerableOperation() { return "fixture"; }
                }
                """, List.of(), temp.resolve("library-classes"));
        Path libraryJar = jar(libraryClasses, temp.resolve("direct.jar"));
        Path applicationClasses = compile("modulea.DirectUse", """
                package modulea;
                import fixture.direct.DirectLibrary;
                public final class DirectUse {
                    public String callDirectly() { return DirectLibrary.vulnerableOperation(); }
                }
                """, List.of(libraryJar), temp.resolve("workspace/target/classes"));

        WorkspaceAnalysisInputs inputs = new WorkspaceAnalysisInputs(
                List.of(applicationClasses),
                List.of(new WorkspaceAnalysisInputs.ComponentArtifact(
                        "pkg:maven/fixture/direct@1.0?type=jar", libraryJar)),
                List.of(), Set.of(), "fixture");

        ReachabilityGraph graph = new WalaReachabilityEngine().analyse(inputs);

        assertThat(graph.engine()).isEqualTo("WALA 1.8.0");
        assertThat(graph.algorithm()).isEqualTo("0-CFA");
        assertThat(graph.edges()).anySatisfy(edge -> {
            assertThat(edge.caller()).startsWith("modulea.DirectUse#callDirectly");
            assertThat(edge.callee()).startsWith("fixture.direct.DirectLibrary#vulnerableOperation");
        });
    }

    @Test
    void keepsDirectAndSpringMediatedCallsInTheirOwningModuleWithoutInventingAnUnusedCall() throws Exception {
        Path jacksonClasses = compile("fixture.jackson.ObjectMapper", """
                package fixture.jackson;
                public final class ObjectMapper {
                    public static String readTree(String json) { return json; }
                }
                """, List.of(), temp.resolve("jackson-classes"));
        Path jacksonJar = jar(jacksonClasses, temp.resolve("jackson.jar"));
        Path springClasses = compile("fixture.spring.SpringJsonAdapter", """
                package fixture.spring;
                import fixture.jackson.ObjectMapper;
                public final class SpringJsonAdapter {
                    public String convert(String json) { return ObjectMapper.readTree(json); }
                }
                """, List.of(jacksonJar), temp.resolve("spring-classes"));
        Path springJar = jar(springClasses, temp.resolve("spring.jar"));
        Path unusedClasses = compile("fixture.unused.OptionalLibrary", """
                package fixture.unused;
                public final class OptionalLibrary { public static void operation() {} }
                """, List.of(), temp.resolve("unused-classes"));
        Path unusedJar = jar(unusedClasses, temp.resolve("unused.jar"));

        Path moduleA = compile("modulea.UsesJson", """
                package modulea;
                import fixture.jackson.ObjectMapper;
                import fixture.spring.SpringJsonAdapter;
                public final class UsesJson {
                    public String directlyCallsJackson() { return ObjectMapper.readTree("{}"); }
                    public String reachesJacksonThroughSpring() { return new SpringJsonAdapter().convert("{}"); }
                }
                """, List.of(jacksonJar, springJar), temp.resolve("workspace/module-a/target/classes"));
        Path moduleB = compile("moduleb.NoLibraryCall", """
                package moduleb;
                public final class NoLibraryCall { public String value() { return "safe"; } }
                """, List.of(), temp.resolve("workspace/module-b/target/classes"));

        ReachabilityGraph graph = new WalaReachabilityEngine().analyse(new WorkspaceAnalysisInputs(
                List.of(moduleA, moduleB),
                List.of(
                        new WorkspaceAnalysisInputs.ComponentArtifact("pkg:maven/fixture/jackson@1.0?type=jar", jacksonJar),
                        new WorkspaceAnalysisInputs.ComponentArtifact("pkg:maven/fixture/spring@1.0?type=jar", springJar),
                        new WorkspaceAnalysisInputs.ComponentArtifact("pkg:maven/fixture/unused@1.0?type=jar", unusedJar)),
                List.of(), Set.of(), "four-case-fixture"));

        assertThat(graph.edges()).anySatisfy(edge -> {
            assertThat(edge.caller()).startsWith("modulea.UsesJson#directlyCallsJackson");
            assertThat(edge.callee()).startsWith("fixture.jackson.ObjectMapper#readTree");
        });
        assertThat(graph.edges()).anySatisfy(edge -> {
            assertThat(edge.caller()).startsWith("modulea.UsesJson#reachesJacksonThroughSpring");
            assertThat(edge.callee()).startsWith("fixture.spring.SpringJsonAdapter#convert");
        });
        assertThat(graph.edges()).anySatisfy(edge -> {
            assertThat(edge.caller()).startsWith("fixture.spring.SpringJsonAdapter#convert");
            assertThat(edge.callee()).startsWith("fixture.jackson.ObjectMapper#readTree");
        });
        assertThat(graph.edges()).noneMatch(edge -> edge.caller().startsWith("moduleb.")
                && edge.callee().startsWith("fixture.unused."));
    }

    @Test
    void moduleScopedResultsDoNotAttributeOneVersionCallToAnotherVersion() throws Exception {
        Path versionOneClasses = compile("fixture.versioned.Library", """
                package fixture.versioned;
                public final class Library { public static String use() { return "one"; } }
                """, List.of(), temp.resolve("version-one-classes"));
        Path versionOne = jar(versionOneClasses, temp.resolve("library-1.jar"));
        Path versionTwoClasses = compile("fixture.versioned.Library", """
                package fixture.versioned;
                public final class Library { public static String use() { return "two"; } }
                """, List.of(), temp.resolve("version-two-classes"));
        Path versionTwo = jar(versionTwoClasses, temp.resolve("library-2.jar"));
        Path moduleA = compile("modulea.UsesVersionOne", """
                package modulea;
                import fixture.versioned.Library;
                public final class UsesVersionOne { public String call() { return Library.use(); } }
                """, List.of(versionOne), temp.resolve("workspace/module-a/target/classes"));
        Path moduleB = compile("moduleb.DoesNotUseVersionTwo", """
                package moduleb;
                public final class DoesNotUseVersionTwo { public String value() { return "safe"; } }
                """, List.of(), temp.resolve("workspace/module-b/target/classes"));

        ReachabilityWorkerResult moduleAResult = analyseBounded(moduleA,
                "pkg:maven/fixture/library@1", versionOne);
        ReachabilityWorkerResult moduleBResult = analyseBounded(moduleB,
                "pkg:maven/fixture/library@2", versionTwo);

        assertThat(moduleAResult.components()).singleElement().satisfies(coverage -> {
            assertThat(coverage.purl()).endsWith("@1");
            assertThat(coverage.reachableMethods()).isEqualTo(1);
        });
        assertThat(moduleBResult.components()).singleElement().satisfies(coverage -> {
            assertThat(coverage.purl()).endsWith("@2");
            assertThat(coverage.reachableMethods()).isZero();
        });
    }

    @Test
    void duplicateClassesWithinOneModuleAreExplicitlyAmbiguous() throws Exception {
        Path firstClasses = compile("fixture.collision.Library", """
                package fixture.collision;
                public final class Library { public static void call() {} }
                """, List.of(), temp.resolve("collision-one-classes"));
        Path first = jar(firstClasses, temp.resolve("collision-1.jar"));
        Path secondClasses = compile("fixture.collision.Library", """
                package fixture.collision;
                public final class Library { public static void call() {} }
                """, List.of(), temp.resolve("collision-two-classes"));
        Path second = jar(secondClasses, temp.resolve("collision-2.jar"));
        Path application = compile("modulea.CollisionUse", """
                package modulea;
                import fixture.collision.Library;
                public final class CollisionUse { public void call() { Library.call(); } }
                """, List.of(first), temp.resolve("workspace/collision/target/classes"));
        WorkspaceAnalysisInputs inputs = new WorkspaceAnalysisInputs(
                List.of(application),
                List.of(new WorkspaceAnalysisInputs.ComponentArtifact("pkg:maven/fixture/collision@1", first),
                        new WorkspaceAnalysisInputs.ComponentArtifact("pkg:maven/fixture/collision@2", second)),
                List.of(), Set.of(), "collision");

        ReachabilityWorkerResult result = ReachabilityWorkerMain.boundedResult(
                inputs, new WalaReachabilityEngine().analyse(inputs));

        assertThat(result.components()).hasSize(2)
                .allSatisfy(coverage -> assertThat(coverage.ambiguousClassOwnership()).isTrue());
    }

    @Test
    void aClassDuplicatedBetweenWorkspaceOutputAndAJarIsExplicitlyAmbiguous() throws Exception {
        Path jarClasses = compile("fixture.workspacecollision.Library", """
                package fixture.workspacecollision;
                public final class Library { public static void call() {} }
                """, List.of(), temp.resolve("workspace-collision-jar-classes"));
        Path dependency = jar(jarClasses, temp.resolve("workspace-collision.jar"));
        Path supportingOutput = compile("fixture.workspacecollision.Library", """
                package fixture.workspacecollision;
                public final class Library { public static void call() {} }
                """, List.of(), temp.resolve("workspace/supporting/target/classes"));
        Path application = compile("modulea.WorkspaceCollisionUse", """
                package modulea;
                import fixture.workspacecollision.Library;
                public final class WorkspaceCollisionUse { public void call() { Library.call(); } }
                """, List.of(dependency), temp.resolve("workspace/application/target/classes"));
        WorkspaceAnalysisInputs inputs = new WorkspaceAnalysisInputs(
                List.of(application), List.of(supportingOutput),
                List.of(new WorkspaceAnalysisInputs.ComponentArtifact(
                        "pkg:maven/fixture/workspace-collision@1", dependency)),
                List.of(), Set.of(), "workspace-collision");

        ReachabilityWorkerResult result = ReachabilityWorkerMain.boundedResult(
                inputs, new WalaReachabilityEngine().analyse(inputs));

        assertThat(result.components()).singleElement()
                .satisfies(coverage -> assertThat(coverage.ambiguousClassOwnership()).isTrue());
    }

    @Test
    void followsCallsThroughASupportingWorkspaceModuleWithoutRootingThatModule() throws Exception {
        Path libraryClasses = compile("fixture.support.Library", """
                package fixture.support;
                public final class Library { public static String call() { return "used"; } }
                """, List.of(), temp.resolve("support-library-classes"));
        Path library = jar(libraryClasses, temp.resolve("support-library.jar"));
        Path moduleB = compile("moduleb.Adapter", """
                package moduleb;
                import fixture.support.Library;
                public final class Adapter {
                    public String forwards() { return Library.call(); }
                    public String unrelated() { return Library.call(); }
                }
                """, List.of(library), temp.resolve("workspace/support-b/target/classes"));
        Path moduleA = compile("modulea.Entry", """
                package modulea;
                import moduleb.Adapter;
                public final class Entry { public String call() { return new Adapter().forwards(); } }
                """, List.of(moduleB), temp.resolve("workspace/support-a/target/classes"));
        WorkspaceAnalysisInputs inputs = new WorkspaceAnalysisInputs(
                List.of(moduleA), List.of(moduleB),
                List.of(new WorkspaceAnalysisInputs.ComponentArtifact("pkg:maven/fixture/support@1", library)),
                List.of(), Set.of(), "supporting-module");

        ReachabilityWorkerResult result = ReachabilityWorkerMain.boundedResult(
                inputs, new WalaReachabilityEngine().analyse(inputs));

        assertThat(result.components()).singleElement().satisfies(coverage -> {
            assertThat(coverage.reachableMethods()).isEqualTo(1);
            assertThat(coverage.displayPaths()).anySatisfy(path -> {
                assertThat(path.getFirst()).startsWith("modulea.Entry#call");
                assertThat(path).anyMatch(method -> method.startsWith("moduleb.Adapter#forwards"));
                assertThat(path).noneMatch(method -> method.startsWith("moduleb.Adapter#unrelated"));
            });
        });
    }

    private ReachabilityWorkerResult analyseBounded(Path output, String purl, Path jar) throws Exception {
        WorkspaceAnalysisInputs inputs = new WorkspaceAnalysisInputs(
                List.of(output), List.of(new WorkspaceAnalysisInputs.ComponentArtifact(purl, jar)),
                List.of(), Set.of(), purl);
        return ReachabilityWorkerMain.boundedResult(inputs, new WalaReachabilityEngine().analyse(inputs));
    }

    private Path compile(String className, String source, List<Path> classpath, Path output) throws IOException {
        Path sourceRoot = temp.resolve("source").resolve(className.replace('.', '/')).getParent();
        Files.createDirectories(sourceRoot);
        Path sourceFile = sourceRoot.resolve(className.substring(className.lastIndexOf('.') + 1) + ".java");
        Files.writeString(sourceFile, source);
        Files.createDirectories(output);

        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        assertThat(compiler).as("tests require the JDK that builds SBOMscope, not a JRE").isNotNull();
        List<String> arguments = new java.util.ArrayList<>(List.of(
                "--release", "21", "-d", output.toString()));
        if (!classpath.isEmpty()) {
            arguments.addAll(List.of("-classpath", classpath.stream()
                    .map(Path::toString)
                    .collect(java.util.stream.Collectors.joining(java.io.File.pathSeparator))));
        }
        arguments.add(sourceFile.toString());
        assertThat(compiler.run(null, null, null, arguments.toArray(String[]::new))).isZero();
        return output;
    }

    private Path jar(Path classes, Path destination) throws IOException {
        try (OutputStream output = Files.newOutputStream(destination);
             JarOutputStream jar = new JarOutputStream(output);
             var files = Files.walk(classes)) {
            for (Path file : files.filter(Files::isRegularFile).toList()) {
                JarEntry entry = new JarEntry(classes.relativize(file).toString().replace('\\', '/'));
                jar.putNextEntry(entry);
                Files.copy(file, jar);
                jar.closeEntry();
            }
        }
        return destination;
    }
}
