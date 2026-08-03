package dev.sbomscope.reachability;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import dev.sbomscope.sbom.DependencyScope;
import dev.sbomscope.sbom.StoredComponent;

import static org.assertj.core.api.Assertions.assertThat;

class WorkspaceInputDiscoveryTest {

    @TempDir
    Path temp;

    private final WorkspaceInputDiscovery discovery = new WorkspaceInputDiscovery();

    @Test
    void readsExistingOutputsAndExactMavenArtifactWithoutWritingEither() throws Exception {
        Path output = Files.createDirectories(temp.resolve("workspace/module-a/target/classes"));
        Files.writeString(output.resolve("Application.class"), "not-real-bytecode");
        Path repository = Files.createDirectories(temp.resolve("m2/org/example/library/1.2.3"));
        Path jar = Files.writeString(repository.resolve("library-1.2.3.jar"), "jar");

        WorkspaceAnalysisInputs inputs = discovery.discover(temp.resolve("workspace"), temp.resolve("m2"),
                List.of(mavenComponent("org.example", "library", "1.2.3", DependencyScope.TRANSITIVE)));

        assertThat(inputs.productionOutputs()).containsExactly(output);
        assertThat(inputs.dependencyArtifacts()).containsExactly(
                new WorkspaceAnalysisInputs.ComponentArtifact("pkg:maven/org.example/library@1.2.3?type=jar", jar));
        assertThat(inputs.missingInputs()).isEmpty();
        assertThat(inputs.blockers()).isEmpty();
        assertThat(inputs.fingerprint()).hasSize(64);
    }

    @Test
    void marksMissingOutputsAndJarsIncompleteRatherThanNegative() {
        WorkspaceAnalysisInputs inputs = discovery.discover(temp, temp.resolve("m2"),
                List.of(mavenComponent("org.example", "library", "1.2.3", DependencyScope.TRANSITIVE)));

        assertThat(inputs.hasProductionOutputs()).isFalse();
        assertThat(inputs.completeForNegativeResult()).isFalse();
        assertThat(inputs.blockers()).contains(
                CompletenessBlocker.MISSING_PRODUCTION_OUTPUT,
                CompletenessBlocker.MISSING_DEPENDENCY_JAR);
    }

    @Test
    void springAndReflectionPreventAStaticNegativeFromBeingComplete() throws Exception {
        Path output = Files.createDirectories(temp.resolve("workspace/target/classes"));
        Files.write(output.resolve("UsesReflection.class"), "java/lang/reflect/Method".getBytes());
        Path repository = Files.createDirectories(temp.resolve("m2/org/springframework/spring-core/7.0.0"));
        Files.writeString(repository.resolve("spring-core-7.0.0.jar"), "jar");

        WorkspaceAnalysisInputs inputs = discovery.discover(temp.resolve("workspace"), temp.resolve("m2"),
                List.of(mavenComponent("org.springframework", "spring-core", "7.0.0", DependencyScope.DIRECT)));

        assertThat(inputs.blockers()).contains(
                CompletenessBlocker.SPRING_OR_AOP_PRESENT,
                CompletenessBlocker.REFLECTION_REFERENCED);
        assertThat(inputs.completeForNegativeResult()).isFalse();
    }

    @Test
    void rejectsSbomCoordinatesThatCouldEscapeTheConfiguredMavenRepository() throws Exception {
        Path output = Files.createDirectories(temp.resolve("workspace/target/classes"));
        Files.writeString(output.resolve("Application.class"), "not-real-bytecode");
        Path outside = Files.createDirectories(temp.resolve("outside/1.0"));
        Files.writeString(outside.resolve("outside-1.0.jar"), "must-not-be-read");

        WorkspaceAnalysisInputs inputs = discovery.discover(temp.resolve("workspace"), temp.resolve("m2"),
                List.of(
                        mavenComponent("..", "outside", "1.0", DependencyScope.TRANSITIVE),
                        mavenComponent("org.example", "../outside", "1.0", DependencyScope.TRANSITIVE),
                        mavenComponent("org.example", "C:\\outside", "1.0", DependencyScope.TRANSITIVE)));

        assertThat(inputs.dependencyArtifacts()).isEmpty();
        assertThat(inputs.blockers()).contains(CompletenessBlocker.MISSING_DEPENDENCY_JAR);
        assertThat(inputs.missingInputs()).hasSize(3)
                .allMatch(message -> message.contains("Rejected unsafe Maven coordinates"));
    }

    @Test
    void oversizedClassInspectionBecomesAConservativeReflectionBlocker() throws Exception {
        Path output = Files.createDirectories(temp.resolve("workspace/target/classes"));
        Path oversized = output.resolve("Oversized.class");
        try (var channel = java.nio.channels.FileChannel.open(oversized,
                java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.WRITE)) {
            channel.position(WorkspaceInputDiscovery.MAX_CLASS_INSPECTION_BYTES);
            channel.write(java.nio.ByteBuffer.wrap(new byte[] { 0 }));
        }

        WorkspaceAnalysisInputs inputs = discovery.discover(temp.resolve("workspace"), temp.resolve("m2"), List.of());

        assertThat(inputs.blockers()).contains(CompletenessBlocker.REFLECTION_REFERENCED);
        assertThat(inputs.completeForNegativeResult()).isFalse();
    }

    private StoredComponent mavenComponent(String group, String name, String version, DependencyScope scope) {
        return new StoredComponent(UUID.randomUUID(), name, group, name, version,
                "pkg:maven/%s/%s@%s?type=jar".formatted(group, name, version), "library", false, scope);
    }
}
