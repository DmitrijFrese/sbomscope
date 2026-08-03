package dev.sbomscope.reachability;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.List;
import java.util.UUID;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import dev.sbomscope.sbom.DependencyScope;
import dev.sbomscope.sbom.StoredComponent;

import static org.assertj.core.api.Assertions.assertThat;

class WorkspaceModuleMapperTest {

    private final Path temp = Path.of("target", "workspace-module-mapper-test-" + UUID.randomUUID());
    private final WorkspaceModuleMapper mapper = new WorkspaceModuleMapper();

    @AfterEach
    void cleanUp() throws Exception {
        if (!Files.exists(temp)) return;
        try (var files = Files.walk(temp)) {
            files.sorted(Comparator.reverseOrder()).forEach(path -> {
                try {
                    Files.deleteIfExists(path);
                } catch (Exception ignored) {
                    // Test scratch is under the ignored build target; a Windows scanner may release it shortly.
                }
            });
        }
    }

    @Test
    void mapsOutputOnlyWhenPomCoordinatesExactlyMatchOneApplicationComponent() throws Exception {
        Path workspace = Files.createDirectories(temp.resolve("workspace"));
        Path module = Files.createDirectories(workspace.resolve("module-a/target/classes"));
        Files.writeString(workspace.resolve("module-a/pom.xml"), """
                <project><modelVersion>4.0.0</modelVersion>
                <groupId>example</groupId><artifactId>module-a</artifactId><version>1.2.3</version>
                </project>
                """);

        var mappings = mapper.map(workspace, List.of(module), List.of(component("module-a", "1.2.3")));

        assertThat(mappings).singleElement().satisfies(mapping -> {
            assertThat(mapping.mapped()).isTrue();
            assertThat(mapping.label()).isEqualTo("module-a");
            assertThat(mapping.component().bomRef()).isEqualTo("module-a");
        });
    }

    @Test
    void leavesAPropertyBasedPomUnmappedRatherThanGuessing() throws Exception {
        Path workspace = Files.createDirectories(temp.resolve("workspace"));
        Path module = Files.createDirectories(workspace.resolve("module-a/target/classes"));
        Files.writeString(workspace.resolve("module-a/pom.xml"), """
                <project><modelVersion>4.0.0</modelVersion><groupId>example</groupId>
                <artifactId>module-a</artifactId><version>${revision}</version></project>
                """);

        var mappings = mapper.map(workspace, List.of(module), List.of(component("module-a", "1.2.3")));

        assertThat(mappings).singleElement().satisfies(mapping -> {
            assertThat(mapping.mapped()).isFalse();
            assertThat(mapping.reason()).contains("Could not read complete");
        });
    }

    private StoredComponent component(String name, String version) {
        return new StoredComponent(UUID.randomUUID(), name, "example", name, version,
                "pkg:maven/example/%s@%s?type=jar".formatted(name, version), "library", false,
                DependencyScope.APPLICATION);
    }
}
