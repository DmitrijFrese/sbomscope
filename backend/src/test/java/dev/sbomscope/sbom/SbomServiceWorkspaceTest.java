package dev.sbomscope.sbom;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Attaching, changing or clearing a document's workspace after upload (B20).
 *
 * <p>Until 2026-08-06 the path could only be set at upload time, so a document uploaded
 * without one could never gain it — the only route was delete-and-re-upload, discarding
 * scan history to change one string. This is what closes that gap.
 */
@SpringBootTest
@Transactional
class SbomServiceWorkspaceTest {

    @Autowired
    private SbomService sboms;

    @TempDir
    private Path tempDir;

    private static final String MINIMAL_SBOM = """
            {"bomFormat":"CycloneDX","specVersion":"1.6","components":[
              {"type":"library","bom-ref":"pkg:maven/example/lib@1.0.0",
               "group":"example","name":"lib","version":"1.0.0"}
            ]}
            """;

    private StoredSbom upload() {
        return sboms.importSbom("subject.cdx.json", null,
                new ByteArrayInputStream(MINIMAL_SBOM.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void setsAWorkspaceOnADocumentThatHadNone() {
        StoredSbom doc = upload();
        assertThat(doc.workspacePath()).isNull();

        StoredSbom updated = sboms.attachWorkspace(doc.id(), tempDir.toString()).orElseThrow();

        assertThat(updated.workspacePath()).isEqualTo(tempDir.toAbsolutePath().normalize().toString());
        // The change must be visible to a fresh read, not only on the object handed back —
        // that is the property the whole feature exists to provide.
        assertThat(sboms.findById(doc.id()).orElseThrow().workspacePath())
                .isEqualTo(updated.workspacePath());
    }

    @Test
    void changesAnAlreadyAttachedWorkspace() throws IOException {
        StoredSbom doc = upload();
        sboms.attachWorkspace(doc.id(), tempDir.toString());

        Path secondDirectory = Files.createTempDirectory("sbomscope-workspace-b20");
        try {
            StoredSbom updated = sboms.attachWorkspace(doc.id(), secondDirectory.toString()).orElseThrow();
            assertThat(updated.workspacePath())
                    .isEqualTo(secondDirectory.toAbsolutePath().normalize().toString());
        } finally {
            Files.deleteIfExists(secondDirectory);
        }
    }

    @Test
    void clearingIsARealOperationNotANoOp() {
        StoredSbom doc = upload();
        sboms.attachWorkspace(doc.id(), tempDir.toString());

        StoredSbom cleared = sboms.attachWorkspace(doc.id(), null).orElseThrow();

        assertThat(cleared.workspacePath()).isNull();
        assertThat(sboms.findById(doc.id()).orElseThrow().workspacePath()).isNull();
    }

    @Test
    void blankIsTreatedAsClearing() {
        StoredSbom doc = upload();
        sboms.attachWorkspace(doc.id(), tempDir.toString());

        StoredSbom cleared = sboms.attachWorkspace(doc.id(), "   ").orElseThrow();

        assertThat(cleared.workspacePath()).isNull();
    }

    @Test
    void rejectsAPathThatDoesNotExist() {
        StoredSbom doc = upload();
        Path missing = tempDir.resolve("does-not-exist");

        assertThatThrownBy(() -> sboms.attachWorkspace(doc.id(), missing.toString()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("does not exist");
    }

    @Test
    void rejectsAFileAsOpposedToADirectory() throws IOException {
        StoredSbom doc = upload();
        Path file = Files.createFile(tempDir.resolve("not-a-directory.txt"));

        assertThatThrownBy(() -> sboms.attachWorkspace(doc.id(), file.toString()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("not a directory");
    }

    @Test
    void anUnknownSbomIdReturnsEmptyRatherThanThrowing() {
        // Distinguishes "no such document" from every validation failure above, which all
        // throw — the controller maps this case to 404 and the others to 400.
        Optional<StoredSbom> result = sboms.attachWorkspace(UUID.randomUUID(), tempDir.toString());
        assertThat(result).isEmpty();
    }
}
