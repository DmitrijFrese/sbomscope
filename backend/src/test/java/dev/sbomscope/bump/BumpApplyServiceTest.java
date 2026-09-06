package dev.sbomscope.bump;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import tools.jackson.databind.ObjectMapper;

import dev.sbomscope.bump.BumpApplyService.ApplyRefused;
import dev.sbomscope.bump.BumpApplyService.FileWrite;
import dev.sbomscope.logging.ActivityLogger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The gates matter more than the write here, so most of these assert that <b>nothing happened</b>.
 * Each refusal test therefore checks the file's bytes afterwards: "it threw" and "it threw before
 * writing" are different claims, and only the second one is the safety property.
 */
class BumpApplyServiceTest {

    private static final String POM = """
            <project>
              <properties>
                <lib.version>1.0.0</lib.version>
              </properties>
            </project>
            """;

    private final ActivityLogger activityLog = new ActivityLogger(new ObjectMapper());

    @Test
    void writesAtomicallyAndLeavesAnOrigBackup(@TempDir Path workspace) throws IOException {
        Path pom = write(workspace, "pom.xml", POM);
        String patched = POM.replace("1.0.0", "2.0.0");

        ApplyResult result = service(cleanRepository())
                .apply(workspace, List.of(new FileWrite("pom.xml", fingerprint(POM), patched)), false);

        assertThat(Files.readString(pom)).isEqualTo(patched);
        assertThat(Files.readString(workspace.resolve("pom.xml.orig"))).isEqualTo(POM);
        assertThat(result.written()).containsExactly("pom.xml");
        assertThat(result.backups()).containsExactly("pom.xml.orig");
        assertThat(result.skipped()).isEmpty();
        // Nothing left behind: a staged temp file that survives is a file the user has to explain.
        try (var entries = Files.list(workspace)) {
            assertThat(entries.map(path -> path.getFileName().toString()))
                    .containsExactlyInAnyOrder("pom.xml", "pom.xml.orig");
        }
    }

    @Test
    void numbersABackupRatherThanOverwritingAnEarlierOne(@TempDir Path workspace) throws IOException {
        write(workspace, "pom.xml", POM);
        Files.writeString(workspace.resolve("pom.xml.orig"), "an earlier undo");

        service(cleanRepository()).apply(workspace,
                List.of(new FileWrite("pom.xml", fingerprint(POM), POM.replace("1.0.0", "2.0.0"))), false);

        assertThat(Files.readString(workspace.resolve("pom.xml.orig"))).isEqualTo("an earlier undo");
        assertThat(Files.readString(workspace.resolve("pom.xml.orig.1"))).isEqualTo(POM);
    }

    @Test
    void refusesADirtyTrackedTreeAndWritesNothing(@TempDir Path workspace) throws IOException {
        Path pom = write(workspace, "pom.xml", POM);

        assertThatThrownBy(() -> service(dirtyRepository()).apply(workspace,
                List.of(new FileWrite("pom.xml", fingerprint(POM), POM.replace("1.0.0", "2.0.0"))), false))
                .isInstanceOf(ApplyRefused.class)
                .hasMessageContaining("not clean");

        assertThat(Files.readString(pom)).isEqualTo(POM);
        assertThat(workspace.resolve("pom.xml.orig")).doesNotExist();
    }

    @Test
    void refusesADirtyTreeEvenWhenTheOverrideIsSet(@TempDir Path workspace) throws IOException {
        Path pom = write(workspace, "pom.xml", POM);

        // The override exists for "this is not a repository", never for "you have uncommitted
        // work". There the user has a real undo and should use it.
        assertThatThrownBy(() -> service(dirtyRepository()).apply(workspace,
                List.of(new FileWrite("pom.xml", fingerprint(POM), POM.replace("1.0.0", "2.0.0"))), true))
                .isInstanceOf(ApplyRefused.class);

        assertThat(Files.readString(pom)).isEqualTo(POM);
    }

    @Test
    void refusesAnUntrackedWorkspaceUntilItIsOverridden(@TempDir Path workspace) throws IOException {
        Path pom = write(workspace, "pom.xml", POM);
        String patched = POM.replace("1.0.0", "2.0.0");
        BumpApplyService service = service(notARepository());

        assertThatThrownBy(() -> service.apply(workspace,
                List.of(new FileWrite("pom.xml", fingerprint(POM), patched)), false))
                .isInstanceOf(ApplyRefused.class)
                .hasMessageContaining("confirm explicitly");
        assertThat(Files.readString(pom)).isEqualTo(POM);

        service.apply(workspace, List.of(new FileWrite("pom.xml", fingerprint(POM), patched)), true);
        assertThat(Files.readString(pom)).isEqualTo(patched);
    }

    @Test
    void refusesAFileThatChangedOnDiskSinceThePreview(@TempDir Path workspace) throws IOException {
        Path pom = write(workspace, "pom.xml", POM);
        String staleFingerprint = fingerprint(POM);
        Files.writeString(pom, POM.replace("1.0.0", "1.0.1"));

        assertThatThrownBy(() -> service(cleanRepository()).apply(workspace,
                List.of(new FileWrite("pom.xml", staleFingerprint, POM.replace("1.0.0", "2.0.0"))), false))
                .isInstanceOf(ApplyRefused.class)
                .hasMessageContaining("changed on disk");

        assertThat(Files.readString(pom)).isEqualTo(POM.replace("1.0.0", "1.0.1"));
    }

    @Test
    void refusesTheWholeApplyWhenOneFileFails(@TempDir Path workspace) throws IOException {
        Path good = write(workspace, "pom.xml", POM);
        Path module = Files.createDirectories(workspace.resolve("module-a"));
        Path bad = write(module, "pom.xml", POM);
        Files.writeString(bad, POM.replace("1.0.0", "9.9.9"));

        assertThatThrownBy(() -> service(cleanRepository()).apply(workspace, List.of(
                new FileWrite("pom.xml", fingerprint(POM), POM.replace("1.0.0", "2.0.0")),
                new FileWrite("module-a/pom.xml", fingerprint(POM), POM.replace("1.0.0", "2.0.0"))), false))
                .isInstanceOf(ApplyRefused.class);

        // The point of the test: the file that would have succeeded is untouched, because a
        // half-applied workspace is worse than a refused one.
        assertThat(Files.readString(good)).isEqualTo(POM);
        assertThat(workspace.resolve("pom.xml.orig")).doesNotExist();
    }

    @Test
    void refusesAPathThatEscapesTheWorkspace(@TempDir Path parent) throws IOException {
        Path workspace = Files.createDirectories(parent.resolve("workspace"));
        write(workspace, "pom.xml", POM);
        Path outside = write(parent, "pom.xml", POM);

        assertThatThrownBy(() -> service(cleanRepository()).apply(workspace,
                List.of(new FileWrite("../pom.xml", fingerprint(POM), POM.replace("1.0.0", "2.0.0"))), false))
                .isInstanceOf(ApplyRefused.class)
                .hasMessageContaining("outside the workspace");

        assertThat(Files.readString(outside)).isEqualTo(POM);
    }

    @Test
    void refusesTextThatNoLongerParses(@TempDir Path workspace) throws IOException {
        Path pom = write(workspace, "pom.xml", POM);

        assertThatThrownBy(() -> service(cleanRepository()).apply(workspace,
                List.of(new FileWrite("pom.xml", fingerprint(POM), "<project><properties>")), false))
                .isInstanceOf(ApplyRefused.class);

        assertThat(Files.readString(pom)).isEqualTo(POM);
    }

    @Test
    void skipsAFileWhoseContentAlreadyMatches(@TempDir Path workspace) throws IOException {
        write(workspace, "pom.xml", POM);

        ApplyResult result = service(cleanRepository())
                .apply(workspace, List.of(new FileWrite("pom.xml", fingerprint(POM), POM)), false);

        assertThat(result.written()).isEmpty();
        assertThat(result.skipped()).containsExactly("pom.xml");
        // No backup for a file nobody changed: a .orig that records nothing is noise the user
        // has to clean up, and it makes the real ones harder to trust.
        assertThat(workspace.resolve("pom.xml.orig")).doesNotExist();
    }

    private BumpApplyService service(GitWorkingTree git) {
        return new BumpApplyService(git, activityLog);
    }

    private GitWorkingTree cleanRepository() {
        return stub(new GitWorkingTree.Status(true, true, "clean"));
    }

    private GitWorkingTree dirtyRepository() {
        return stub(new GitWorkingTree.Status(true, false, " M pom.xml"));
    }

    private GitWorkingTree notARepository() {
        return stub(new GitWorkingTree.Status(false, false, "This workspace is not a git repository"));
    }

    /** A stub rather than a mock: the real one starts a process, and no test here is about git. */
    private GitWorkingTree stub(GitWorkingTree.Status status) {
        return new GitWorkingTree() {
            @Override
            public Status statusOf(Path workspace) {
                return status;
            }
        };
    }

    private Path write(Path directory, String name, String text) throws IOException {
        Path path = directory.resolve(name);
        Files.writeString(path, text);
        return path;
    }

    private String fingerprint(String text) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(text.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new AssertionError(e);
        }
    }
}
