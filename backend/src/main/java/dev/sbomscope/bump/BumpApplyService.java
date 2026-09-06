package dev.sbomscope.bump;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;

import org.springframework.stereotype.Service;

import dev.sbomscope.logging.ActivityLogger;

/**
 * The only code in SBOMscope that writes to a file outside {@code ~/.sbomscope}.
 *
 * <p>That is why it is small, why every refusal happens before any byte is written, and why the
 * whole apply fails rather than half of it succeeding: a workspace with two of four poms patched
 * is worse than one with none, because the reader cannot tell by looking which state they are in.
 *
 * <p>The three gates are the maintainer's own decision of 2026-09-05 and are deliberately
 * belt-and-braces: git is the real undo, the {@code .orig} backups cover the workspace that is
 * not in git, and the confirmation dialog's file list catches a preview that resolved somewhere
 * unexpected. Each covers a case the other two cannot see.
 */
@Service
public class BumpApplyService {

    /** What the browser sends: the text it wants written, and the fingerprint it was built from. */
    public record FileWrite(String path, String fingerprint, String text) {}

    /** Refusals are the ordinary outcome here, not exceptional, so they carry their own reason. */
    public static class ApplyRefused extends RuntimeException {
        public ApplyRefused(String message) {
            super(message);
        }
    }

    private final GitWorkingTree git;
    private final ActivityLogger activityLog;

    // Constructed rather than injected: PomScanner is a plain, stateless parser that PomWorkspace
    // also builds for itself, and it is not a Spring bean. Asking for one here is what broke
    // every context test the first time this class existed.
    private final PomScanner scanner = new PomScanner();
    private final tools.jackson.databind.ObjectMapper json = new tools.jackson.databind.ObjectMapper();

    BumpApplyService(GitWorkingTree git, ActivityLogger activityLog) {
        this.git = git;
        this.activityLog = activityLog;
    }

    /**
     * @param overrideGitGate the user's explicit confirmation, which is honoured <b>only</b> for
     *                        a workspace that is not a repository. A dirty tracked tree is never
     *                        overridable from here: there the user has a real undo available and
     *                        should use it
     */
    public ApplyResult apply(Path workspace, List<FileWrite> writes, boolean overrideGitGate) {
        Path root = workspace.toAbsolutePath().normalize();
        if (writes.isEmpty()) {
            throw new ApplyRefused("There is nothing to apply");
        }

        checkGitGate(root, overrideGitGate);

        // Everything below runs twice over the same list: once deciding, once writing. Nothing
        // is written until every file has passed, because a refusal discovered halfway through
        // leaves exactly the half-applied state this whole class exists to prevent.
        List<Planned> planned = new ArrayList<>();
        for (FileWrite write : writes) {
            planned.add(check(root, write));
        }

        List<String> written = new ArrayList<>();
        List<String> backups = new ArrayList<>();
        List<String> skipped = new ArrayList<>();
        for (Planned file : planned) {
            if (file.unchanged()) {
                skipped.add(file.relativePath());
                continue;
            }
            Path backup = writeBackup(file);
            writeAtomically(file);
            written.add(file.relativePath());
            backups.add(root.relativize(backup).toString().replace('\\', '/'));
        }

        activityLog.record(ActivityLogger.Category.DATA, "BUMP_APPLY",
                written.isEmpty() ? "nothing-to-write" : "written",
                "Workspace " + root + " — wrote " + written.size() + " file(s): "
                        + String.join(", ", written)
                        + (skipped.isEmpty() ? "" : "; unchanged: " + String.join(", ", skipped)));

        return new ApplyResult(List.copyOf(written), List.copyOf(backups), List.copyOf(skipped));
    }

    private void checkGitGate(Path root, boolean overrideGitGate) {
        GitWorkingTree.Status status = git.statusOf(root);
        if (status.repository() && status.clean()) {
            return;
        }
        if (status.repository()) {
            throw new ApplyRefused("The git working tree is not clean. Commit or stash first — "
                    + "that is what makes this reversible.\n" + status.detail());
        }
        if (!overrideGitGate) {
            throw new ApplyRefused(status.detail()
                    + ". Applying here cannot be undone with git; confirm explicitly to continue.");
        }
    }

    private Planned check(Path root, FileWrite write) {
        Path target = root.resolve(write.path()).toAbsolutePath().normalize();

        // The second, independent check of a fact the plan already recorded as editable=false.
        // Independent on purpose: the first lives in code that only reads, and a containment rule
        // enforced solely where it is convenient is a containment rule waiting to be bypassed.
        if (!target.startsWith(root)) {
            throw new ApplyRefused("Refusing to write outside the workspace: " + write.path());
        }
        if (!Files.isRegularFile(target)) {
            throw new ApplyRefused("No longer a file in the workspace: " + write.path());
        }
        if (!Files.isWritable(target)) {
            throw new ApplyRefused("Not writable: " + write.path());
        }

        byte[] current;
        try {
            current = Files.readAllBytes(target);
        } catch (IOException e) {
            throw new ApplyRefused("Could not read " + write.path() + ": " + e.getMessage());
        }
        String fingerprint = fingerprint(current);
        if (!fingerprint.equals(write.fingerprint())) {
            throw new ApplyRefused(write.path() + " changed on disk since the preview was built. "
                    + "Rebuild the plan and review it again.");
        }

        // Parsed here and only here. A file that does not parse is refused before it is written,
        // which is what makes reverting real: the model still holds text the user can correct.
        validate(write);

        byte[] wanted = write.text().getBytes(StandardCharsets.UTF_8);
        return new Planned(target, write.path(), wanted, MessageDigest.isEqual(current, wanted));
    }

    /**
     * Parsed here and only here, by the grammar the file is actually written in.
     *
     * <p>This is what makes reverting real: a file that no longer parses refuses the apply while
     * the model still holds text the user can correct. It dispatches on the file name rather than
     * assuming XML — the first version of this class validated everything with {@link PomScanner}
     * and would have rejected every {@code package.json} as malformed XML, which is the shape of
     * mistake that makes a feature look broken in the one place it is hardest to explain.
     */
    private void validate(FileWrite write) {
        String name = write.path().substring(write.path().lastIndexOf('/') + 1);
        try {
            if (name.endsWith(".json")) {
                json.readTree(write.text());
            } else {
                scanner.scan(write.path(), write.text());
            }
        } catch (RuntimeException e) {
            throw new ApplyRefused(write.path() + " does not parse after your edits: "
                    + e.getMessage());
        }
    }

    private Path writeBackup(Planned file) {
        Path backup = file.target().resolveSibling(file.target().getFileName() + ".orig");
        // An existing .orig is somebody's earlier undo. Overwriting it would destroy the only
        // copy of a state they may still want, so the new one is numbered instead.
        int ordinal = 1;
        while (Files.exists(backup)) {
            backup = file.target().resolveSibling(file.target().getFileName() + ".orig." + ordinal);
            ordinal++;
        }
        try {
            Files.copy(file.target(), backup);
        } catch (IOException e) {
            throw new ApplyRefused("Could not write a backup beside " + file.relativePath()
                    + ": " + e.getMessage());
        }
        return backup;
    }

    private void writeAtomically(Planned file) {
        Path directory = file.target().getParent();
        Path temporary;
        try {
            // In the target's own directory, because an atomic move across file systems is not
            // atomic and on Windows is not permitted at all.
            temporary = Files.createTempFile(directory, ".sbomscope-bump", ".tmp");
            Files.write(temporary, file.bytes());
        } catch (IOException e) {
            throw new ApplyRefused("Could not stage a write for " + file.relativePath()
                    + ": " + e.getMessage());
        }
        try {
            Files.move(temporary, file.target(),
                    StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (AtomicMoveNotSupportedException e) {
            try {
                Files.move(temporary, file.target(), StandardCopyOption.REPLACE_EXISTING);
            } catch (IOException fallback) {
                throw new ApplyRefused("Could not write " + file.relativePath() + ": "
                        + fallback.getMessage());
            }
        } catch (IOException e) {
            deleteQuietly(temporary);
            throw new ApplyRefused("Could not write " + file.relativePath() + ": " + e.getMessage());
        }
    }

    private void deleteQuietly(Path path) {
        try {
            Files.deleteIfExists(path);
        } catch (IOException ignored) {
            // Nothing useful to do: the write already failed and this is a temp file in the way.
        }
    }

    private String fingerprint(byte[] bytes) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is unavailable", e);
        }
    }

    private record Planned(Path target, String relativePath, byte[] bytes, boolean unchanged) {}
}
