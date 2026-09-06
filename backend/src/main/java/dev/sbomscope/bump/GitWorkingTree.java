package dev.sbomscope.bump;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Whether a workspace's git working tree is clean, answered by invoking the user's own
 * {@code git} — never a library, and never a reimplementation.
 *
 * <p>The same posture as the Maven probe driving the user's {@code mvn}: the tool belongs to
 * them, is already on their PATH if they use it, and is not something SBOMscope ships or
 * downloads. The alternative was reimplementing an index-versus-worktree comparison to produce
 * one boolean, or adding JGit against the lean-dependency constraint.
 *
 * <p><b>git missing from the PATH resolves to "not a repository"</b>, which is the override
 * path rather than a silent pass. That collapses two situations the user experiences
 * identically — no git installed, and a directory git does not track — into the one answer that
 * makes the apply dialog ask rather than assume.
 */
@Component
public class GitWorkingTree {

    private static final Logger log = LoggerFactory.getLogger(GitWorkingTree.class);

    /** Long enough for a large repository, short enough that a hung git does not hang an apply. */
    private static final long TIMEOUT_SECONDS = 20;

    /**
     * @param repository false when git is absent, the directory is not tracked, or git failed
     *                   for any reason we cannot distinguish from those
     * @param clean      meaningful only when {@code repository} is true
     * @param detail     what to tell the user, already phrased for them
     */
    public record Status(boolean repository, boolean clean, String detail) {}

    public Status statusOf(Path workspace) {
        ProcessBuilder builder = new ProcessBuilder("git", "status", "--porcelain")
                .directory(workspace.toFile());
        builder.redirectErrorStream(true);

        Process process = null;
        try {
            process = builder.start();
            String output;
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
                output = reader.lines().reduce("", (left, right) -> left + right + "\n").trim();
            }
            if (!process.waitFor(TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                process.destroyForcibly();
                return new Status(false, false, "git did not answer within " + TIMEOUT_SECONDS
                        + " seconds; treating this workspace as untracked");
            }
            if (process.exitValue() != 0) {
                // The usual case here is "not a git repository", which git reports on stderr and
                // we have merged into the output above. Anything else lands here too, and lands
                // in the same place deliberately: an answer we cannot trust is not a clean tree.
                return new Status(false, false, "This workspace is not a git repository");
            }
            if (output.isEmpty()) {
                return new Status(true, true, "The git working tree is clean");
            }
            return new Status(true, false, "The git working tree has uncommitted changes:\n" + output);
        } catch (IOException e) {
            log.debug("git could not be started in {}", workspace, e);
            return new Status(false, false, "git is not available on the PATH; "
                    + "treating this workspace as untracked");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            if (process != null) {
                process.destroyForcibly();
            }
            return new Status(false, false, "The git check was interrupted");
        }
    }

    /** The lines a caller should show when refusing, capped so a huge diff cannot fill a dialog. */
    public static List<String> firstLines(String detail, int limit) {
        return detail.lines().limit(limit).toList();
    }
}
