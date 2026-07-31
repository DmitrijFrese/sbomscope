package dev.sbomscope.probe;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * One {@code mvn} invocation, captured in full and written to the main log.
 *
 * <p>Every probe command goes through here rather than each caller starting its own process,
 * for two reasons that are really one: the correct way to drain a child process is subtle
 * enough that it must not be implemented twice, and a probe nobody can diagnose is the failure
 * mode this project keeps designing against — the same argument that produced the activity log
 * in the first place, applied to the tool the probe actually drives.
 *
 * <p><b>stderr is merged into stdout, and that is load-bearing.</b> The previous shape read
 * stdout to EOF, then stderr, then called {@code waitFor}. A child that fills the stderr pipe
 * buffer — 4–64 KB depending on the OS — blocks writing to it, so it never closes stdout, so
 * the read never returns and {@code waitFor} is never reached: <em>the timeout cannot fire</em>
 * and the probe thread hangs for good, taking every queued probe behind it. An air-gapped or
 * mirror-less Maven emits a "Could not transfer artifact" block per artifact and reaches that
 * buffer easily. One merged stream has no second buffer to deadlock against. Nothing was
 * distinguishing the two streams anyway — both call sites concatenated them before looking.
 *
 * <p>The timeout is enforced by a watchdog that destroys the process, rather than by a bounded
 * read: killing the child closes the stream, which is what actually unblocks the read.
 */
final class MavenInvocation {

    private static final Logger log = LoggerFactory.getLogger(MavenInvocation.class);

    /**
     * Ceiling on captured output. A Maven that cannot reach a repository repeats itself per
     * artifact, and the useful part — what it could not do and why — is in the first few
     * hundred lines. Reading without a bound would let a pathological run exhaust the heap of
     * an application that otherwise runs comfortably small.
     */
    private static final int MAX_CAPTURED_CHARS = 200_000;

    /**
     * The {@code mvn} each thread currently has running, so a run can be stopped from outside
     * the thread executing it.
     *
     * <p>Keyed by thread rather than held as a single reference because "Test Maven" runs its
     * invocations on a request thread while probes run on their own; one shared slot would let
     * a cancelled probe kill somebody's settings test. Probes are serialised on one thread, so
     * within the probe path there is only ever one entry.
     */
    private static final ConcurrentHashMap<Thread, Process> RUNNING = new ConcurrentHashMap<>();

    private MavenInvocation() {
    }

    /**
     * Destroys {@code process} <b>and everything it started</b>.
     *
     * <p>{@code destroyForcibly()} on its own terminates the named process and nothing beneath
     * it. That is not enough here: on Windows the configured executable is {@code mvn.cmd}, a
     * batch wrapper whose actual work is a {@code java} grandchild, so killing the wrapper
     * leaves the real Maven running — holding the repository, the network connection and the
     * CPU, with nothing left tracking it. It is precisely the orphaned process this is meant
     * to prevent, produced by the code meant to prevent it.
     *
     * <p>Descendants are taken first: destroying the parent reparents them, and the handle to
     * walk them from is gone by the time you look.
     */
    static void destroyTree(Process process) {
        process.descendants().forEach(ProcessHandle::destroyForcibly);
        process.destroyForcibly();
    }

    /**
     * Kills whatever {@code mvn} the given thread is running right now, if any.
     *
     * <p>This is what makes a probe cancellable at all. Interrupting the thread does not do it:
     * it is blocked reading the child's output, and a stream read does not answer an interrupt.
     * Killing the child closes the stream — the same mechanism the timeout watchdog relies on,
     * for the same reason.
     *
     * @return whether there was a process to kill
     */
    static boolean cancelRunningOn(Thread thread) {
        Process process = RUNNING.get(thread);
        if (process == null) {
            return false;
        }
        log.info("Stopping the mvn process running on {} at the caller's request", thread.getName());
        destroyTree(process);
        return true;
    }

    /**
     * @param startFailed the executable could not be started at all — a wrong path, not a
     *                    Maven failure, and the one case with no process output to report
     * @param output      stdout and stderr interleaved as Maven wrote them, truncated at
     *                    {@link #MAX_CAPTURED_CHARS}
     * @param startError  the launch failure's own message; null unless {@code startFailed}
     */
    record Result(boolean startFailed, boolean timedOut, int exitCode, String output, String startError) {

        boolean ok() {
            return !startFailed && !timedOut && exitCode == 0;
        }

        /**
         * Boilerplate Maven prints after every failure, in the order it prints it.
         *
         * <p>Not errors — advice about re-running with {@code -e} and a link to a wiki page.
         */
        private static final List<String> BOILERPLATE = List.of(
                "-> [help",
                "to see the full stack trace",
                "re-run maven using",
                "for more information about the errors",
                "[help ");

        /**
         * The line that actually says what went wrong.
         *
         * <p><b>The first informative {@code [ERROR]} line, not the last one.</b> This read the
         * last non-blank line, borrowed from the osv-scanner contract where errors genuinely do
         * come last — and Maven is the opposite: it ends every failure with four lines of advice
         * and a wiki URL, so a real PKIX failure was reported to the panel as
         * <em>"[ERROR] [Help 1] http://cwiki.apache.org/…/DependencyResolutionException"</em>.
         * Maven leads with its summary (<em>"Failed to execute goal on project probe: Could not
         * collect dependencies…"</em>), which is the line worth showing.
         *
         * <p>Falls back to the old behaviour when nothing matches, because a wrong-but-present
         * line still beats an empty message.
         */
        String lastMeaningfulLine() {
            if (startFailed) {
                return startError == null ? "mvn could not be started." : startError;
            }
            String trimmed = output == null ? "" : output.strip();
            if (trimmed.isEmpty()) {
                return "mvn exited " + exitCode + " with no output.";
            }
            String[] lines = trimmed.split("\n");

            for (String line : lines) {
                String candidate = line.strip();
                String withoutPrefix = candidate.replaceFirst("(?i)^\\[error]\\s*", "").strip();
                if (!candidate.regionMatches(true, 0, "[ERROR]", 0, 7) || withoutPrefix.isEmpty()) {
                    continue;
                }
                String lowered = withoutPrefix.toLowerCase(Locale.ROOT);
                if (BOILERPLATE.stream().noneMatch(lowered::startsWith)) {
                    return candidate;
                }
            }

            for (int i = lines.length - 1; i >= 0; i--) {
                if (!lines[i].isBlank()) {
                    return lines[i].strip();
                }
            }
            return trimmed;
        }
    }

    /**
     * Runs {@code command}, capturing everything it printed.
     *
     * <p>The command line is logged before the run and the outcome after it, both at INFO, so
     * the main log always shows what was asked of Maven and what came back. <b>The full output
     * is logged at WARN whenever the invocation fails</b> — the case somebody is actually
     * diagnosing — and at DEBUG when it succeeds, so a working setup does not write a probe's
     * worth of Maven chatter into the log on every candidate. Raise
     * {@code logging.level.dev.sbomscope.probe} to DEBUG to capture successful runs too.
     *
     * @param description what this invocation is for, in the log line — e.g. "dependency:tree"
     */
    static Result run(String description, List<String> command, Path workingDirectory, Duration timeout) {
        // Logged in full: the whole point is that somebody can copy this line into a terminal
        // and reproduce it by hand. The isolated repository and any -P profiles are already
        // arguments, so they appear here without being called out separately.
        log.info("mvn {} — running: {}{}", description, String.join(" ", command),
                workingDirectory == null ? "" : " (in " + workingDirectory + ")");

        ProcessBuilder builder = new ProcessBuilder(command);
        builder.redirectErrorStream(true);
        if (workingDirectory != null) {
            builder.directory(workingDirectory.toFile());
        }

        Process process;
        try {
            process = builder.start();
        } catch (IOException e) {
            log.warn("mvn {} — could not start {}: {}", description, command.getFirst(), e.getMessage());
            return new Result(true, false, -1, "", e.getMessage());
        }

        long startedAt = System.nanoTime();
        AtomicBoolean destroyedByWatchdog = new AtomicBoolean();
        Thread watchdog = startWatchdog(process, timeout, description, destroyedByWatchdog);
        // Published only for the window this call owns the process, and removed in every exit
        // path below, so a cancellation arriving between invocations finds nothing to kill
        // rather than a handle to a process that has already gone.
        RUNNING.put(Thread.currentThread(), process);

        String output;
        try {
            output = drain(process);
        } catch (IOException e) {
            destroyTree(process);
            watchdog.interrupt();
            RUNNING.remove(Thread.currentThread());
            log.warn("mvn {} — failed while reading output: {}", description, e.getMessage());
            return new Result(false, false, -1, "", "Failed while reading mvn output: " + e.getMessage());
        }

        boolean interrupted = false;
        int exitCode = -1;
        try {
            // The stream is at EOF, so the process has either exited or been destroyed by the
            // watchdog; this returns promptly either way rather than waiting the full timeout.
            exitCode = process.waitFor();
        } catch (InterruptedException e) {
            interrupted = true;
            destroyTree(process);
            Thread.currentThread().interrupt();
        } finally {
            watchdog.interrupt();
            RUNNING.remove(Thread.currentThread());
        }

        Duration took = Duration.ofNanos(System.nanoTime() - startedAt);
        if (interrupted) {
            log.warn("mvn {} — interrupted after {} ms", description, took.toMillis());
            return new Result(false, false, -1, output, null);
        }

        // A destroyed process reports a nonzero exit like any other failure, so "did the
        // watchdog fire" is asked of the watchdog, not inferred from the exit code.
        Result result = new Result(false, destroyedByWatchdog.get(), exitCode, output, null);

        if (result.ok()) {
            log.info("mvn {} — exit 0 in {} ms, {} chars of output",
                    description, took.toMillis(), output.length());
            if (log.isDebugEnabled() && !output.isBlank()) {
                log.debug("mvn {} — output:\n{}", description, output);
            }
        } else {
            log.warn("mvn {} — {} after {} ms. Command: {}", description,
                    result.timedOut() ? "timed out" : "exit " + exitCode, took.toMillis(),
                    String.join(" ", command));
            // Full output, not the last line: on a machine that cannot reach a repository the
            // last line is a generic "see the errors above", and the errors above are the answer.
            log.warn("mvn {} — output:\n{}", description,
                    output.isBlank() ? "(mvn printed nothing)" : output);
        }
        return result;
    }

    /** Reads the merged stream to EOF, stopping at the cap and saying so in the text itself. */
    private static String drain(Process process) throws IOException {
        StringBuilder captured = new StringBuilder();
        char[] buffer = new char[8192];
        boolean truncated = false;

        try (Reader reader = new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8)) {
            int read;
            while ((read = reader.read(buffer)) != -1) {
                if (captured.length() < MAX_CAPTURED_CHARS) {
                    captured.append(buffer, 0, Math.min(read, MAX_CAPTURED_CHARS - captured.length()));
                } else {
                    // Keep draining rather than breaking out: an undrained pipe blocks the
                    // child, which is the deadlock this class exists to avoid.
                    truncated = true;
                }
            }
        }
        if (truncated) {
            captured.append("\n… truncated at ").append(MAX_CAPTURED_CHARS).append(" characters.");
        }
        return captured.toString();
    }

    /**
     * Destroys the process once the timeout passes, which closes the stream and so unblocks
     * the read in {@link #run}. {@code destroyed} is how the caller tells a timeout apart from
     * an ordinary nonzero exit, since a destroyed process reports one of those too.
     */
    private static Thread startWatchdog(Process process, Duration timeout, String description,
                                         AtomicBoolean destroyed) {
        Thread watchdog = new Thread(() -> {
            try {
                if (!process.waitFor(timeout.toMillis(), TimeUnit.MILLISECONDS)) {
                    destroyed.set(true);
                    log.warn("mvn {} — exceeded {} s, destroying it and everything it started",
                            description, timeout.toSeconds());
                    destroyTree(process);
                }
            } catch (InterruptedException e) {
                // The process finished on its own and run() is tidying up.
                Thread.currentThread().interrupt();
            }
        }, "maven-probe-watchdog");
        watchdog.setDaemon(true);
        watchdog.start();
        return watchdog;
    }
}
