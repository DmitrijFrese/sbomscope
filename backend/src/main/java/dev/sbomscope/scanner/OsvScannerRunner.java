package dev.sbomscope.scanner;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import dev.sbomscope.logging.ActivityLogger;
import dev.sbomscope.settings.ScannerSettings;

/**
 * Runs the external osv-scanner binary.
 *
 * <p>The binary is launched directly through {@link ProcessBuilder}, never via a shell,
 * so a path containing spaces or shell metacharacters cannot turn into command
 * injection.
 */
@Component
public class OsvScannerRunner {

    private static final Logger log = LoggerFactory.getLogger(OsvScannerRunner.class);

    private static final Duration VERSION_TIMEOUT = Duration.ofSeconds(20);
    private static final Duration SCAN_TIMEOUT = Duration.ofMinutes(10);

    /**
     * osv-scanner reports findings through its exit code: 0 means it ran and found
     * nothing, 1 means it ran and found vulnerabilities. Treating 1 as failure is the
     * classic mistake — it would make every genuinely vulnerable project look like a
     * broken scan.
     */
    private static final int EXIT_NO_VULNERABILITIES = 0;
    private static final int EXIT_VULNERABILITIES_FOUND = 1;

    private final ActivityLogger activityLog;

    public OsvScannerRunner(ActivityLogger activityLog) {
        this.activityLog = activityLog;
    }

    /** Runs {@code --version}, both to confirm the path works and to record what ran. */
    public String version(String executablePath) {
        Result result = run(List.of(executablePath, "--version"), null, VERSION_TIMEOUT);

        if (result.exitCode() != 0) {
            throw new OsvScannerException(
                    "That file did not respond to --version (exit %d). %s"
                            .formatted(result.exitCode(), lastLine(result.stderr())));
        }

        String reported = firstLine(result.stdout());
        if (reported.isBlank()) {
            reported = lastLine(result.stderr());
        }
        if (!reported.toLowerCase().contains("osv-scanner")) {
            throw new OsvScannerException(
                    "That binary does not identify itself as osv-scanner. It reported: " + reported);
        }
        return reported;
    }

    /**
     * Scans an SBOM offline and returns the scanner's JSON report.
     *
     * @param sbomFile a CycloneDX document on disk; osv-scanner accepts an SBOM directly,
     *                 so no lockfile is required
     */
    public String scan(Path sbomFile, ScannerSettings settings) {
        requireDatabase(settings);

        List<String> command = List.of(
                settings.executablePath(),
                "scan",
                "--lockfile", sbomFile.toAbsolutePath().toString(),
                // No network access at any point, per the offline-first constraint.
                "--offline",
                "--format", "json");

        Result result = run(command, settings.databaseDirectory(), SCAN_TIMEOUT);

        if (result.exitCode() != EXIT_NO_VULNERABILITIES
                && result.exitCode() != EXIT_VULNERABILITIES_FOUND) {
            throw new OsvScannerException(
                    "osv-scanner failed (exit %d). %s"
                            .formatted(result.exitCode(), lastLine(result.stderr())));
        }

        if (result.stdout().isBlank()) {
            throw new OsvScannerException(
                    "osv-scanner produced no output. " + lastLine(result.stderr()));
        }
        return result.stdout();
    }

    private void requireDatabase(ScannerSettings settings) {
        Path directory = Path.of(settings.databaseDirectory());
        if (!Files.isDirectory(directory)) {
            throw new OsvScannerException(
                    "No offline vulnerability database at %s. Download it from Settings before scanning."
                            .formatted(directory));
        }
    }

    /**
     * Wraps {@link #execute} to record every invocation to the activity log — every caller
     * of {@code run} launches an external process, and that is exactly one of the three
     * things the activity log exists to catch.
     */
    private Result run(List<String> command, String databaseDirectory, Duration timeout) {
        String invocation = String.join(" ", command.subList(1, command.size()));
        try {
            Result result = execute(command, databaseDirectory, timeout);
            activityLog.record(ActivityLogger.Category.PROCESS, "OSV_SCANNER", "SUCCESS",
                    "%s (exit %d)".formatted(invocation, result.exitCode()));
            return result;
        } catch (OsvScannerException e) {
            activityLog.record(ActivityLogger.Category.PROCESS, "OSV_SCANNER", "FAILURE",
                    "%s: %s".formatted(invocation, e.getMessage()));
            throw e;
        }
    }

    private Result execute(List<String> command, String databaseDirectory, Duration timeout) {
        ProcessBuilder builder = new ProcessBuilder(command);
        if (databaseDirectory != null) {
            // How osv-scanner is told where the offline database lives.
            builder.environment().put("OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY", databaseDirectory);
        }

        Process process;
        try {
            process = builder.start();
        } catch (IOException e) {
            throw new OsvScannerException(
                    "Could not start osv-scanner at %s: %s".formatted(command.getFirst(), e.getMessage()), e);
        }

        try {
            // Drain both streams before waiting: a full pipe buffer would deadlock the
            // child process, and the JSON report can be large.
            String stdout = read(process.getInputStream());
            String stderr = read(process.getErrorStream());

            if (!process.waitFor(timeout.toMillis(), TimeUnit.MILLISECONDS)) {
                process.destroyForcibly();
                throw new OsvScannerException(
                        "osv-scanner did not finish within " + timeout.toMinutes() + " minutes.");
            }
            return new Result(process.exitValue(), stdout, stderr);

        } catch (IOException e) {
            process.destroyForcibly();
            throw new OsvScannerException("Failed while reading osv-scanner output.", e);
        } catch (InterruptedException e) {
            process.destroyForcibly();
            Thread.currentThread().interrupt();
            throw new OsvScannerException("Interrupted while waiting for osv-scanner.", e);
        }
    }

    private String read(InputStream stream) throws IOException {
        try (stream) {
            return new String(stream.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    /** First line of stdout — where {@code --version} prints its answer. */
    private String firstLine(String text) {
        if (text == null || text.isBlank()) {
            return "";
        }
        String trimmed = text.strip();
        int newline = trimmed.indexOf('\n');
        return (newline >= 0 ? trimmed.substring(0, newline) : trimmed).strip();
    }

    /**
     * The <em>last</em> line of output, not the first.
     *
     * <p>osv-scanner writes progress to stderr before anything goes wrong — "Starting
     * filesystem walk…" and similar — so reporting the first line reliably hides the
     * actual failure that follows it. That cost real debugging time: a format-detection
     * failure surfaced as an unhelpful progress message.
     */
    private String lastLine(String text) {
        if (text == null || text.isBlank()) {
            return "";
        }
        String trimmed = text.strip();
        if (log.isDebugEnabled()) {
            log.debug("osv-scanner output: {}", trimmed);
        }
        int newline = trimmed.lastIndexOf('\n');
        return (newline >= 0 ? trimmed.substring(newline + 1) : trimmed).strip();
    }

    private record Result(int exitCode, String stdout, String stderr) {}
}
