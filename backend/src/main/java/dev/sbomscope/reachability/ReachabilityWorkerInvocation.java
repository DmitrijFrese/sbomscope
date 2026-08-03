package dev.sbomscope.reachability;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.jar.JarFile;

import tools.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import dev.sbomscope.SbomscopeApplication;

/** Starts and, when asked, safely destroys a separate SBOMscope WALA worker JVM. */
@Component
public class ReachabilityWorkerInvocation {

    static final long MAX_RESULT_BYTES = 16L * 1024 * 1024;
    static final int MAX_DIAGNOSTIC_BYTES = 64 * 1024;
    static final int MAX_FAILURE_MESSAGE_BYTES = 8 * 1024;
    private static final byte[] TRUNCATED_DIAGNOSTIC = "\n[diagnostic truncated]\n"
            .getBytes(StandardCharsets.UTF_8);

    private final ObjectMapper mapper;
    private final Path workerDirectory;

    ReachabilityWorkerInvocation(ObjectMapper mapper, @Value("${sbomscope.data-directory:${user.home}/.sbomscope}") String dataDirectory) {
        this.mapper = mapper;
        this.workerDirectory = Path.of(dataDirectory).resolve("reachability-workers");
    }

    public Running start(WorkspaceAnalysisInputs inputs, int maxHeapMegabytes) throws IOException {
        Files.createDirectories(workerDirectory);
        Path directory = Files.createTempDirectory(workerDirectory, "run-");
        Path input = directory.resolve("input.json");
        Path output = directory.resolve("output.json");
        Path error = directory.resolve("stderr.log");
        mapper.writeValue(input.toFile(), ReachabilityWorkerMain.requestFor(inputs));
        List<String> command = command(input, output, maxHeapMegabytes);
        Process process = new ProcessBuilder(command)
                .redirectOutput(ProcessBuilder.Redirect.DISCARD)
                .redirectError(ProcessBuilder.Redirect.PIPE)
                .start();
        Thread diagnosticPump = new Thread(
                () -> drainDiagnostic(process.getErrorStream(), error),
                "sbomscope-reachability-worker-stderr-" + process.pid());
        diagnosticPump.setDaemon(true);
        diagnosticPump.start();
        return new Running(process, output, error, directory, command, diagnosticPump);
    }

    private List<String> command(Path input, Path output, int maxHeapMegabytes) {
        String java = Path.of(System.getProperty("java.home"), "bin", "java").toString();
        List<String> command = new ArrayList<>(List.of(java, "-Xmx%dm".formatted(maxHeapMegabytes)));
        Path executableArchive = springBootArchiveOnClassPath();
        if (executableArchive != null && isSpringBootArchive(executableArchive)) {
            // A Spring Boot executable jar keeps application classes under BOOT-INF/classes,
            // so it cannot be used as an ordinary -cp entry. JarLauncher recreates the same
            // class path that `java -jar` used for this parent process.
            command.addAll(List.of("-cp", executableArchive.toString(),
                    "org.springframework.boot.loader.launch.JarLauncher"));
        } else {
            Path application = applicationCodeSource();
            if (Files.isRegularFile(application)) {
                command.addAll(List.of("-jar", application.toString()));
            } else {
                command.addAll(List.of("-cp", System.getProperty("java.class.path"), "dev.sbomscope.SbomscopeApplication"));
            }
        }
        command.addAll(List.of(ReachabilityWorkerMain.SWITCH, input.toString(), output.toString()));
        return command;
    }

    private Path springBootArchiveOnClassPath() {
        String classPath = System.getProperty("java.class.path", "");
        for (String entry : classPath.split(java.util.regex.Pattern.quote(System.getProperty("path.separator")))) {
            Path archive = Path.of(entry);
            if (Files.isRegularFile(archive) && isSpringBootArchive(archive)) return archive;
        }
        return null;
    }

    private boolean isSpringBootArchive(Path archive) {
        try (JarFile jar = new JarFile(archive.toFile())) {
            return jar.getJarEntry("BOOT-INF/classes/") != null;
        } catch (IOException ignored) {
            return false;
        }
    }

    private Path applicationCodeSource() {
        try {
            return Path.of(SbomscopeApplication.class.getProtectionDomain().getCodeSource().getLocation().toURI());
        } catch (Exception e) {
            throw new IllegalStateException("Could not locate the SBOMscope application to start the reachability worker", e);
        }
    }

    public record Running(Process process, Path output, Path error, Path directory, List<String> command,
                          Thread diagnosticPump) {
        public boolean await(Duration timeout) throws InterruptedException {
            boolean finished = process.waitFor(timeout.toMillis(), TimeUnit.MILLISECONDS);
            if (finished) diagnosticPump.join();
            return finished;
        }

        public void stop() {
            process.descendants().forEach(ProcessHandle::destroyForcibly);
            process.destroyForcibly();
            try {
                process.waitFor(5, TimeUnit.SECONDS);
                diagnosticPump.join(1_000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    public ReachabilityWorkerResult read(Running running) throws IOException {
        return readResult(running.output());
    }

    ReachabilityWorkerResult readResult(Path output) throws IOException {
        long size = Files.size(output);
        if (size > MAX_RESULT_BYTES) {
            throw new IOException("Workspace call-graph worker result exceeded the 16 MiB safety limit.");
        }
        return mapper.readValue(output.toFile(), ReachabilityWorkerResult.class);
    }

    /** A bounded worker diagnostic, captured before the parent clears its temporary files. */
    public String failureMessage(Running running) {
        return failureMessage(running.error());
    }

    String failureMessage(Path error) {
        try {
            byte[] diagnostic;
            try (InputStream input = Files.newInputStream(error)) {
                diagnostic = input.readNBytes(MAX_FAILURE_MESSAGE_BYTES);
            }
            String message = new String(diagnostic, StandardCharsets.UTF_8).trim();
            if (message.isBlank()) return "The isolated worker exited without a diagnostic.";
            return message.lines().filter(line -> !line.isBlank()).findFirst().orElse("The isolated worker failed.");
        } catch (IOException ignored) {
            return "The isolated worker failed and its diagnostic could not be read.";
        }
    }

    static void drainDiagnostic(InputStream source, Path destination) {
        try (source; OutputStream output = Files.newOutputStream(destination)) {
            byte[] buffer = new byte[8192];
            int contentLimit = MAX_DIAGNOSTIC_BYTES - TRUNCATED_DIAGNOSTIC.length;
            int written = 0;
            boolean truncated = false;
            int read;
            while ((read = source.read(buffer)) != -1) {
                int permitted = Math.min(read, Math.max(0, contentLimit - written));
                if (permitted > 0) {
                    output.write(buffer, 0, permitted);
                    written += permitted;
                }
                if (permitted < read) truncated = true;
            }
            if (truncated) output.write(TRUNCATED_DIAGNOSTIC);
        } catch (IOException ignored) {
            // Diagnostics are best-effort. The parent still has the exit status and a bounded fallback message.
        }
    }

    /** Best-effort deletion of the parent-owned request, result and worker stderr files. */
    public void cleanUp(Running running) {
        try (var files = Files.walk(running.directory())) {
            files.sorted(Comparator.reverseOrder()).forEach(path -> {
                try {
                    Files.deleteIfExists(path);
                } catch (IOException ignored) {
                    // A virus scanner can hold one of these short-lived diagnostic files on Windows.
                }
            });
        } catch (IOException ignored) {
            // The directory is diagnostic-only and lives under SBOMscope's own data directory.
        }
    }
}
