package dev.sbomscope.reachability;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Comparator;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import org.junit.jupiter.api.Test;

import tools.jackson.databind.ObjectMapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ReachabilityWorkerInvocationTest {

    private final Path temp = Path.of("target", "reachability-worker-test-" + UUID.randomUUID());

    @Test
    void startsTheSameApplicationInWorkerModeWithoutStartingSpring() throws Exception {
        ReachabilityWorkerInvocation invocation = new ReachabilityWorkerInvocation(new ObjectMapper(), temp.toString());
        WorkspaceAnalysisInputs inputs = new WorkspaceAnalysisInputs(List.of(), List.of(), List.of(), Set.of(), "test");

        ReachabilityWorkerInvocation.Running running = invocation.start(inputs, 256);
        try {
            assertThat(running.await(Duration.ofSeconds(30))).isTrue();
            String errorOutput = Files.readString(running.error());
            assertThat(running.process().exitValue())
                    .withFailMessage("Worker command: %s%nWorker stderr:%n%s", running.command(), errorOutput)
                    .isZero();
            assertThat(invocation.read(running)).satisfies(result -> {
                assertThat(result.engine()).isEqualTo("WALA 1.8.0");
                assertThat(result.components()).isEmpty();
            });
            assertThat(invocation.failureMessage(running)).isEqualTo("The isolated worker exited without a diagnostic.");
        } finally {
            invocation.cleanUp(running);
            deleteBestEffort(temp);
        }
    }

    @Test
    void rejectsAnUnboundedWorkerResultBeforeDeserializingIt() throws Exception {
        Files.createDirectories(temp);
        Path output = temp.resolve("oversized-output.json");
        try (var channel = java.nio.channels.FileChannel.open(output,
                java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.WRITE)) {
            channel.position(ReachabilityWorkerInvocation.MAX_RESULT_BYTES);
            channel.write(java.nio.ByteBuffer.wrap(new byte[] { 0 }));
        }
        ReachabilityWorkerInvocation invocation = new ReachabilityWorkerInvocation(new ObjectMapper(), temp.toString());

        assertThatThrownBy(() -> invocation.readResult(output))
                .isInstanceOf(java.io.IOException.class)
                .hasMessageContaining("16 MiB");

        deleteBestEffort(temp);
    }

    @Test
    void capsWorkerDiagnosticsOnDiskWhileContinuingToDrainTheStream() throws Exception {
        Files.createDirectories(temp);
        byte[] diagnostic = "failure detail\n".repeat(10_000).getBytes(StandardCharsets.UTF_8);
        Path error = temp.resolve("stderr.log");

        ReachabilityWorkerInvocation.drainDiagnostic(new java.io.ByteArrayInputStream(diagnostic), error);

        assertThat(Files.size(error)).isLessThanOrEqualTo(ReachabilityWorkerInvocation.MAX_DIAGNOSTIC_BYTES);
        assertThat(Files.readString(error)).endsWith("[diagnostic truncated]\n");
        deleteBestEffort(temp);
    }

    @Test
    void readsOnlyABoundedFailureMessagePrefix() throws Exception {
        Files.createDirectories(temp);
        Path error = temp.resolve("large-stderr.log");
        Files.writeString(error, "first useful failure\n" + "x".repeat(ReachabilityWorkerInvocation.MAX_DIAGNOSTIC_BYTES));
        ReachabilityWorkerInvocation invocation = new ReachabilityWorkerInvocation(new ObjectMapper(), temp.toString());

        assertThat(invocation.failureMessage(error)).isEqualTo("first useful failure");
        deleteBestEffort(temp);
    }

    private static void deleteBestEffort(Path directory) throws Exception {
        if (!Files.exists(directory)) return;
        try (var files = Files.walk(directory)) {
            files.sorted(Comparator.reverseOrder()).forEach(path -> {
                try {
                    Files.deleteIfExists(path);
                } catch (Exception ignored) {
                    // A just-exited child JVM may briefly retain a Windows directory handle.
                }
            });
        }
    }
}
