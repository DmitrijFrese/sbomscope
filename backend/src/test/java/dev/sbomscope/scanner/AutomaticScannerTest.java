package dev.sbomscope.scanner;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Test;

import dev.sbomscope.logging.ActivityLogger;
import dev.sbomscope.settings.ScannerSettingsChangedEvent;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The automatic scanner, with the scan itself stubbed out.
 *
 * <p>What is worth pinning here is not that osv-scanner works — that is covered against real
 * fixtures elsewhere — but the three decisions this class makes: that a machine which cannot
 * scan is left alone silently, that a failure nobody is waiting for cannot escape and take a
 * thread with it, and that startup queues exactly the SBOMs with a gap in them.
 */
class AutomaticScannerTest {

    private final ScanService scans = mock(ScanService.class);
    private final VulnerabilityRepository repository = mock(VulnerabilityRepository.class);
    private final ActivityLogger activityLog = mock(ActivityLogger.class);

    private final AutomaticScanner scanner = new AutomaticScanner(scans, repository, activityLog);

    private final UUID sbomId = UUID.randomUUID();

    private void ready(UUID id) {
        when(scans.readiness(id)).thenReturn(ScanService.ScanReadiness.ok());
    }

    private void blocked(UUID id, String reason) {
        when(scans.readiness(id)).thenReturn(ScanService.ScanReadiness.blocked(reason, null));
    }

    private void scanReturns(UUID id) {
        when(scans.scan(id)).thenReturn(new ScanService.ScanResult(3, 1, Instant.now(), "v2.4.0"));
    }

    /** The work runs on its own thread, so the assertion has to wait for it to drain. */
    private void awaitIdle() {
        long deadline = System.currentTimeMillis() + 5_000;
        while (!scanner.inFlight().isEmpty() && System.currentTimeMillis() < deadline) {
            Thread.onSpinWait();
        }
        assertThat(scanner.inFlight()).as("still in flight after 5s").isEmpty();
    }

    @Test
    void doesNothingAtAllWhenAScanCouldNotRun() {
        // Not an error that a machine without a scanner did not scan, so there is nothing to
        // report — and nothing may be marked as scanning either, or the card would promise an
        // answer that is never coming.
        blocked(sbomId, "SCANNING_DISABLED");

        scanner.scanLater(sbomId, AutomaticScanner.Trigger.UPLOAD);

        assertThat(scanner.isInFlight(sbomId)).isFalse();
        verify(scans, never()).scan(any());
    }

    @Test
    void scansAndThenClearsTheMarker() {
        ready(sbomId);
        scanReturns(sbomId);

        scanner.scanLater(sbomId, AutomaticScanner.Trigger.UPLOAD);
        awaitIdle();

        verify(scans).scan(sbomId);
        // The trigger is what this entry exists to record; the counts are the scan's own entry.
        verify(activityLog).record(eq(ActivityLogger.Category.PROCESS), eq("AUTO_SCAN"),
                eq("STARTED"), contains("newly uploaded"));
    }

    @Test
    void aFailureIsRecordedAndDoesNotEscapeTheWorker() {
        // Nothing is waiting on this answer, so a thrown exception would reach nobody — but
        // an external process still ran, so it is still written down.
        ready(sbomId);
        when(scans.scan(sbomId)).thenThrow(new OsvScannerException("the binary has moved"));

        scanner.scanLater(sbomId, AutomaticScanner.Trigger.STARTUP);
        awaitIdle();

        verify(activityLog).record(eq(ActivityLogger.Category.PROCESS), eq("AUTO_SCAN"),
                eq("FAILURE"), contains("the binary has moved"));
    }

    @Test
    void queuesEverySbomWithAComponentNothingHasEverChecked() {
        UUID other = UUID.randomUUID();
        when(repository.sbomIdsWithUnscannedComponents()).thenReturn(List.of(sbomId, other));
        ready(sbomId);
        ready(other);
        scanReturns(sbomId);
        scanReturns(other);

        scanner.scanUnscannedAtStartup();
        awaitIdle();

        verify(scans).scan(sbomId);
        verify(scans).scan(other);
    }

    @Test
    void configuringTheScannerQueuesWhatWasSkippedWhileItWasNotConfigured() {
        // The gap this closes: scanLater declines silently when readiness is not met, so an
        // SBOM uploaded with no scanner configured stayed unscanned until the next restart,
        // showing an empty table that reads as "nothing found". Configuring the scanner is
        // the moment the obstacle goes away, and it has to be what re-runs the sweep.
        when(repository.sbomIdsWithUnscannedComponents()).thenReturn(List.of(sbomId));
        ready(sbomId);
        scanReturns(sbomId);

        scanner.scanUnscannedAfterSettingsChange(new ScannerSettingsChangedEvent());
        awaitIdle();

        verify(scans).scan(sbomId);
        verify(activityLog).record(eq(ActivityLogger.Category.PROCESS), eq("AUTO_SCAN"),
                eq("STARTED"), contains("scanner settings changing"));
    }

    @Test
    void aSettingsChangeThatFixesNothingQueuesNothing() {
        // Saving the panel is not evidence that anything became scannable. Every SBOM already
        // has a scan row here, so the sweep must find nothing to do rather than re-scanning
        // the world on every save — re-running analysis stays the manual button.
        when(repository.sbomIdsWithUnscannedComponents()).thenReturn(List.of());

        scanner.scanUnscannedAfterSettingsChange(new ScannerSettingsChangedEvent());

        assertThat(scanner.inFlight()).isEmpty();
        verify(scans, never()).scan(any());
    }

    @Test
    void doesNotQueueTheSameSbomTwiceWhileOneIsStillPending() throws Exception {
        // Reachable in ordinary use: an upload queues one, and a startup sweep or a second
        // upload of the same document can arrive while it is still waiting its turn.
        //
        // The latch is what makes this deterministic rather than a race — without it the
        // first scan could finish before the second call arrives, and the test would be
        // asserting nothing.
        CountDownLatch secondCallMade = new CountDownLatch(1);
        ready(sbomId);
        when(scans.scan(sbomId)).thenAnswer(invocation -> {
            secondCallMade.await(5, TimeUnit.SECONDS);
            return new ScanService.ScanResult(3, 1, Instant.now(), "v2.4.0");
        });

        scanner.scanLater(sbomId, AutomaticScanner.Trigger.UPLOAD);
        scanner.scanLater(sbomId, AutomaticScanner.Trigger.STARTUP);
        secondCallMade.countDown();
        awaitIdle();

        verify(scans).scan(sbomId);
    }
}
