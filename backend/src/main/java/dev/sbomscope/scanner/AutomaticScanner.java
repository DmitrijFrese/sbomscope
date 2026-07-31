package dev.sbomscope.scanner;

import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

import jakarta.annotation.PreDestroy;

import dev.sbomscope.logging.ActivityLogger;
import dev.sbomscope.settings.ScannerSettingsChangedEvent;

/**
 * Scans without being asked: after an upload, and at startup for anything never covered.
 *
 * <p><b>Why this is allowed at all.</b> Constraint 2 forbids <em>fetching</em> vulnerability
 * data automatically, and running osv-scanner against an archive already on disk fetches
 * nothing — it sends nothing anywhere, so there is nothing for anyone to consent to. The line
 * constraint 1 draws is what leaves the machine, not what the CPU does. Downloading an archive
 * stays strictly on request; analysing one does not.
 *
 * <p><b>Startup work begins only once the application is serving</b> — an
 * {@link ApplicationReadyEvent} listener rather than a constructor or {@code @PostConstruct}.
 * The objection to doing this at all was that it would land on launch, and starting after the
 * port is open is what answers it.
 *
 * <p><b>One at a time, on one thread.</b> A scan is an external process reading an archive of
 * several hundred megabytes; several at once would compete for the same disk to finish no
 * sooner. Serial also means the in-flight set is small enough to be worth showing.
 *
 * <p><b>Silence is the correct behaviour when nothing can run.</b> Readiness is checked per
 * SBOM and a blocked one is skipped without a message: it is not an error that a machine with
 * no scanner configured did not scan. Every run that <em>does</em> happen is written to the
 * activity log, because it starts an external process.
 *
 * <p>The manual re-scan is untouched. Filling a gap and deliberately re-running analysis
 * against a freshly downloaded archive are different needs, and only the first is automatic.
 */
@Component
public class AutomaticScanner {

    private static final Logger log = LoggerFactory.getLogger(AutomaticScanner.class);

    private final ScanService scans;
    private final VulnerabilityRepository repository;
    private final ActivityLogger activityLog;

    private final ExecutorService worker = Executors.newSingleThreadExecutor(runnable -> {
        Thread thread = new Thread(runnable, "sbomscope-auto-scan");
        // A daemon thread so a scan in flight cannot hold the JVM open after shutdown; the
        // work is resumable by construction, since an unscanned component stays unscanned.
        thread.setDaemon(true);
        return thread;
    });

    /**
     * Submitted and not yet finished — queued and running together.
     *
     * <p>Not split into the two the way the probe queue is. There, the distinction was
     * load-bearing: reporting a queued probe as running claimed Maven was being invoked for
     * something that had not started. Here the sidebar says "scanning" on a card, and the
     * honest reading of that is "this document is being dealt with", which queued satisfies.
     */
    private final Set<UUID> inFlight = ConcurrentHashMap.newKeySet();

    AutomaticScanner(ScanService scans, VulnerabilityRepository repository, ActivityLogger activityLog) {
        this.scans = scans;
        this.repository = repository;
        this.activityLog = activityLog;
    }

    /**
     * Why a scan nobody pressed a button for is happening.
     *
     * <p>Recorded rather than inferred. The question the activity log has to answer is *"why
     * did an external process run when I did not ask for one"*, and the scan's own entry —
     * shared with the manual path — cannot answer it.
     */
    public enum Trigger {
        UPLOAD("a newly uploaded SBOM"),
        STARTUP("components that had never been scanned"),
        SCANNER_CONFIGURED("the scanner settings changing, leaving components never scanned");

        private final String description;

        Trigger(String description) {
            this.description = description;
        }
    }

    /** SBOMs currently queued or being scanned, for the sidebar to mark. */
    public Set<UUID> inFlight() {
        return Set.copyOf(inFlight);
    }

    public boolean isInFlight(UUID sbomId) {
        return inFlight.contains(sbomId);
    }

    /**
     * Queues a scan for one SBOM, if one is not already queued for it.
     *
     * <p>Returns immediately: the upload response must not wait on an external process, which
     * would make importing a document take as long as scanning it.
     */
    public void scanLater(UUID sbomId, Trigger trigger) {
        // Checked here as well as in the worker, so a machine with no scanner does not show
        // every uploaded card as "scanning" for the moment it takes to find that out.
        if (!scans.readiness(sbomId).ready() || !inFlight.add(sbomId)) {
            return;
        }
        try {
            worker.execute(() -> run(sbomId, trigger));
        } catch (RejectedExecutionException e) {
            // Shutting down. Nothing is lost: the components stay unscanned and the next
            // startup picks them up again.
            inFlight.remove(sbomId);
        }
    }

    /**
     * At startup, every SBOM holding a component nothing has ever checked.
     *
     * <p>Deliberately "never scanned" rather than "stale". A stale result is a real answer
     * that has aged, and re-running analysis against a refreshed archive is a decision with a
     * cost — that stays the manual button. A component with no scan row at all is a gap, and
     * a gap in a vulnerability tool reads as "nothing found" to anyone who does not know to
     * look for the difference.
     */
    @EventListener(ApplicationReadyEvent.class)
    void scanUnscannedAtStartup() {
        queueUnscanned(Trigger.STARTUP);
    }

    /**
     * The same sweep, when the scanner settings change.
     *
     * <p>Closes a gap the startup sweep could not: {@link #scanLater} declines silently when
     * readiness is not met, so an SBOM uploaded before osv-scanner was configured stayed
     * unscanned until the next restart — with nothing on screen to say the automation had
     * skipped it, which is precisely the "reads as nothing found" failure the startup sweep
     * exists to prevent. Configuring the scanner is the moment the obstacle goes away.
     *
     * <p><b>After the commit, not on publication.</b> {@code updateScannerSettings} is
     * transactional, and the scan runs on another thread with its own connection — queued
     * before the commit, it would re-check readiness against the settings as they were and
     * decline again, turning the fix into a no-op that looks like the original bug.
     * {@code fallbackExecution} keeps it working where there is no transaction at all.
     */
    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT, fallbackExecution = true)
    void scanUnscannedAfterSettingsChange(ScannerSettingsChangedEvent event) {
        queueUnscanned(Trigger.SCANNER_CONFIGURED);
    }

    private void queueUnscanned(Trigger trigger) {
        List<UUID> pending = repository.sbomIdsWithUnscannedComponents();
        if (pending.isEmpty()) {
            return;
        }
        log.info("{} SBOM(s) have components that have never been scanned; queueing", pending.size());
        pending.forEach(sbomId -> scanLater(sbomId, trigger));
    }

    private void run(UUID sbomId, Trigger trigger) {
        try {
            // Re-checked immediately before running: settings can have changed while this sat
            // in the queue, and the archive it needs can have been erased from Settings.
            if (!scans.readiness(sbomId).ready()) {
                return;
            }

            // Written before the scan, not after, and carrying the trigger rather than the
            // result. The scan writes its own entry with the counts, so repeating them here
            // would put the same numbers in the log twice while still leaving unanswered the
            // only thing this entry exists for.
            activityLog.record(ActivityLogger.Category.PROCESS, "AUTO_SCAN", "STARTED",
                    "SBOM %s, prompted by %s".formatted(sbomId, trigger.description));

            scans.scan(sbomId);
        } catch (RuntimeException e) {
            // Nothing asked for this, so nothing is waiting for the answer — but it still
            // happened and still ran an external process, so it is still recorded. Swallowed
            // rather than rethrown because an uncaught exception here would say nothing to
            // anybody and the executor would carry on regardless.
            log.warn("Automatic scan of SBOM {} failed", sbomId, e);
            activityLog.record(ActivityLogger.Category.PROCESS, "AUTO_SCAN", "FAILURE",
                    "SBOM %s: %s".formatted(sbomId, e.getMessage()));
        } finally {
            inFlight.remove(sbomId);
        }
    }

    @PreDestroy
    void stop() {
        worker.shutdownNow();
        try {
            worker.awaitTermination(2, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
