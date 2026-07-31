package dev.sbomscope.scanner;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.junit.jupiter.api.Test;

import dev.sbomscope.logging.ActivityLogger;
import dev.sbomscope.sbom.DependencyScope;
import dev.sbomscope.sbom.SbomFileStore;
import dev.sbomscope.sbom.SbomService;
import dev.sbomscope.sbom.StoredComponent;
import dev.sbomscope.settings.ScannerSettings;
import dev.sbomscope.settings.SettingsService;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * When results are worth re-running, and which of two reasons applies.
 *
 * <p>The interesting case is the one that was missing entirely: downloading a fresh archive
 * left every existing scan silently superseded, with nothing on screen to say so until the
 * seven-day clock happened to run out. A day-count notice is the wrong sentence for that —
 * these results are not old, they were produced against data this machine no longer has.
 */
class ScanStalenessTest {

    private static final String DB_DIR = "/tmp/osv-db";
    private static final int STALE_AFTER_DAYS = 7;

    private final SettingsService settings = mock(SettingsService.class);
    private final VulnerabilityRepository repository = mock(VulnerabilityRepository.class);
    private final SbomService sboms = mock(SbomService.class);
    private final OsvDatabaseService databases = mock(OsvDatabaseService.class);

    private final ScanService scans = new ScanService(
            settings, mock(OsvScannerRunner.class), mock(OsvReportParser.class), repository,
            sboms, mock(SbomFileStore.class), databases, mock(OsvArchiveMatcher.class),
            mock(ActivityLogger.class), STALE_AFTER_DAYS);

    private final UUID sbomId = UUID.randomUUID();

    private void scannedAt(Instant when) {
        when(repository.lastScannedAt(sbomId)).thenReturn(Optional.ofNullable(when));
    }

    /** A Maven-only SBOM, so only the Maven archive is relevant to it. */
    private void mavenSbom() {
        when(settings.scannerSettings()).thenReturn(new ScannerSettings(true, "/bin/osv", DB_DIR));
        when(sboms.findComponents(sbomId)).thenReturn(List.of(new StoredComponent(
                UUID.randomUUID(), "ref", "org.example", "lib", "1.0.0",
                "pkg:maven/org.example/lib@1.0.0", "library", false, DependencyScope.DIRECT)));
    }

    private void archives(Instant mavenWrittenAt, Instant npmWrittenAt) {
        when(databases.status(DB_DIR)).thenReturn(List.of(
                new OsvDatabaseService.EcosystemStatus(
                        "Maven", mavenWrittenAt != null, 1L, mavenWrittenAt, "/tmp/maven", "url"),
                new OsvDatabaseService.EcosystemStatus(
                        "npm", npmWrittenAt != null, 1L, npmWrittenAt, "/tmp/npm", "url")));
    }

    private Instant daysAgo(int days) {
        return Instant.now().minus(days, ChronoUnit.DAYS);
    }

    @Test
    void aRecentScanAgainstAnOlderArchiveIsNotStale() {
        mavenSbom();
        scannedAt(daysAgo(1));
        archives(daysAgo(3), null);

        assertThat(scans.staleReason(sbomId)).isEqualTo(ScanService.StaleReason.NONE);
    }

    @Test
    void anArchiveWrittenAfterTheScanSupersedesIt() {
        // The whole point: yesterday's scan is not "old", it is answered against data that has
        // since been replaced. One day is well inside the seven-day threshold, so nothing but
        // this check can catch it.
        mavenSbom();
        scannedAt(daysAgo(1));
        archives(Instant.now(), null);

        assertThat(scans.staleReason(sbomId)).isEqualTo(ScanService.StaleReason.ARCHIVE_REFRESHED);
    }

    @Test
    void supersessionIsReportedAheadOfAge() {
        // Both are true. The archive is the stronger and more actionable statement, and a
        // day-count sentence would send the reader to look at the wrong thing.
        mavenSbom();
        scannedAt(daysAgo(30));
        archives(daysAgo(1), null);

        assertThat(scans.staleReason(sbomId)).isEqualTo(ScanService.StaleReason.ARCHIVE_REFRESHED);
    }

    @Test
    void anArchiveThisSbomDoesNotNeedIsIgnored() {
        // A Maven-only document is not superseded by a fresh npm archive, exactly as the
        // readiness check does not demand npm's 200 MB from someone who has no npm components.
        mavenSbom();
        scannedAt(daysAgo(1));
        archives(daysAgo(3), Instant.now());

        assertThat(scans.staleReason(sbomId)).isEqualTo(ScanService.StaleReason.NONE);
    }

    @Test
    void anOldScanWithNoFreshArchiveIsAged() {
        mavenSbom();
        scannedAt(daysAgo(STALE_AFTER_DAYS + 1));
        archives(daysAgo(30), null);

        assertThat(scans.staleReason(sbomId)).isEqualTo(ScanService.StaleReason.AGED);
    }

    @Test
    void neverScannedIsStale() {
        // Not a cosmetic default: "no findings" must never be readable as "no vulnerabilities"
        // when nothing has been checked at all.
        mavenSbom();
        scannedAt(null);

        assertThat(scans.staleReason(sbomId)).isEqualTo(ScanService.StaleReason.AGED);
    }

    @Test
    void anAbsentArchiveCannotSupersedeAnything() {
        // present=false carries a null timestamp. Treating that as "written at the epoch" or
        // as unknown-so-assume-fresh would both produce a wrong answer.
        mavenSbom();
        scannedAt(daysAgo(1));
        archives(null, null);

        assertThat(scans.staleReason(sbomId)).isEqualTo(ScanService.StaleReason.NONE);
    }

    @Test
    void anSbomWithNoRecognisedEcosystemIsJudgedOnAgeAlone() {
        // Nothing to compare against, so the archive question does not arise.
        when(settings.scannerSettings()).thenReturn(new ScannerSettings(true, "/bin/osv", DB_DIR));
        when(sboms.findComponents(sbomId)).thenReturn(List.of(new StoredComponent(
                UUID.randomUUID(), "ref", null, "mystery", "1.0.0", null,
                "library", false, DependencyScope.DIRECT)));
        when(databases.status(any())).thenReturn(List.of());
        scannedAt(daysAgo(1));

        assertThat(scans.staleReason(sbomId)).isEqualTo(ScanService.StaleReason.NONE);
    }
}
