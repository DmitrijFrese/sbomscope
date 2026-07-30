package dev.sbomscope.api;

import java.time.Instant;
import java.util.List;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import org.springframework.http.HttpStatus;

import dev.sbomscope.probe.MavenDependencyResolver;
import dev.sbomscope.probe.MavenProbeException;
import dev.sbomscope.scanner.DownloadProgress;
import dev.sbomscope.scanner.OsvDatabaseService;
import dev.sbomscope.scanner.OsvScannerException;
import dev.sbomscope.scanner.OsvScannerRunner;
import dev.sbomscope.settings.ExportSettings;
import dev.sbomscope.settings.MavenToolSettings;
import dev.sbomscope.settings.ScannerSettings;
import dev.sbomscope.settings.SettingsService;

@RestController
@RequestMapping("/api/settings")
class SettingsController {

    private final SettingsService settings;
    private final OsvScannerRunner scanner;
    private final OsvDatabaseService database;
    private final MavenDependencyResolver maven;

    SettingsController(SettingsService settings, OsvScannerRunner scanner, OsvDatabaseService database,
                        MavenDependencyResolver maven) {
        this.settings = settings;
        this.scanner = scanner;
        this.database = database;
        this.maven = maven;
    }

    record ScannerSettingsPayload(
            boolean enabled,
            String executablePath,
            String databaseDirectory) {

        ScannerSettings toDomain() {
            return new ScannerSettings(enabled, executablePath, databaseDirectory);
        }

        static ScannerSettingsPayload from(ScannerSettings domain) {
            return new ScannerSettingsPayload(
                    domain.enabled(), domain.executablePath(), domain.databaseDirectory());
        }
    }

    record DatabaseStatus(
            String ecosystem,
            boolean present,
            long sizeBytes,
            Instant lastModified,
            /** Absolute location on disk, so the file can be found, copied or deleted. */
            String path,
            /** Exactly what gets fetched — nothing is downloaded opaquely. */
            String sourceUrl,
            /**
             * Whether this archive has been parsed into the upgrade-path index.
             *
             * <p>Separate from {@code present} because they are separately reachable: an
             * archive carried across by hand, or downloaded before the index existed, is on
             * disk and scannable but cannot answer "would this version be clean". Scanning
             * never needs the index — osv-scanner reads the archive itself.
             */
            boolean indexed) {}

    record ScannerStatus(
            ScannerSettingsPayload settings,
            List<DatabaseStatus> database,
            DownloadProgress download) {}

    /** Outcome of running the configured binary; never throws, so the UI can show it inline. */
    record ScannerTestResult(boolean ok, String version, String error) {}

    record ExportSettingsPayload(boolean visibleColumnsOnly) {}

    @GetMapping("/export")
    ExportSettingsPayload exportSettings() {
        return new ExportSettingsPayload(settings.exportSettings().visibleColumnsOnly());
    }

    @PutMapping("/export")
    ExportSettingsPayload updateExport(@RequestBody ExportSettingsPayload payload) {
        return new ExportSettingsPayload(
                settings.updateExportSettings(new ExportSettings(payload.visibleColumnsOnly()))
                        .visibleColumnsOnly());
    }

    @GetMapping("/scanner")
    ScannerStatus scannerStatus() {
        ScannerSettings current = settings.scannerSettings();
        return new ScannerStatus(
                ScannerSettingsPayload.from(current),
                database.status(current.databaseDirectory()).stream()
                        .map(status -> new DatabaseStatus(
                                status.ecosystem(), status.present(),
                                status.sizeBytes(), status.lastModified(),
                                status.path(), status.sourceUrl(),
                                database.isIndexed(current.databaseDirectory(), status.ecosystem())))
                        .toList(),
                database.progress());
    }

    /** Polled by the UI while a download runs. */
    @GetMapping("/scanner/database/progress")
    DownloadProgress downloadProgress() {
        return database.progress();
    }

    @PutMapping("/scanner")
    ScannerStatus updateScanner(@RequestBody ScannerSettingsPayload payload) {
        settings.updateScannerSettings(payload.toDomain());
        return scannerStatus();
    }

    @PostMapping("/scanner/test")
    ScannerTestResult testScanner() {
        ScannerSettings current = settings.scannerSettings();
        if (!current.hasExecutable()) {
            return new ScannerTestResult(false, null, "No scanner path configured.");
        }
        try {
            return new ScannerTestResult(true, scanner.version(current.executablePath()), null);
        } catch (OsvScannerException e) {
            return new ScannerTestResult(false, null, e.getMessage());
        }
    }

    /**
     * Explicit user action — the only thing that ever fetches vulnerability data.
     * One ecosystem at a time, because the archives differ by an order of magnitude in
     * size and most projects only need one of them.
     *
     * <p>Returns as soon as the download starts; the UI polls
     * {@code /scanner/database/progress} for the rest.
     */
    /**
     * Indexes an archive that is already on disk.
     *
     * <p>Separate from the download because the two are separately reachable states: an
     * archive copied across by hand has never been downloaded here, and one fetched before
     * the index existed is present but unusable for upgrade paths. Re-downloading 200 MB to
     * fix that would be absurd, and on an air-gapped machine impossible.
     */
    @PostMapping("/scanner/database/index")
    @ResponseStatus(HttpStatus.ACCEPTED)
    DownloadProgress indexDatabase(@RequestParam("ecosystem") String ecosystem) {
        return database.startIndexing(settings.scannerSettings().databaseDirectory(), ecosystem);
    }

    @PostMapping("/scanner/database/download")
    @ResponseStatus(HttpStatus.ACCEPTED)
    DownloadProgress downloadDatabase(@RequestParam("ecosystem") String ecosystem) {
        ScannerSettings current = settings.scannerSettings();
        return database.startDownload(current.databaseDirectory(), ecosystem);
    }

    // --- Maven probe (Phase 8 Tier 2) -----------------------------------------------------

    record MavenSettingsPayload(
            boolean enabled, String executablePath, int maxProbes, int runBudgetMinutes, String profiles,
            String dependencyPluginVersion, String helpPluginVersion) {

        MavenToolSettings toDomain() {
            return new MavenToolSettings(enabled, executablePath, maxProbes, runBudgetMinutes, profiles,
                    dependencyPluginVersion, helpPluginVersion);
        }

        static MavenSettingsPayload from(MavenToolSettings domain) {
            return new MavenSettingsPayload(
                    domain.enabled(), domain.executablePath(), domain.maxProbes(), domain.runBudgetMinutes(),
                    domain.profiles(), domain.dependencyPluginVersion(), domain.helpPluginVersion());
        }
    }

    /**
     * Mirrors {@link ScannerTestResult}: never throws, so the UI can show it inline.
     *
     * <p>{@code version} and {@code plugins} are reported separately because they fail
     * separately and for different reasons — a perfectly good Maven that cannot obtain the
     * probe's plugins is the exact shape of the air-gapped failure, and collapsing the two
     * would report it as "Maven is broken".
     */
    record MavenTestResult(boolean ok, String version, String plugins, String error) {}

    @GetMapping("/maven")
    MavenSettingsPayload mavenSettings() {
        return MavenSettingsPayload.from(settings.mavenSettings());
    }

    @PutMapping("/maven")
    MavenSettingsPayload updateMaven(@RequestBody MavenSettingsPayload payload) {
        return MavenSettingsPayload.from(settings.updateMavenSettings(payload.toDomain()));
    }

    /**
     * Two checks, not one: that the binary is Maven, and that the plugins a probe drives can
     * actually be obtained and run. The second is the one that matters — {@code --version}
     * succeeds on a machine where every probe will fail, and reporting "Working" there sends
     * the reader looking for the problem everywhere except where it is.
     */
    @PostMapping("/maven/test")
    MavenTestResult testMaven() {
        MavenToolSettings current = settings.mavenSettings();
        if (!current.hasExecutable()) {
            return new MavenTestResult(false, null, null, "No mvn path configured.");
        }

        String version;
        try {
            version = maven.version(current.executablePath());
        } catch (MavenProbeException e) {
            return new MavenTestResult(false, null, null, e.getMessage());
        }

        try {
            // The version is carried through on failure: "Maven works, its plugins do not" is a
            // different problem from "that is not Maven", and the reader needs to see which.
            return new MavenTestResult(true, version, maven.verifyProbePlugins(current), null);
        } catch (MavenProbeException e) {
            return new MavenTestResult(false, version, null, e.getMessage());
        }
    }
}
