package dev.sbomscope.settings;

import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import dev.sbomscope.logging.ActivityLogger;

/** Typed access to the settings a user can change from the UI. */
@Service
public class SettingsService {

    static final String SCANNER_ENABLED = "scanner.enabled";
    static final String SCANNER_PATH = "scanner.executablePath";
    static final String SCANNER_DB_DIR = "scanner.databaseDirectory";
    static final String EXPORT_VISIBLE_COLUMNS_ONLY = "export.visibleColumnsOnly";
    static final String MAVEN_ENABLED = "maven.enabled";
    static final String MAVEN_PATH = "maven.executablePath";
    static final String MAVEN_MAX_PROBES = "maven.maxProbes";
    static final String MAVEN_RUN_BUDGET_MINUTES = "maven.runBudgetMinutes";
    static final String MAVEN_PROFILES = "maven.profiles";

    private final SettingsRepository repository;
    private final ActivityLogger activityLog;
    private final ApplicationEventPublisher events;

    SettingsService(SettingsRepository repository, ActivityLogger activityLog,
                     ApplicationEventPublisher events) {
        this.repository = repository;
        this.activityLog = activityLog;
        this.events = events;
    }

    public ScannerSettings scannerSettings() {
        return new ScannerSettings(
                repository.find(SCANNER_ENABLED).map(Boolean::parseBoolean).orElse(false),
                repository.find(SCANNER_PATH).filter(value -> !value.isBlank()).orElse(null),
                repository.find(SCANNER_DB_DIR)
                        .filter(value -> !value.isBlank())
                        .orElseGet(SettingsService::defaultDatabaseDirectory));
    }

    @Transactional
    public ScannerSettings updateScannerSettings(ScannerSettings requested) {
        String path = normalisePath(requested.executablePath(), "Scanner path");
        String databaseDirectory = normalisePath(requested.databaseDirectory(), "Database directory");

        if (requested.enabled() && (path == null)) {
            throw new IllegalArgumentException(
                    "Enable scanning only once a path to the osv-scanner binary is set.");
        }
        if (path != null) {
            requireExecutableFile(path);
        }

        repository.put(SCANNER_ENABLED, Boolean.toString(requested.enabled()));
        repository.put(SCANNER_PATH, path == null ? "" : path);
        repository.put(SCANNER_DB_DIR,
                databaseDirectory == null ? defaultDatabaseDirectory() : databaseDirectory);

        activityLog.record(ActivityLogger.Category.DATA, "SETTINGS_CHANGED",
                "scanner: enabled=%s, path=%s".formatted(requested.enabled(), path != null));
        return scannerSettings();
    }

    public ExportSettings exportSettings() {
        return new ExportSettings(
                repository.find(EXPORT_VISIBLE_COLUMNS_ONLY).map(Boolean::parseBoolean).orElse(false));
    }

    @Transactional
    public ExportSettings updateExportSettings(ExportSettings requested) {
        repository.put(EXPORT_VISIBLE_COLUMNS_ONLY, Boolean.toString(requested.visibleColumnsOnly()));
        activityLog.record(ActivityLogger.Category.DATA, "SETTINGS_CHANGED",
                "export: visibleColumnsOnly=%s".formatted(requested.visibleColumnsOnly()));
        return exportSettings();
    }

    public MavenToolSettings mavenSettings() {
        return new MavenToolSettings(
                repository.find(MAVEN_ENABLED).map(Boolean::parseBoolean).orElse(false),
                repository.find(MAVEN_PATH).filter(value -> !value.isBlank()).orElse(null),
                repository.find(MAVEN_MAX_PROBES).map(Integer::parseInt)
                        .orElse(MavenToolSettings.DEFAULT_MAX_PROBES),
                repository.find(MAVEN_RUN_BUDGET_MINUTES).map(Integer::parseInt)
                        .orElse(MavenToolSettings.DEFAULT_RUN_BUDGET_MINUTES),
                repository.find(MAVEN_PROFILES).filter(value -> !value.isBlank()).orElse(null));
    }

    @Transactional
    public MavenToolSettings updateMavenSettings(MavenToolSettings requested) {
        String path = normalisePath(requested.executablePath(), "Maven path");
        String profiles = requested.profiles() == null || requested.profiles().isBlank()
                ? null : requested.profiles().trim();

        if (requested.enabled() && path == null) {
            throw new IllegalArgumentException(
                    "Enable the Maven probe only once a path to mvn is set.");
        }
        if (path != null) {
            requireExecutableFile(path);
        }
        requireInRange(requested.maxProbes(), MavenToolSettings.MIN_PROBES, MavenToolSettings.MAX_PROBES,
                "Maximum probes");
        requireInRange(requested.runBudgetMinutes(), MavenToolSettings.MIN_RUN_BUDGET_MINUTES,
                MavenToolSettings.MAX_RUN_BUDGET_MINUTES, "Run budget");

        repository.put(MAVEN_ENABLED, Boolean.toString(requested.enabled()));
        repository.put(MAVEN_PATH, path == null ? "" : path);
        repository.put(MAVEN_MAX_PROBES, Integer.toString(requested.maxProbes()));
        repository.put(MAVEN_RUN_BUDGET_MINUTES, Integer.toString(requested.runBudgetMinutes()));
        repository.put(MAVEN_PROFILES, profiles == null ? "" : profiles);

        activityLog.record(ActivityLogger.Category.DATA, "SETTINGS_CHANGED",
                "maven: enabled=%s, path=%s, maxProbes=%d, runBudgetMinutes=%d, profiles=%s"
                        .formatted(requested.enabled(), path != null, requested.maxProbes(),
                                requested.runBudgetMinutes(), profiles == null ? "(none)" : profiles));
        // Anything caching a result against "the current Maven config" — the probe's
        // negative-result cache, the lifted effective-pom fragments — must not go on
        // answering from a configuration that no longer applies.
        events.publishEvent(new MavenSettingsChangedEvent());
        return mavenSettings();
    }

    /** {@code ~/.sbomscope/osv-db}, kept beside the rest of SBOMscope's local data. */
    static String defaultDatabaseDirectory() {
        return Path.of(System.getProperty("user.home"), ".sbomscope", "osv-db").toString();
    }

    /**
     * {@code ~/.sbomscope/probe-repo}, never the user's own {@code ~/.m2}. A failed probe
     * writes {@code .lastUpdated} markers that can make a later real build refuse to retry a
     * download; perturbing someone's build environment to answer a question they asked idly
     * is not a trade worth making.
     */
    public static String defaultProbeRepository() {
        return Path.of(System.getProperty("user.home"), ".sbomscope", "probe-repo").toString();
    }

    private String normalisePath(String value, String label) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return Path.of(value.trim()).toAbsolutePath().normalize().toString();
        } catch (InvalidPathException e) {
            throw new IllegalArgumentException("%s is not a valid path: %s".formatted(label, value), e);
        }
    }

    private void requireInRange(int value, int min, int max, String label) {
        if (value < min || value > max) {
            throw new IllegalArgumentException(
                    "%s must be between %d and %d, was %d.".formatted(label, min, max, value));
        }
    }

    private void requireExecutableFile(String path) {
        Path binary = Path.of(path);
        if (!Files.exists(binary)) {
            throw new IllegalArgumentException("No file at " + path);
        }
        if (Files.isDirectory(binary)) {
            throw new IllegalArgumentException(
                    "That is a directory. Point at the osv-scanner binary itself: " + path);
        }
        if (!Files.isExecutable(binary)) {
            throw new IllegalArgumentException(
                    "The file at %s is not executable.".formatted(path));
        }
    }
}
