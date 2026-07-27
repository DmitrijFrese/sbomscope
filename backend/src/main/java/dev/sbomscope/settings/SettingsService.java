package dev.sbomscope.settings;

import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Typed access to the settings a user can change from the UI. */
@Service
public class SettingsService {

    static final String SCANNER_ENABLED = "scanner.enabled";
    static final String SCANNER_PATH = "scanner.executablePath";
    static final String SCANNER_DB_DIR = "scanner.databaseDirectory";
    static final String EXPORT_VISIBLE_COLUMNS_ONLY = "export.visibleColumnsOnly";

    private final SettingsRepository repository;

    SettingsService(SettingsRepository repository) {
        this.repository = repository;
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

        return scannerSettings();
    }

    public ExportSettings exportSettings() {
        return new ExportSettings(
                repository.find(EXPORT_VISIBLE_COLUMNS_ONLY).map(Boolean::parseBoolean).orElse(false));
    }

    @Transactional
    public ExportSettings updateExportSettings(ExportSettings requested) {
        repository.put(EXPORT_VISIBLE_COLUMNS_ONLY, Boolean.toString(requested.visibleColumnsOnly()));
        return exportSettings();
    }

    /** {@code ~/.sbomscope/osv-db}, kept beside the rest of SBOMscope's local data. */
    static String defaultDatabaseDirectory() {
        return Path.of(System.getProperty("user.home"), ".sbomscope", "osv-db").toString();
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
