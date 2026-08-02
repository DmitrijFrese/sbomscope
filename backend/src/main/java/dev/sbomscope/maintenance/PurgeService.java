package dev.sbomscope.maintenance;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import dev.sbomscope.exploit.ExploitFeedService;
import dev.sbomscope.logging.ActivityLogger;
import dev.sbomscope.probe.BumpProbeService;
import dev.sbomscope.sbom.SbomFileStore;
import dev.sbomscope.sbom.SbomService;
import dev.sbomscope.scanner.OsvDatabaseService;
import dev.sbomscope.settings.SettingsService;

/**
 * Erases local data on explicit request.
 *
 * <p>Deletes <em>rows</em>, never the database file. H2 holds an exclusive lock on
 * {@code sbomscope.mv.db} while the application runs — the same lock that stops the jar
 * being rebuilt — so removing the file from inside the running process is not possible.
 * Emptying the tables achieves the same thing and leaves a working schema behind.
 *
 * <p>This therefore cannot help with a migration that will not start: {@code
 * flyway_schema_history} is deliberately untouched, and a schema the application refuses to
 * boot on has to be dealt with while it is stopped.
 */
@Service
public class PurgeService {

    private static final Logger log = LoggerFactory.getLogger(PurgeService.class);

    private final JdbcTemplate jdbc;
    private final SbomService sboms;
    private final SbomFileStore files;
    private final SettingsService settings;
    private final ActivityLogger activityLog;
    private final ExploitFeedService exploitFeeds;
    private final BumpProbeService probes;
    private final Path logsDirectory;
    private final Path probeRepository;

    PurgeService(JdbcTemplate jdbc, SbomService sboms, SbomFileStore files, SettingsService settings,
                 ActivityLogger activityLog, ExploitFeedService exploitFeeds, BumpProbeService probes,
                 @Value("${sbomscope.logs-directory}") String logsDirectory,
                 @Value("${sbomscope.probe-repository}") String probeRepository) {
        this.jdbc = jdbc;
        this.sboms = sboms;
        this.files = files;
        this.settings = settings;
        this.activityLog = activityLog;
        this.exploitFeeds = exploitFeeds;
        this.probes = probes;
        this.logsDirectory = Path.of(logsDirectory).toAbsolutePath().normalize();
        this.probeRepository = Path.of(probeRepository).toAbsolutePath().normalize();
    }

    /**
     * What a purge removed, per target, so the confirmation states facts rather than
     * "done" — with destructive actions the user should be able to see the size of what
     * just happened.
     */
    public record PurgeResult(Map<String, String> removed) {}

    @Transactional
    public PurgeResult purge(Set<PurgeTarget> targets) {
        // Read before anything is deleted: the archive location lives in the settings that
        // this same call may be about to erase.
        String databaseDirectory = settings.scannerSettings().databaseDirectory();

        if (targets.contains(PurgeTarget.MAVEN_PROBE_CACHE)) {
            validateProbeRepositoryPath();
            return probes.withIdleProbeRepository(() -> performPurge(targets, databaseDirectory));
        }
        return performPurge(targets, databaseDirectory);
    }

    private PurgeResult performPurge(Set<PurgeTarget> targets, String databaseDirectory) {
        Map<String, String> removed = new LinkedHashMap<>();
        boolean erasingRolledLogs = targets.contains(PurgeTarget.ROLLED_LOGS);

        // Must precede deletion: either of these writes can cross the 10 MB boundary and roll
        // the active file. Writing first means the newly-created .1 is included in the exact
        // numbered set deleted below, rather than recreating old history after the purge.
        if (erasingRolledLogs) {
            log.warn("Purge requested: {}", targets);
            activityLog.record(ActivityLogger.Category.DATA, "PURGE", "STARTED", targets.toString());
        }

        if (targets.contains(PurgeTarget.SBOMS)) {
            removed.put(PurgeTarget.SBOMS.name(), purgeSboms());
        }
        if (targets.contains(PurgeTarget.FINDINGS)) {
            removed.put(PurgeTarget.FINDINGS.name(), purgeFindings());
        }
        if (targets.contains(PurgeTarget.SETTINGS)) {
            int rows = jdbc.update("DELETE FROM app_setting");
            removed.put(PurgeTarget.SETTINGS.name(), rows + " settings reset to defaults");
        }
        if (targets.contains(PurgeTarget.OSV_DATABASE)) {
            // The exploitation feeds ride on this target rather than earning a fifth checkbox.
            // The data targets differ by orders of magnitude in what they cost to undo, and
            // 4 MB of KEV and EPSS is not a new order of magnitude beside a 200 MB
            // npm archive. Their rows go with their files, being derived data pointing at
            // nothing once the file is gone.
            int indexRows = jdbc.update("DELETE FROM osv_index");
            int sourceRows = jdbc.update("DELETE FROM osv_index_source");
            removed.put(PurgeTarget.OSV_DATABASE.name(),
                    purgeDatabaseArchives(databaseDirectory)
                            + "; %d index rows and %d index sources; ".formatted(indexRows, sourceRows)
                            + exploitFeeds.purge());
        }
        if (targets.contains(PurgeTarget.MAVEN_PROBE_CACHE)) {
            removed.put(PurgeTarget.MAVEN_PROBE_CACHE.name(), purgeProbeRepository());
        }
        if (erasingRolledLogs) {
            // Last: warnings produced by any earlier best-effort deletion belong to the old
            // history the user asked to remove.
            removed.put(PurgeTarget.ROLLED_LOGS.name(), purgeRolledLogs());
        }

        // Do not write after rolled-log deletion: that write itself could roll an active file
        // and immediately recreate numbered history containing pre-purge lines.
        if (!erasingRolledLogs) {
            log.warn("Purge completed: {}", removed);
            activityLog.record(ActivityLogger.Category.DATA, "PURGE", removed.toString());
        }
        return new PurgeResult(removed);
    }

    /**
     * Rows first, then the documents on disk. That order matters: if file deletion fails
     * halfway, what is left is a document with no SBOM row — an orphan, which is untidy but
     * harmless. The reverse would leave an SBOM row pointing at a document that is gone,
     * which looks like working data until someone tries to re-scan it.
     */
    private String purgeSboms() {
        List<UUID> ids = sboms.findAll().stream().map(sbom -> sbom.id()).toList();

        int rows = jdbc.update("DELETE FROM sbom");
        ids.forEach(files::delete);

        return "%d SBOMs, with their components and stored documents".formatted(rows);
    }

    /** Findings cascade from their scan row, but both are counted so the total is honest. */
    private String purgeFindings() {
        int findings = jdbc.update("DELETE FROM vulnerability_finding");
        int scans = jdbc.update("DELETE FROM vulnerability_scan");
        return "%d findings across %d scanned components".formatted(findings, scans);
    }

    /**
     * Only the archives SBOMscope downloads, never the directory itself — a user may well
     * have pointed the setting at a folder that holds other things, and deleting a tree we
     * do not own is not ours to do.
     */
    private String purgeDatabaseArchives(String databaseDirectory) {
        List<String> deleted = new ArrayList<>();

        for (String ecosystem : OsvDatabaseService.ECOSYSTEMS) {
            Path directory = Path.of(databaseDirectory, "osv-scanner", ecosystem);
            for (String name : List.of("all.zip", "all.zip.partial")) {
                Path archive = directory.resolve(name);
                try {
                    if (Files.deleteIfExists(archive)) {
                        deleted.add(ecosystem + "/" + name);
                    }
                } catch (IOException e) {
                    log.warn("Could not delete {}", archive, e);
                }
            }
        }

        return deleted.isEmpty() ? "nothing to remove" : String.join(", ", deleted);
    }

    private String purgeRolledLogs() {
        List<String> removed = new ArrayList<>();
        List<String> absent = new ArrayList<>();
        List<String> failed = new ArrayList<>();
        long bytes = 0;

        List<String> names = new ArrayList<>();
        for (int i = 1; i <= 5; i++) {
            names.add("sbomscope.log." + i);
        }
        for (int i = 1; i <= 3; i++) {
            names.add("activity.jsonl." + i);
        }

        for (String name : names) {
            Path path = logsDirectory.resolve(name);
            try {
                long size = Files.isRegularFile(path) ? Files.size(path) : 0;
                if (Files.deleteIfExists(path)) {
                    removed.add(name);
                    bytes += size;
                } else {
                    absent.add(name);
                }
            } catch (IOException e) {
                failed.add(name + " (" + e.getMessage() + ")");
                log.warn("Could not delete rolled log {}", path, e);
            }
        }

        String result = "%d files (%d bytes) removed; active sbomscope.log and activity.jsonl kept"
                .formatted(removed.size(), bytes);
        if (!removed.isEmpty()) {
            result += "; removed: " + String.join(", ", removed);
        }
        if (!absent.isEmpty()) {
            result += "; not present: " + String.join(", ", absent);
        }
        if (!failed.isEmpty()) {
            result += "; not removed: " + String.join(", ", failed);
        }
        return result;
    }

    private void validateProbeRepositoryPath() {
        Path parent = probeRepository.getParent();
        if (parent == null || probeRepository.equals(probeRepository.getRoot())
                || !"probe-repo".equals(probeRepository.getFileName().toString())) {
            throw new IllegalStateException(
                    "Refusing to clear an unexpected Maven probe cache path: " + probeRepository);
        }
    }

    private String purgeProbeRepository() {
        if (!Files.exists(probeRepository)) {
            return "nothing to remove; later probes may require repository access";
        }

        List<Path> paths;
        try (var walk = Files.walk(probeRepository)) {
            // Materialise before deleting. On Windows the open directory stream itself can
            // keep a directory from being removed.
            paths = walk.sorted(Comparator.reverseOrder()).toList();
        } catch (IOException e) {
            throw new IllegalStateException("Could not read the Maven probe cache: " + e.getMessage(), e);
        }

        int files = 0;
        long bytes = 0;
        List<String> failed = new ArrayList<>();
        for (Path path : paths) {
            try {
                boolean regular = Files.isRegularFile(path);
                long size = regular ? Files.size(path) : 0;
                if (Files.deleteIfExists(path) && regular) {
                    files++;
                    bytes += size;
                }
            } catch (IOException e) {
                failed.add(probeRepository.relativize(path) + " (" + e.getMessage() + ")");
                log.warn("Could not delete Maven probe cache path {}", path, e);
            }
        }

        String result = "%d files (%d bytes) removed; later probes may require repository access"
                .formatted(files, bytes);
        if (!failed.isEmpty()) {
            result += "; not removed: " + String.join(", ", failed);
        }
        return result;
    }
}
