package dev.sbomscope.maintenance;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import dev.sbomscope.settings.SettingsService;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Purge is irreversible, so what it refuses matters as much as what it deletes.
 *
 * <p>Transactional, and therefore rolled back: the purge empties tables wholesale, and
 * leaving that committed would pull the ground out from under every other test sharing this
 * in-memory database.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class PurgeTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JdbcTemplate jdbc;

    @Autowired
    private SettingsService settings;

    @Value("${sbomscope.logs-directory}")
    private String logsDirectory;

    @Value("${sbomscope.probe-repository}")
    private String probeRepository;

    private final UUID sbomId = UUID.randomUUID();
    private final String purl = "pkg:maven/dev.sbomscope.purge/lib@1.0.0";

    @BeforeEach
    void seed() {
        jdbc.update("INSERT INTO sbom (id, filename, uploaded_at, spec_version, component_count)"
                        + " VALUES (?, ?, ?, ?, ?)",
                sbomId, "purge.cdx.json", OffsetDateTime.now(ZoneOffset.UTC), "1.6", 1);
        jdbc.update("INSERT INTO component (id, sbom_id, bom_ref, group_name, name, version, purl)"
                        + " VALUES (?, ?, ?, ?, ?, ?, ?)",
                UUID.randomUUID(), sbomId, purl, "dev.sbomscope.purge", "lib", "1.0.0", purl);
        jdbc.update("INSERT INTO vulnerability_scan (purl, scanned_at, scanner_version) VALUES (?, ?, ?)",
                purl, OffsetDateTime.now(ZoneOffset.UTC), "test");
        jdbc.update("INSERT INTO vulnerability_finding (id, purl, osv_id, severity_score)"
                        + " VALUES (?, ?, ?, ?)",
                UUID.randomUUID(), purl, "GHSA-purge-test", new java.math.BigDecimal("7.5"));
    }

    private int count(String table) {
        return jdbc.queryForObject("SELECT COUNT(*) FROM " + table, Integer.class);
    }

    /**
     * Scoped to this test's own fixture. Other test classes commit rows into the shared
     * in-memory database, so a global count would be measuring their data as well as ours.
     */
    private int ownSboms() {
        return jdbc.queryForObject("SELECT COUNT(*) FROM sbom WHERE id = ?", Integer.class, sbomId);
    }

    private int ownComponents() {
        return jdbc.queryForObject(
                "SELECT COUNT(*) FROM component WHERE sbom_id = ?", Integer.class, sbomId);
    }

    private int ownFindings() {
        return jdbc.queryForObject(
                "SELECT COUNT(*) FROM vulnerability_finding WHERE purl = ?", Integer.class, purl);
    }

    private int ownScans() {
        return jdbc.queryForObject(
                "SELECT COUNT(*) FROM vulnerability_scan WHERE purl = ?", Integer.class, purl);
    }

    /** Flyway quotes its table name, so the exact casing is whatever it created. */
    private String migrationHistoryTable() {
        return jdbc.queryForObject(
                "SELECT table_name FROM information_schema.tables"
                        + " WHERE UPPER(table_name) = 'FLYWAY_SCHEMA_HISTORY'",
                String.class);
    }

    private void purge(String body) throws Exception {
        mockMvc.perform(post("/api/maintenance/purge")
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isOk());
    }

    private void rejects(String body, String expectedMessage) throws Exception {
        mockMvc.perform(post("/api/maintenance/purge")
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value(org.hamcrest.Matchers.containsString(expectedMessage)));
    }

    @Test
    void refusesWithoutTheTypedConfirmation() throws Exception {
        rejects("{\"confirmation\":\"yes\",\"targets\":[\"SBOMS\"]}", "Type PURGE");
        rejects("{\"targets\":[\"SBOMS\"]}", "Type PURGE");

        assertThat(ownSboms()).as("nothing may be deleted by a rejected request").isEqualTo(1);
    }

    @Test
    void refusesWhenNothingWasChosen() throws Exception {
        rejects("{\"confirmation\":\"PURGE\",\"targets\":[]}", "at least one");

        assertThat(ownSboms()).isEqualTo(1);
    }

    @Test
    void refusesAnUnrecognisedTarget() throws Exception {
        // Deleting something other than what was asked for is the one outcome a purge must
        // never produce, so an unknown name fails rather than being skipped.
        rejects("{\"confirmation\":\"PURGE\",\"targets\":[\"SBOMS\",\"EVERYTHING\"]}", "Unknown purge target");

        assertThat(ownSboms()).isEqualTo(1);
    }

    @Test
    void acceptsEitherConfirmationWord() throws Exception {
        purge("{\"confirmation\":\"delete\",\"targets\":[\"SBOMS\"]}");

        assertThat(count("sbom")).isZero();
    }

    @Test
    void erasingSbomsKeepsTheVulnerabilityCache() throws Exception {
        // The cache is keyed by purl and shared across SBOMs on purpose: re-uploading the
        // same document should get its findings back without running the scanner again.
        purge("{\"confirmation\":\"PURGE\",\"targets\":[\"SBOMS\"]}");

        assertThat(count("sbom")).isZero();
        assertThat(count("component")).as("components cascade with their SBOM").isZero();
        assertThat(ownFindings()).isEqualTo(1);
        assertThat(ownScans()).isEqualTo(1);
    }

    @Test
    void erasingTheCacheKeepsTheSboms() throws Exception {
        purge("{\"confirmation\":\"PURGE\",\"targets\":[\"FINDINGS\"]}");

        assertThat(count("vulnerability_finding")).isZero();
        assertThat(count("vulnerability_scan")).isZero();
        assertThat(ownSboms()).as("the inventory survives losing its analysis").isEqualTo(1);
        assertThat(ownComponents()).isEqualTo(1);
    }

    @Test
    void reportsWhatItRemoved() throws Exception {
        // A destructive action should state the size of what just happened rather than "done".
        mockMvc.perform(post("/api/maintenance/purge")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"confirmation\":\"PURGE\",\"targets\":[\"SBOMS\",\"FINDINGS\"]}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.removed.SBOMS").value(org.hamcrest.Matchers.containsString("SBOMs")))
                .andExpect(jsonPath("$.removed.FINDINGS").value(org.hamcrest.Matchers.containsString("findings")));
    }

    @Test
    void leavesTheMigrationHistoryAlone() throws Exception {
        // Purge cannot rescue a schema the application will not start on, and quietly
        // deleting this table would turn that limitation into a corrupted database.
        String table = "\"" + migrationHistoryTable() + "\"";
        int before = count(table);
        assertThat(before).as("migrations should be recorded").isPositive();

        purge("{\"confirmation\":\"PURGE\",\"targets\":[\"SBOMS\",\"FINDINGS\",\"SETTINGS\"]}");

        assertThat(count(table)).isEqualTo(before);
    }

    @Test
    void offlineDataPurgeRemovesTheArchiveIndexAndItsSource() throws Exception {
        Path archive = Path.of(settings.scannerSettings().databaseDirectory(),
                "osv-scanner", "Maven", "all.zip");
        Path testData = Path.of("target", "sbomscope-test-data").toAbsolutePath().normalize();
        assertThat(archive.toAbsolutePath().normalize().startsWith(testData))
                .as("the suite must never point a purge at the user's real archive").isTrue();
        Files.createDirectories(archive.getParent());
        Files.writeString(archive, "test archive");

        jdbc.update("INSERT INTO osv_index_source"
                        + " (ecosystem, identity, advisories, packages, built_at) VALUES (?, ?, ?, ?, ?)",
                "PurgeTest", "fixture", 1, 1, OffsetDateTime.now(ZoneOffset.UTC));
        jdbc.update("INSERT INTO osv_index"
                        + " (ecosystem, package_name, osv_id, affected) VALUES (?, ?, ?, ?)",
                "PurgeTest", "example", "GHSA-index-purge", "[]");

        purge("{\"confirmation\":\"PURGE\",\"targets\":[\"OSV_DATABASE\"]}");

        assertThat(jdbc.queryForObject(
                "SELECT COUNT(*) FROM osv_index WHERE ecosystem = 'PurgeTest'", Integer.class)).isZero();
        assertThat(jdbc.queryForObject(
                "SELECT COUNT(*) FROM osv_index_source WHERE ecosystem = 'PurgeTest'", Integer.class)).isZero();
        assertThat(archive).doesNotExist();
    }

    @Test
    void rolledLogPurgeKeepsActiveAndUnrelatedFiles() throws Exception {
        Path directory = Path.of(logsDirectory);
        Files.createDirectories(directory);
        Path proseHistory = directory.resolve("sbomscope.log.2");
        Path activityHistory = directory.resolve("activity.jsonl.3");
        Path unrelated = directory.resolve("notes.txt");
        Files.writeString(proseHistory, "old prose");
        Files.writeString(activityHistory, "old activity");
        Files.writeString(unrelated, "not ours");

        purge("{\"confirmation\":\"PURGE\",\"targets\":[\"ROLLED_LOGS\"]}");

        assertThat(proseHistory).doesNotExist();
        assertThat(activityHistory).doesNotExist();
        assertThat(directory.resolve("sbomscope.log")).exists();
        assertThat(directory.resolve("activity.jsonl")).exists();
        assertThat(unrelated).exists();
        Files.deleteIfExists(unrelated);
    }

    @Test
    void probeCachePurgeDeletesOnlyTheIsolatedRepository() throws Exception {
        Path repository = Path.of(probeRepository);
        Path artifact = repository.resolve("com/example/lib/1.0/lib-1.0.jar");
        Files.createDirectories(artifact.getParent());
        Files.writeString(artifact, "cached");

        mockMvc.perform(post("/api/maintenance/purge")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"confirmation\":\"PURGE\",\"targets\":[\"MAVEN_PROBE_CACHE\"]}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.removed.MAVEN_PROBE_CACHE")
                        .value(org.hamcrest.Matchers.containsString("1 files")));

        assertThat(repository).doesNotExist();
    }
}
