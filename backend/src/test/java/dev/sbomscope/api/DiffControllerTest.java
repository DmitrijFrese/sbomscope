package dev.sbomscope.api;

import java.io.InputStream;
import java.math.BigDecimal;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import dev.sbomscope.sbom.CycloneDxParser;
import dev.sbomscope.sbom.ParsedSbom;
import dev.sbomscope.sbom.ParsedSbom.ParsedComponent;

import static org.hamcrest.Matchers.greaterThan;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class DiffControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private CycloneDxParser parser;

    @Autowired
    private JdbcTemplate jdbc;

    private UUID left;
    private UUID right;

    @BeforeEach
    void seedDocuments() throws Exception {
        jdbc.update("DELETE FROM vulnerability_finding");
        jdbc.update("DELETE FROM vulnerability_scan");
        left = seed("maven-sbomscope.cdx.json");
        right = seed("npm-frontend.cdx.json");

        List<String> rightPurls = jdbc.queryForList(
                "SELECT DISTINCT purl FROM component"
                        + " WHERE sbom_id = ? AND purl IS NOT NULL LIMIT 2",
                String.class, right);
        for (int index = 0; index < rightPurls.size(); index++) {
            finding(rightPurls.get(index), "GHSA-DIFF-RIGHT-" + index, "CVE-2026-4242");
        }
        String leftPurl = jdbc.queryForObject(
                "SELECT purl FROM component WHERE sbom_id = ? AND purl IS NOT NULL LIMIT 1",
                String.class, left);
        finding(leftPurl, "GHSA-DIFF-LEFT", "CVE-2026-4343");
    }

    @Test
    void returnsNotFoundWhenEitherDocumentIsUnknown() throws Exception {
        UUID unknown = UUID.randomUUID();

        mockMvc.perform(get("/api/diff").param("left", unknown.toString())
                        .param("right", right.toString()))
                .andExpect(status().isNotFound());
        mockMvc.perform(get("/api/diff").param("left", left.toString())
                        .param("right", unknown.toString()))
                .andExpect(status().isNotFound());
    }

    @Test
    void returnsRowsAndDocumentWideSummary() throws Exception {
        mockMvc.perform(get("/api/diff").param("left", left.toString())
                        .param("right", right.toString()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.rows.length()").value(greaterThan(0)))
                .andExpect(jsonPath("$.summary.changes.ADDED").value(greaterThan(0)))
                .andExpect(jsonPath("$.summary.changes.REMOVED").value(greaterThan(0)))
                .andExpect(jsonPath("$.summary.changes.VERSION_CHANGED").value(0))
                .andExpect(jsonPath("$.summary.changes.UNCHANGED").value(0))
                .andExpect(jsonPath("$.summary.cveIdsGained").value(1))
                .andExpect(jsonPath("$.summary.cveIdsLost").value(1));
    }

    @Test
    void passesSortAndDirectionThroughToTheComparison() throws Exception {
        mockMvc.perform(get("/api/diff").param("left", left.toString())
                        .param("right", right.toString())
                        .param("sort", "CHANGE")
                        .param("direction", "asc"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.rows[0].change").value("ADDED"));
        mockMvc.perform(get("/api/diff").param("left", left.toString())
                        .param("right", right.toString())
                        .param("sort", "CHANGE")
                        .param("direction", "desc"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.rows[0].change").value("REMOVED"));
    }

    @Test
    void invalidRegexUsesTheExistingBadRequestHandler() throws Exception {
        mockMvc.perform(get("/api/diff").param("left", left.toString())
                        .param("right", right.toString())
                        .param("filter", "^(spring")
                        .param("regex", "true"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").exists());
    }

    private UUID seed(String fixture) throws Exception {
        ParsedSbom parsed = fixture(fixture);
        UUID id = UUID.randomUUID();
        jdbc.update("INSERT INTO sbom (id, filename, uploaded_at, spec_version, component_count)"
                        + " VALUES (?, ?, ?, ?, ?)",
                id, fixture, OffsetDateTime.now(ZoneOffset.UTC),
                parsed.specVersion(), parsed.components().size());

        for (ParsedComponent component : parsed.components()) {
            jdbc.update("INSERT INTO component (id, sbom_id, bom_ref, group_name, name, version,"
                            + " purl, component_type, is_root, dependency_scope)"
                            + " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    UUID.randomUUID(), id, component.bomRef(), component.group(), component.name(),
                    component.version(), component.purl(), component.type(), component.root(),
                    component.scope().name());
        }
        return id;
    }

    private void finding(String purl, String osvId, String cveId) {
        jdbc.update("INSERT INTO vulnerability_scan (purl, scanned_at, scanner_version)"
                        + " VALUES (?, ?, ?)",
                purl, OffsetDateTime.now(ZoneOffset.UTC), "test");
        jdbc.update("INSERT INTO vulnerability_finding"
                        + " (id, purl, osv_id, cve_id, severity_score) VALUES (?, ?, ?, ?, ?)",
                UUID.randomUUID(), purl, osvId, cveId, new BigDecimal("5.0"));
    }

    private ParsedSbom fixture(String name) throws Exception {
        try (InputStream stream = getClass().getResourceAsStream("/sboms/" + name)) {
            org.assertj.core.api.Assertions.assertThat(stream).as("fixture %s", name).isNotNull();
            return parser.parse(stream);
        }
    }
}
