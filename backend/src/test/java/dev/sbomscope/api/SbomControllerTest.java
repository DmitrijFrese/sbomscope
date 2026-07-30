package dev.sbomscope.api;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MockMvc;

import dev.sbomscope.sbom.SbomFileStore;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * End-to-end coverage of the upload lifecycle against the real database and the real
 * Flyway-built schema.
 */
@SpringBootTest
@AutoConfigureMockMvc
class SbomControllerTest {

    @Autowired
    private MockMvc mockMvc;

    /** Pointed at the test data directory by src/test/resources/application.yml, never ~/.sbomscope. */
    @Autowired
    private SbomFileStore files;

    private MockMvc mockMvc() {
        return mockMvc;
    }

    private MockMultipartFile fixture(String name) throws Exception {
        try (InputStream stream = getClass().getResourceAsStream("/sboms/" + name)) {
            return new MockMultipartFile("file", name, MediaType.APPLICATION_JSON_VALUE,
                    stream.readAllBytes());
        }
    }

    private MockMultipartFile file(String name, String content) {
        return new MockMultipartFile("file", name, MediaType.APPLICATION_JSON_VALUE,
                content.getBytes());
    }

    @Test
    void uploadsListsAndDeletesAnSbom() throws Exception {
        MockMvc mvc = mockMvc();

        String id = com.jayway.jsonpath.JsonPath.read(
                mvc.perform(multipart("/api/sboms").file(fixture("npm-frontend.cdx.json")))
                        .andExpect(status().isCreated())
                        .andExpect(jsonPath("$.filename").value("npm-frontend.cdx.json"))
                        .andExpect(jsonPath("$.specVersion").value("1.5"))
                        .andExpect(jsonPath("$.componentCount").value(org.hamcrest.Matchers.greaterThan(0)))
                        .andExpect(jsonPath("$.workspacePath").doesNotExist())
                        .andReturn().getResponse().getContentAsString(),
                "$.id");

        mvc.perform(get("/api/sboms"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[?(@.id == '" + id + "')]").exists());

        mvc.perform(get("/api/sboms/" + id + "/components"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].name").exists())
                .andExpect(jsonPath("$[0].purl").exists());

        mvc.perform(delete("/api/sboms/" + id)).andExpect(status().isNoContent());
        mvc.perform(get("/api/sboms/" + id)).andExpect(status().isNotFound());
    }

    @Test
    void rejectsAFileThatIsNotAnSbom() throws Exception {
        mockMvc().perform(multipart("/api/sboms").file(file("notes.json", "{\"hello\":\"world\"}")))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value(org.hamcrest.Matchers.containsString("CycloneDX")));
    }

    @Test
    void rejectsAnEmptyFile() throws Exception {
        mockMvc().perform(multipart("/api/sboms").file(file("empty.json", "")))
                .andExpect(status().isBadRequest());
    }

    @Test
    void rejectsAWorkspacePathThatDoesNotExist() throws Exception {
        mockMvc().perform(multipart("/api/sboms")
                        .file(fixture("npm-frontend.cdx.json"))
                        .param("workspacePath", "/definitely/not/a/real/directory"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value(
                        org.hamcrest.Matchers.containsString("does not exist")));
    }

    @Test
    void acceptsAValidWorkspacePath() throws Exception {
        String existingDirectory = System.getProperty("java.io.tmpdir");

        mockMvc().perform(multipart("/api/sboms")
                        .file(fixture("maven-sbomscope.cdx.json"))
                        .param("workspacePath", existingDirectory))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.workspacePath").exists());
    }

    @Test
    void returnsNotFoundForAnUnknownSbom() throws Exception {
        mockMvc().perform(get("/api/sboms/00000000-0000-0000-0000-000000000000"))
                .andExpect(status().isNotFound());
    }

    @Test
    void servesTheStoredDocumentUnderTheNameItWasUploadedWith() throws Exception {
        MockMvc mvc = mockMvc();
        String uploaded = new String(fixture("npm-frontend.cdx.json").getBytes(), StandardCharsets.UTF_8);

        String id = com.jayway.jsonpath.JsonPath.read(
                mvc.perform(multipart("/api/sboms").file(fixture("npm-frontend.cdx.json")))
                        .andReturn().getResponse().getContentAsString(),
                "$.id");

        // Byte-identical to what was uploaded, not a re-serialisation of our parse: this is
        // the file the scanner reads, which is exactly why it is the one worth handing on.
        mvc.perform(get("/api/sboms/" + id + "/document"))
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Disposition",
                        org.hamcrest.Matchers.containsString("npm-frontend.cdx.json")))
                .andExpect(content().string(uploaded));

        mvc.perform(delete("/api/sboms/" + id)).andExpect(status().isNoContent());
    }

    @Test
    void answersNotFoundWhenTheDocumentHasBeenSweptFromDisk() throws Exception {
        MockMvc mvc = mockMvc();

        String id = com.jayway.jsonpath.JsonPath.read(
                mvc.perform(multipart("/api/sboms").file(fixture("maven-sbomscope.cdx.json")))
                        .andReturn().getResponse().getContentAsString(),
                "$.id");

        // A row can outlive its file — the sweeper is deliberately one-directional and a
        // schema reset never touches the disk — and that state must not be a 500.
        Files.delete(files.pathFor(UUID.fromString(id)));

        mvc.perform(get("/api/sboms/" + id + "/document")).andExpect(status().isNotFound());

        mvc.perform(delete("/api/sboms/" + id)).andExpect(status().isNoContent());
    }
}
