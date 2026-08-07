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
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
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
    void workspaceEvidenceExplainsWhenNoWorkspaceWasAttached() throws Exception {
        MockMvc mvc = mockMvc();
        String id = com.jayway.jsonpath.JsonPath.read(
                mvc.perform(multipart("/api/sboms").file(fixture("npm-frontend.cdx.json")))
                        .andExpect(status().isCreated())
                        .andReturn().getResponse().getContentAsString(),
                "$.id");
        String purl = com.jayway.jsonpath.JsonPath.read(
                mvc.perform(get("/api/sboms/" + id + "/components"))
                        .andExpect(status().isOk())
                        .andReturn().getResponse().getContentAsString(),
                "$[0].purl");

        mvc.perform(get("/api/sboms/" + id + "/component/workspace").param("purl", purl))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.state").value("NOT_CONFIGURED"))
                .andExpect(jsonPath("$.message").value(org.hamcrest.Matchers.containsString("without a workspace")));
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

    @Test
    void attachesChangesAndClearsAWorkspaceAfterUpload() throws Exception {
        MockMvc mvc = mockMvc();
        String id = com.jayway.jsonpath.JsonPath.read(
                mvc.perform(multipart("/api/sboms").file(fixture("npm-frontend.cdx.json")))
                        .andExpect(jsonPath("$.workspacePath").doesNotExist())
                        .andReturn().getResponse().getContentAsString(),
                "$.id");
        String existingDirectory = System.getProperty("java.io.tmpdir");

        // Set, where none existed — the gap B20 closes: until 2026-08-06 this path only
        // existed on upload, so a document that skipped it could never gain one.
        mvc.perform(patch("/api/sboms/" + id + "/workspace")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"workspacePath\":\"" + existingDirectory.replace("\\", "\\\\") + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.workspacePath").exists());

        // Clear — a real operation, not a no-op: a workspace that has moved is worse than
        // none, so the endpoint must accept a null path rather than reject it as empty.
        mvc.perform(patch("/api/sboms/" + id + "/workspace")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"workspacePath\":null}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.workspacePath").doesNotExist());
    }

    @Test
    void rejectsAttachingAWorkspaceThatDoesNotExist() throws Exception {
        MockMvc mvc = mockMvc();
        String id = com.jayway.jsonpath.JsonPath.read(
                mvc.perform(multipart("/api/sboms").file(fixture("npm-frontend.cdx.json")))
                        .andReturn().getResponse().getContentAsString(),
                "$.id");

        mvc.perform(patch("/api/sboms/" + id + "/workspace")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"workspacePath\":\"/definitely/not/a/real/directory\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value(
                        org.hamcrest.Matchers.containsString("does not exist")));
    }

    @Test
    void attachingAWorkspaceToAnUnknownSbomIsNotFound() throws Exception {
        mockMvc().perform(patch("/api/sboms/00000000-0000-0000-0000-000000000000/workspace")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"workspacePath\":null}"))
                .andExpect(status().isNotFound());
    }

    @Test
    void filesADocumentIntoAFolderAndBackOut() throws Exception {
        MockMvc mvc = mockMvc();
        String id = com.jayway.jsonpath.JsonPath.read(
                mvc.perform(multipart("/api/sboms").file(fixture("npm-frontend.cdx.json")))
                        .andReturn().getResponse().getContentAsString(),
                "$.id");
        String folderId = com.jayway.jsonpath.JsonPath.read(
                mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders
                                .post("/api/folders")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"name\":\"Filed here\",\"parentId\":null}"))
                        .andExpect(status().isCreated())
                        .andReturn().getResponse().getContentAsString(),
                "$.id");

        mvc.perform(patch("/api/sboms/" + id + "/folder")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"folderId\":\"" + folderId + "\"}"))
                .andExpect(status().isNoContent());
        mvc.perform(get("/api/sboms")).andExpect(status().isOk())
                .andExpect(jsonPath("$[?(@.id == '" + id + "')].folderId").value(
                        org.hamcrest.Matchers.contains(folderId)));

        mvc.perform(patch("/api/sboms/" + id + "/folder")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"folderId\":null}"))
                .andExpect(status().isNoContent());
        // A filter-projected path keeps a null field as an element — `[null]`, not `[]` —
        // unlike a plain `$.folderId` on a single object, where `doesNotExist()` applies.
        mvc.perform(get("/api/sboms")).andExpect(status().isOk())
                .andExpect(jsonPath("$[?(@.id == '" + id + "')].folderId").value(
                        org.hamcrest.Matchers.contains(org.hamcrest.Matchers.nullValue())));

        // This class is not @Transactional, so the folder above is committed and outlives the
        // test. That leaked into FolderServiceTest, whose top-level group then contained a
        // folder it never created — caught by the strict membership check in reorderFolders.
        // Deleting it here keeps the shared in-memory database as this test found it.
        mvc.perform(delete("/api/folders/" + folderId)).andExpect(status().isNoContent());
    }
}
