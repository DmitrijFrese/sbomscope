package dev.sbomscope.api;

import com.jayway.jsonpath.JsonPath;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.nullValue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Projects and folders over HTTP (B19), against the real Flyway-built schema.
 *
 * <p>{@code @Transactional} so each test's writes roll back afterwards — without it every
 * method shares one committed database, and two tests each creating a project named
 * "Project" would collide on the sibling-name rule for no reason either test states.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class FolderControllerTest {

    @Autowired
    private MockMvc mockMvc;

    private String create(String name, String parentId) throws Exception {
        String body = parentId == null
                ? "{\"name\":\"" + name + "\",\"parentId\":null}"
                : "{\"name\":\"" + name + "\",\"parentId\":\"" + parentId + "\"}";
        return JsonPath.read(
                mockMvc.perform(post("/api/folders").contentType(MediaType.APPLICATION_JSON).content(body))
                        .andExpect(status().isCreated())
                        .andReturn().getResponse().getContentAsString(),
                "$.id");
    }

    @Test
    void createsListsAndDeletesAProject() throws Exception {
        String id = create("Payments Platform", null);

        mockMvc.perform(get("/api/folders"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[?(@.id == '" + id + "')].name").value(contains("Payments Platform")))
                // Filter-projected paths keep a null field as an element rather than dropping
                // it — `[null]`, not `[]` — unlike a plain `$.parentId` on a single object.
                .andExpect(jsonPath("$[?(@.id == '" + id + "')].parentId").value(contains(nullValue())));

        mockMvc.perform(delete("/api/folders/" + id)).andExpect(status().isNoContent());
        mockMvc.perform(get("/api/folders"))
                .andExpect(jsonPath("$[?(@.id == '" + id + "')]").value(hasSize(0)));
    }

    @Test
    void refusesADuplicateSiblingName() throws Exception {
        create("Duplicate", null);

        mockMvc.perform(post("/api/folders")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\":\"Duplicate\",\"parentId\":null}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value(org.hamcrest.Matchers.containsString("already")));
    }

    @Test
    void refusesAFourthLevel() throws Exception {
        String project = create("Project", null);
        String level2 = create("Level 2", project);
        String level3 = create("Level 3", level2);

        mockMvc.perform(post("/api/folders")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\":\"Level 4\",\"parentId\":\"" + level3 + "\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value(org.hamcrest.Matchers.containsString("levels deep")));
    }

    @Test
    void renamesAFolder() throws Exception {
        String id = create("Old name", null);

        mockMvc.perform(patch("/api/folders/" + id + "/name")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\":\"New name\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name").value("New name"));
    }

    @Test
    void movesAFolderToTheTopLevel() throws Exception {
        String project = create("Project", null);
        String child = create("Child", project);

        mockMvc.perform(patch("/api/folders/" + child + "/parent")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"parentId\":null}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.parentId").doesNotExist());
    }

    @Test
    void refusesMovingAFolderIntoItsOwnDescendant() throws Exception {
        String project = create("Project", null);
        String child = create("Child", project);

        mockMvc.perform(patch("/api/folders/" + project + "/parent")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"parentId\":\"" + child + "\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value(org.hamcrest.Matchers.containsString("inside it")));
    }

    @Test
    void deletingAnUnknownFolderIsNotFound() throws Exception {
        mockMvc.perform(delete("/api/folders/00000000-0000-0000-0000-000000000000"))
                .andExpect(status().isNotFound());
    }
}
