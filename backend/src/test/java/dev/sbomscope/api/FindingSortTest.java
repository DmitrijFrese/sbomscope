package dev.sbomscope.api;

import java.io.InputStream;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MockMvc;

import dev.sbomscope.scanner.FindingQuery;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Every sort field, both directions, through the real SQL.
 *
 * <p>Written because adding one cost an afternoon's worth of a lesson: {@code FIXED_VERSION}
 * ordered by a column the {@code SELECT DISTINCT} list did not carry, and H2 rejects that — so
 * the whole findings endpoint answered 500 for one value of one parameter while every existing
 * test passed. A sort field is a small addition that touches hand-assembled SQL in three
 * places, and nothing else asserts that the assembled statement is even valid.
 *
 * <p>Deliberately driven by {@code SortField.values()}: a field added later is covered without
 * anybody remembering to come back here.
 */
@SpringBootTest
@AutoConfigureMockMvc
class FindingSortTest {

    @Autowired
    private MockMvc mockMvc;

    private MockMultipartFile fixture(String name) throws Exception {
        try (InputStream stream = getClass().getResourceAsStream("/sboms/" + name)) {
            return new MockMultipartFile("file", name, MediaType.APPLICATION_JSON_VALUE,
                    stream.readAllBytes());
        }
    }

    @Test
    void everySortFieldProducesValidSqlInBothDirections() throws Exception {
        String id = com.jayway.jsonpath.JsonPath.read(
                mockMvc.perform(multipart("/api/sboms").file(fixture("vuln-multi-module.cdx.json")))
                        .andExpect(status().isCreated())
                        .andReturn().getResponse().getContentAsString(),
                "$.id");

        for (FindingQuery.SortField sort : FindingQuery.SortField.values()) {
            for (String direction : new String[] {"asc", "desc"}) {
                // The paged view, which is where the DISTINCT constraint bites.
                mockMvc.perform(get("/api/sboms/" + id + "/findings")
                                .param("sort", sort.name())
                                .param("direction", direction)
                                .param("limit", "20")
                                .param("offset", "0"))
                        .andExpect(status().isOk());

                // And the export, which orders through a second hand-assembled statement.
                mockMvc.perform(get("/api/sboms/" + id + "/export.xlsx")
                                .param("sort", sort.name())
                                .param("direction", direction))
                        .andExpect(status().isOk());
            }
        }

        mockMvc.perform(delete("/api/sboms/" + id)).andExpect(status().isNoContent());
    }
}
