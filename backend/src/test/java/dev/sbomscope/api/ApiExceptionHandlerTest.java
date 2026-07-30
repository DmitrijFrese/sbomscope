package dev.sbomscope.api;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The catch-all advice must not turn ordinary "there is nothing here" into a server failure.
 *
 * <p>This has now happened twice with two different exception types, which is why it has a test
 * of its own rather than a line in an existing one: {@code ResponseStatusException} first, and
 * then {@link org.springframework.web.servlet.resource.NoResourceFoundException}, which looks
 * like it would be covered by that handler and is not — it implements {@code ErrorResponse}
 * without extending {@code ResponseStatusException}.
 */
@SpringBootTest
@AutoConfigureMockMvc
class ApiExceptionHandlerTest {

    @Autowired
    private MockMvc mockMvc;

    /**
     * {@code /api/settings} is a real near-miss, not an invented one: the mappings are
     * {@code /api/settings/scanner}, {@code /maven} and {@code /export}, and the parent path
     * maps to nothing. It reported 500 with a stack trace in the log until this was fixed.
     */
    @Test
    void unmappedApiPathIsNotFoundRatherThanServerError() throws Exception {
        mockMvc.perform(get("/api/settings"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.status").value(404));
    }

    /**
     * The property this protects, stated in ARCHITECTURE.md: unknown non-API paths are
     * forwarded to {@code index.html} so a deep link survives a refresh, while {@code /api/}
     * ones deliberately still fail — so that a mistyped fetch URL fails as a missing endpoint
     * rather than as an HTML parse error. That only holds if the failure is a 404.
     */
    @Test
    void unmappedApiPathReportsTheMissingPath() throws Exception {
        mockMvc.perform(get("/api/no-such-endpoint"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.message").value(org.hamcrest.Matchers.containsString("no-such-endpoint")));
    }

    /** A deliberate 404 from a controller keeps working, which is the older half of this. */
    @Test
    void controllerNotFoundStaysNotFound() throws Exception {
        mockMvc.perform(get("/api/sboms/00000000-0000-0000-0000-000000000000"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.message").value("No such SBOM"));
    }
}
