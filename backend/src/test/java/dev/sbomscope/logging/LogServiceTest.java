package dev.sbomscope.logging;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import tools.jackson.databind.ObjectMapper;

import dev.sbomscope.scanner.InvalidFilterPatternException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * {@link LogService#tail} re-reads {@code activity.jsonl} from scratch on every call rather
 * than tracking a cursor — cheap because the file is size-capped, and naturally robust to
 * rotation, which a byte offset would not be.
 */
class LogServiceTest {

    private final ObjectMapper mapper = new ObjectMapper();

    private LogService service(Path directory) {
        return new LogService(mapper, directory.toString());
    }

    private String line(String timestamp, String event) {
        return "{\"timestamp\":\"%s\",\"category\":\"DATA\",\"event\":\"%s\"}".formatted(timestamp, event);
    }

    @Test
    void tailOfAnAbsentFileIsEmpty(@TempDir Path dir) {
        assertThat(service(dir).tail(10, null, false, false)).isEmpty();
    }

    @Test
    void tailReturnsMostRecentFirstAndRespectsLimit(@TempDir Path dir) throws IOException {
        Files.writeString(dir.resolve("activity.jsonl"), String.join("\n",
                line("2026-01-01T00:00:00Z", "FIRST"),
                line("2026-01-01T00:00:01Z", "SECOND"),
                line("2026-01-01T00:00:02Z", "THIRD")));

        List<ActivityEvent> events = service(dir).tail(2, null, false, false);

        assertThat(events).extracting(ActivityEvent::event).containsExactly("THIRD", "SECOND");
    }

    @Test
    void filteringReturnsTheMostRecentMatchesRatherThanMatchesAmongTheMostRecent(@TempDir Path dir)
            throws IOException {
        // The distinction the item turns on. Asking for one entry matching SECOND must not
        // answer "nothing" because SECOND is not among the newest one — a filter that could
        // only see as far back as the limit would report an event that plainly happened as
        // absent, which in a diagnostic tool is worse than showing nothing at all.
        Files.writeString(dir.resolve("activity.jsonl"), String.join("\n",
                line("2026-01-01T00:00:00Z", "FIRST"),
                line("2026-01-01T00:00:01Z", "SECOND"),
                line("2026-01-01T00:00:02Z", "THIRD")));

        assertThat(service(dir).tail(1, "SECOND", false, false))
                .extracting(ActivityEvent::event).containsExactly("SECOND");
    }

    @Test
    void aRegexFilterMatchesTheFieldsTheReaderCanSee(@TempDir Path dir) throws IOException {
        // Matched against the rendered columns, not the raw JSON: `^FIRST` should find the
        // event name, where against the JSON text it would match nothing at all.
        Files.writeString(dir.resolve("activity.jsonl"), String.join("\n",
                line("2026-01-01T00:00:00Z", "FIRST"),
                line("2026-01-01T00:00:01Z", "SECOND")));

        assertThat(service(dir).tail(10, "^DATA (FIRST|NOPE)$", true, false))
                .extracting(ActivityEvent::event).containsExactly("FIRST");
        // Case-insensitive, exactly as the literal filter is — one toggle, one change.
        assertThat(service(dir).tail(10, "second", true, false))
                .extracting(ActivityEvent::event).containsExactly("SECOND");
    }

    @Test
    void anInvalidPatternIsReportedRatherThanReturningNothing(@TempDir Path dir) throws IOException {
        // "No matching lines" and "that is not a pattern" are different answers, and only one
        // of them tells the reader what to do next.
        Files.writeString(dir.resolve("activity.jsonl"), line("2026-01-01T00:00:00Z", "FIRST"));

        assertThatThrownBy(() -> service(dir).tail(10, "SCAN(", true, false))
                .isInstanceOf(InvalidFilterPatternException.class)
                .hasMessageContaining("Unclosed group");
    }

    @Test
    void theTextTailFiltersToMatchingLinesOnly(@TempDir Path dir) throws IOException {
        Files.writeString(dir.resolve("sbomscope.log"), String.join("\n",
                "INFO  running mvn dependency:tree",
                "WARN  could not obtain the plugin",
                "INFO  finished"));

        assertThat(service(dir).text(10, "^WARN", true, false))
                .containsExactly("WARN  could not obtain the plugin");
        assertThat(service(dir).text(10, "mvn", false, false))
                .containsExactly("INFO  running mvn dependency:tree");
        assertThat(service(dir).text(10, null, false, false)).hasSize(3);
    }

    /**
     * A line written mid-rotation, or truncated by a crash, must not take the rest of the
     * tail down with it — one bad record is not a reason to hide every good one.
     */
    @Test
    void tailSkipsAMalformedLineRatherThanFailing(@TempDir Path dir) throws IOException {
        Files.writeString(dir.resolve("activity.jsonl"), String.join("\n",
                line("2026-01-01T00:00:00Z", "GOOD"),
                "{not valid json"));

        List<ActivityEvent> events = service(dir).tail(10, null, false, false);

        assertThat(events).extracting(ActivityEvent::event).containsExactly("GOOD");
    }

    @Test
    void directoryReportsTheConfiguredPath(@TempDir Path dir) {
        assertThat(service(dir).directory()).isEqualTo(dir);
    }
}
