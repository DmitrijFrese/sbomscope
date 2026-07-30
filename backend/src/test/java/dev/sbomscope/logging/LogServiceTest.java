package dev.sbomscope.logging;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import tools.jackson.databind.ObjectMapper;

import static org.assertj.core.api.Assertions.assertThat;

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
        assertThat(service(dir).tail(10)).isEmpty();
    }

    @Test
    void tailReturnsMostRecentFirstAndRespectsLimit(@TempDir Path dir) throws IOException {
        Files.writeString(dir.resolve("activity.jsonl"), String.join("\n",
                line("2026-01-01T00:00:00Z", "FIRST"),
                line("2026-01-01T00:00:01Z", "SECOND"),
                line("2026-01-01T00:00:02Z", "THIRD")));

        List<ActivityEvent> events = service(dir).tail(2);

        assertThat(events).extracting(ActivityEvent::event).containsExactly("THIRD", "SECOND");
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

        List<ActivityEvent> events = service(dir).tail(10);

        assertThat(events).extracting(ActivityEvent::event).containsExactly("GOOD");
    }

    @Test
    void directoryReportsTheConfiguredPath(@TempDir Path dir) {
        assertThat(service(dir).directory()).isEqualTo(dir);
    }
}
