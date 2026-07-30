package dev.sbomscope.logging;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import tools.jackson.databind.ObjectMapper;

/**
 * Writes {@code activity.jsonl}: one JSON object per notable event.
 *
 * <p>Notable = anything touching the network, anything running an external process, and
 * anything changing stored data — the same three categories constraint 1 already draws the
 * offline/disclosure line around. A recommendation nobody can check after the fact is the
 * failure mode this project keeps designing against, so every such action writes one line
 * here regardless of which part of the codebase triggered it.
 *
 * <p>Bound to its own Logback appender under the {@code dev.sbomscope.activity} logger name
 * with additivity off (see {@code logback-spring.xml}), so this line never also lands in the
 * prose log — {@code activity.jsonl} is structured by construction, and the UI that tails it
 * never has to parse prose.
 */
@Component
public class ActivityLogger {

    private static final Logger activity = LoggerFactory.getLogger("dev.sbomscope.activity");

    public enum Category {
        NETWORK,
        PROCESS,
        DATA
    }

    private final ObjectMapper mapper;

    public ActivityLogger(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    /** For an event with no separate success/failure verdict — a plain "this happened". */
    public void record(Category category, String event, String detail) {
        record(category, event, null, detail);
    }

    public void record(Category category, String event, String outcome, String detail) {
        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("timestamp", Instant.now());
        entry.put("category", category.name());
        entry.put("event", event);
        if (outcome != null) {
            entry.put("outcome", outcome);
        }
        if (detail != null) {
            entry.put("detail", detail);
        }
        activity.info(mapper.writeValueAsString(entry));
    }
}
