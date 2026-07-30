package dev.sbomscope.logging;

import java.time.Instant;

/**
 * One line of {@code activity.jsonl}, deserialized.
 *
 * @param outcome null for events that describe a change rather than a result
 * @param detail  the specifics — kept as one free-form string rather than a nested
 *                structure, so every event shares the same shape regardless of what
 *                produced it
 */
public record ActivityEvent(
        Instant timestamp,
        String category,
        String event,
        String outcome,
        String detail) {}
