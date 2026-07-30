package dev.sbomscope.logging;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;

import tools.jackson.databind.ObjectMapper;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@code activity.jsonl} is read back by {@link LogService} and by the UI, so its shape
 * matters as much as its content: one parseable JSON object per line, written to the
 * dedicated {@code dev.sbomscope.activity} logger that logback-spring.xml binds to the file.
 */
class ActivityLoggerTest {

    private final ObjectMapper mapper = new ObjectMapper();
    private final ActivityLogger activityLogger = new ActivityLogger(mapper);
    private final ListAppender<ILoggingEvent> appender = new ListAppender<>();

    private Logger activityLoggerLogger() {
        return (Logger) LoggerFactory.getLogger("dev.sbomscope.activity");
    }

    @BeforeEach
    void attach() {
        appender.start();
        activityLoggerLogger().addAppender(appender);
    }

    @AfterEach
    void detach() {
        activityLoggerLogger().detachAppender(appender);
        appender.list.clear();
    }

    private ActivityEvent onlyEvent() {
        assertThat(appender.list).hasSize(1);
        return mapper.readValue(appender.list.get(0).getFormattedMessage(), ActivityEvent.class);
    }

    @Test
    void writesOneParseableEventWithOutcomeAndDetail() {
        activityLogger.record(ActivityLogger.Category.PROCESS, "SCAN", "SUCCESS", "3 findings");

        ActivityEvent event = onlyEvent();
        assertThat(event.category()).isEqualTo("PROCESS");
        assertThat(event.event()).isEqualTo("SCAN");
        assertThat(event.outcome()).isEqualTo("SUCCESS");
        assertThat(event.detail()).isEqualTo("3 findings");
        assertThat(event.timestamp()).isNotNull();
    }

    @Test
    void omitsOutcomeForAPlainChangeEvent() {
        activityLogger.record(ActivityLogger.Category.DATA, "SBOM_UPLOADED", "demo.cdx.json (12 components)");

        ActivityEvent event = onlyEvent();
        assertThat(event.outcome()).isNull();
        assertThat(event.detail()).isEqualTo("demo.cdx.json (12 components)");
    }
}
