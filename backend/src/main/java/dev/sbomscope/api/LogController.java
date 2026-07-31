package dev.sbomscope.api;

import java.util.List;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import dev.sbomscope.logging.ActivityEvent;
import dev.sbomscope.logging.LogService;

@RestController
@RequestMapping("/api/logs")
class LogController {

    private static final int MAX_LIMIT = 1000;
    private static final int MAX_TEXT_LINES = 5000;

    private final LogService logs;

    LogController(LogService logs) {
        this.logs = logs;
    }

    record LogStatus(String path, boolean canOpenFolder) {}

    @GetMapping("/status")
    LogStatus status() {
        return new LogStatus(logs.directory().toString(), logs.canOpenFolder());
    }

    /** Only meaningful because this process runs on the user's own machine. */
    @PostMapping("/open-folder")
    LogStatus openFolder() {
        logs.openFolder();
        return status();
    }

    @GetMapping("/activity")
    List<ActivityEvent> activity(
            @RequestParam(value = "limit", defaultValue = "200") int limit,
            @RequestParam(value = "filter", required = false) String filter,
            @RequestParam(value = "regex", defaultValue = "false") boolean regex,
            @RequestParam(value = "negate", defaultValue = "false") boolean negate) {
        return logs.tail(Math.min(Math.max(limit, 1), MAX_LIMIT), filter, regex, negate);
    }

    /**
     * The verbose text log, oldest line first.
     *
     * <p>A higher ceiling than the activity tail: this is where a probe's whole Maven output
     * lands, and one failed invocation alone can run to a few hundred lines, so 200 of them
     * would not reach the start of the failure being read.
     */
    @GetMapping("/text")
    List<String> text(
            @RequestParam(value = "limit", defaultValue = "500") int limit,
            @RequestParam(value = "filter", required = false) String filter,
            @RequestParam(value = "regex", defaultValue = "false") boolean regex,
            @RequestParam(value = "negate", defaultValue = "false") boolean negate) {
        return logs.text(Math.min(Math.max(limit, 1), MAX_TEXT_LINES), filter, regex, negate);
    }
}
