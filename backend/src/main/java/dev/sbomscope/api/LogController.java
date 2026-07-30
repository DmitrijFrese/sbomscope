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
    List<ActivityEvent> activity(@RequestParam(value = "limit", defaultValue = "200") int limit) {
        return logs.tail(Math.min(Math.max(limit, 1), MAX_LIMIT));
    }
}
