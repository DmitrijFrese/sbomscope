package dev.sbomscope.logging;

import java.awt.Desktop;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import tools.jackson.core.JacksonException;
import tools.jackson.databind.ObjectMapper;

/**
 * Read-side access to the log directory: tailing {@code activity.jsonl}, and opening the
 * folder it lives in.
 *
 * <p>Opening a folder is only possible because this process runs on the user's own
 * machine — the same property that makes workspace scanning possible. A browser cannot open
 * a native folder from an {@code http://} page; this drives {@link Desktop} from the backend
 * instead, which is a different thing.
 */
@Service
public class LogService {

    private final ObjectMapper mapper;
    private final Path directory;

    LogService(ObjectMapper mapper, @Value("${sbomscope.logs-directory}") String logsDirectory) {
        this.mapper = mapper;
        this.directory = Path.of(logsDirectory);
    }

    public Path directory() {
        return directory;
    }

    /**
     * Whether opening a native file manager window is possible here. Headless environments
     * support no {@link Desktop} at all — the caller falls back silently to the copyable path
     * rather than offering a button that fails.
     */
    public boolean canOpenFolder() {
        return Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.OPEN);
    }

    public void openFolder() {
        if (!canOpenFolder()) {
            throw new IllegalStateException("Opening a folder is not supported on this machine.");
        }
        try {
            Files.createDirectories(directory);
            Desktop.getDesktop().open(directory.toFile());
        } catch (IOException e) {
            throw new UncheckedIOException("Could not open " + directory, e);
        }
    }

    /**
     * Most recent entries first, up to {@code limit}.
     *
     * <p>Re-reads the file from scratch on every call rather than tracking a cursor. The file
     * is size-capped, so this is cheap, and it is naturally robust to rotation, which a byte
     * offset would not be.
     */
    public List<ActivityEvent> tail(int limit) {
        Path file = directory.resolve("activity.jsonl");
        if (!Files.isRegularFile(file)) {
            return List.of();
        }

        List<String> lines;
        try {
            lines = Files.readAllLines(file, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException("Could not read " + file, e);
        }

        List<ActivityEvent> events = new ArrayList<>();
        int from = Math.max(0, lines.size() - limit);
        for (int i = lines.size() - 1; i >= from; i--) {
            String line = lines.get(i);
            if (line.isBlank()) {
                continue;
            }
            try {
                events.add(mapper.readValue(line, ActivityEvent.class));
            } catch (JacksonException e) {
                // A line written mid-rotation, or truncated by a crash; skip it rather than
                // failing the whole tail over one bad record.
            }
        }
        return events;
    }
}
