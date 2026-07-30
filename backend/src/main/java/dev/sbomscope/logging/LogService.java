package dev.sbomscope.logging;

import java.awt.Desktop;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
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
     * <p><b>No cursor is kept</b> — every call seeks from the file's current end, which is what
     * makes this robust to rotation in a way a stored byte offset would not be. But it reads
     * only the last few hundred KB rather than the whole file: the panel polls every 3 seconds,
     * the file is capped at 10 MB, and reading and parsing 10 MB twenty times a minute to
     * return 200 records is a cost with nothing on the other side of it. The window is sized
     * from {@code limit}, so the caller cannot ask for more than it is willing to read.
     */
    public List<ActivityEvent> tail(int limit) {
        Path file = directory.resolve("activity.jsonl");
        if (!Files.isRegularFile(file)) {
            return List.of();
        }

        String block;
        try {
            block = readTailBlock(file, windowBytesFor(limit));
        } catch (IOException e) {
            throw new UncheckedIOException("Could not read " + file, e);
        }

        List<String> lines = block.lines().filter(line -> !line.isBlank()).toList();
        List<ActivityEvent> events = new ArrayList<>();
        int from = Math.max(0, lines.size() - limit);
        for (int i = lines.size() - 1; i >= from; i--) {
            try {
                events.add(mapper.readValue(lines.get(i), ActivityEvent.class));
            } catch (JacksonException e) {
                // A line written mid-rotation, or truncated by a crash; skip it rather than
                // failing the whole tail over one bad record.
            }
        }
        return events;
    }

    /**
     * The last {@code limit} lines of the verbose text log, oldest first.
     *
     * <p>Same bounded, cursor-less tail as {@link #tail(int)} and for the same reasons. What is
     * different is what it is for: {@code activity.jsonl} records that something notable
     * happened, while this holds every {@code mvn} command and everything Maven said back — the
     * thing somebody diagnosing an air-gapped probe actually has to read. Until now the only
     * way to reach it was the "Open folder" button, which is no way at all on a machine where
     * the browser and the file manager are not both to hand.
     *
     * <p>Oldest first, unlike the activity tail: this is a transcript, and reading a stack trace
     * bottom-up is not a thing anyone wants to do.
     */
    public List<String> text(int limit) {
        Path file = directory.resolve("sbomscope.log");
        if (!Files.isRegularFile(file)) {
            return List.of();
        }

        String block;
        try {
            // A prose log line is longer than a JSON activity record — a stack trace frame runs
            // well past a hundred characters — so the window per line is wider than the one
            // above. Undersizing still only costs lines, never correctness.
            block = readTailBlock(file, Math.clamp((long) limit * 512, 64 * 1024, 8 * 1024 * 1024));
        } catch (IOException e) {
            throw new UncheckedIOException("Could not read " + file, e);
        }

        List<String> lines = block.lines().toList();
        return lines.size() <= limit ? lines : lines.subList(lines.size() - limit, lines.size());
    }

    /**
     * Enough room for {@code limit} entries with generous headroom — a probe verdict is the
     * longest thing written here and runs to a few hundred bytes. Undersizing costs entries,
     * never correctness: a short window simply returns fewer than asked for.
     */
    private static int windowBytesFor(int limit) {
        return Math.clamp((long) limit * 1024, 64 * 1024, 4 * 1024 * 1024);
    }

    private static String readTailBlock(Path file, int windowBytes) throws IOException {
        try (SeekableByteChannel channel = Files.newByteChannel(file, StandardOpenOption.READ)) {
            long size = channel.size();
            long from = Math.max(0, size - windowBytes);
            channel.position(from);

            ByteBuffer buffer = ByteBuffer.allocate((int) Math.min(size - from, windowBytes));
            while (buffer.hasRemaining() && channel.read(buffer) != -1) {
                // Reading a file, so a short read only means "not finished yet".
            }

            String text = new String(buffer.array(), 0, buffer.position(), StandardCharsets.UTF_8);
            if (from > 0) {
                // Starting mid-file almost certainly lands mid-line, and possibly mid-UTF-8
                // character. Both are confined to that first fragment, so dropping it is
                // enough — there is no need to decode carefully around the boundary.
                int firstNewline = text.indexOf('\n');
                text = firstNewline < 0 ? "" : text.substring(firstNewline + 1);
            }
            return text;
        }
    }
}
