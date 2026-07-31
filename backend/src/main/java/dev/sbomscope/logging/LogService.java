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
import java.util.Locale;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import dev.sbomscope.scanner.InvalidFilterPatternException;

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
    public List<ActivityEvent> tail(int limit, String filter, boolean regex, boolean negate) {
        Path file = directory.resolve("activity.jsonl");
        if (!Files.isRegularFile(file)) {
            return List.of();
        }

        LineMatcher matcher = LineMatcher.of(filter, regex, negate);

        String block;
        try {
            // Filtering reads the widest window it is allowed rather than one sized to the
            // limit. "The last 200 entries, of which some match" and "the last 200 entries
            // that match" are different answers, and only the second is what somebody hunting
            // a failure asked for — a filter that could only see 200 records back would
            // report "nothing" for an event that happened five minutes ago.
            block = readTailBlock(file, matcher.filtering()
                    ? MAX_ACTIVITY_WINDOW_BYTES
                    : windowBytesFor(limit));
        } catch (IOException e) {
            throw new UncheckedIOException("Could not read " + file, e);
        }

        List<String> lines = block.lines().filter(line -> !line.isBlank()).toList();
        List<ActivityEvent> events = new ArrayList<>();
        for (int i = lines.size() - 1; i >= 0 && events.size() < limit; i--) {
            ActivityEvent event;
            try {
                event = mapper.readValue(lines.get(i), ActivityEvent.class);
            } catch (JacksonException e) {
                // A line written mid-rotation, or truncated by a crash; skip it rather than
                // failing the whole tail over one bad record.
                continue;
            }
            // Matched against the fields as rendered, not against the raw JSON: a pattern like
            // `^SCAN` should match the event name, and against the JSON it would match nothing
            // while `purl` would match a field name nobody can see on screen.
            if (matcher.test(searchableText(event))) {
                events.add(event);
            }
        }
        return events;
    }

    /**
     * The columns the panel actually shows, joined — what the reader believes they are searching.
     *
     * <p><b>Absent fields are dropped rather than joined as empty strings.</b> {@code outcome}
     * and {@code detail} are null for events that describe a change rather than a result, and
     * padding them out left trailing separators on the end of the subject — so {@code $} anchored
     * past whitespace nobody can see and a pattern ending in one silently matched nothing. Caught
     * by a test, which is the only way it would have been: on screen the two render identically.
     */
    private static String searchableText(ActivityEvent event) {
        return Stream.of(event.category(), event.event(), event.outcome(), event.detail())
                .filter(value -> value != null && !value.isBlank())
                .collect(Collectors.joining(" "));
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
    public List<String> text(int limit, String filter, boolean regex, boolean negate) {
        Path file = directory.resolve("sbomscope.log");
        if (!Files.isRegularFile(file)) {
            return List.of();
        }

        LineMatcher matcher = LineMatcher.of(filter, regex, negate);

        String block;
        try {
            // A prose log line is longer than a JSON activity record — a stack trace frame runs
            // well past a hundred characters — so the window per line is wider than the one
            // above. Undersizing still only costs lines, never correctness. Filtering takes the
            // whole allowance, for the reason given on the activity tail.
            block = readTailBlock(file, matcher.filtering()
                    ? MAX_TEXT_WINDOW_BYTES
                    : Math.clamp((long) limit * 512, 64 * 1024, MAX_TEXT_WINDOW_BYTES));
        } catch (IOException e) {
            throw new UncheckedIOException("Could not read " + file, e);
        }

        List<String> lines = block.lines().filter(matcher::test).toList();
        return lines.size() <= limit ? lines : lines.subList(lines.size() - limit, lines.size());
    }

    private static final int MAX_ACTIVITY_WINDOW_BYTES = 4 * 1024 * 1024;
    private static final int MAX_TEXT_WINDOW_BYTES = 8 * 1024 * 1024;

    /**
     * Matches one log line, literally or as a regular expression.
     *
     * <p><b>The deadline is the part that is not decoration.</b> A log line is far longer than
     * a purl — a stack-trace frame or a Maven command line runs to hundreds of characters, and
     * the window here holds thousands of lines — which is exactly where the backtracking shapes
     * that survive Java's engine start costing real time. Unlike the SQL filter, this loop is
     * ours, so it can check between lines and stop; a single line is still uninterruptible, but
     * one line is bounded and thousands are not.
     *
     * <p>Exceeding it is reported, never disguised as "no matches" — a search that quietly
     * returned nothing would be read as evidence the log does not contain the thing being
     * looked for, which is the opposite of what happened.
     */
    private record LineMatcher(Pattern pattern, String literal, boolean negate, long deadlineNanos) {

        private static final long BUDGET_NANOS = 5_000_000_000L;

        static LineMatcher of(String filter, boolean regex, boolean negate) {
            if (filter == null || filter.isBlank()) {
                return new LineMatcher(null, null, false, 0);
            }
            if (!regex) {
                return new LineMatcher(null, filter.trim().toLowerCase(Locale.ROOT), negate, 0);
            }
            try {
                // CASE_INSENSITIVE for the same reason the findings filter passes 'i': turning
                // one toggle on must not also change whether case matters.
                return new LineMatcher(Pattern.compile(filter, Pattern.CASE_INSENSITIVE), null,
                        negate, System.nanoTime() + BUDGET_NANOS);
            } catch (PatternSyntaxException e) {
                throw new InvalidFilterPatternException(filter, e);
            }
        }

        boolean filtering() {
            return pattern != null || literal != null;
        }

        boolean test(String line) {
            return filtering() && negate ? !matches(line) : matches(line);
        }

        private boolean matches(String line) {
            if (literal != null) {
                return line.toLowerCase(Locale.ROOT).contains(literal);
            }
            if (pattern == null) {
                return true;
            }
            if (System.nanoTime() > deadlineNanos) {
                throw new IllegalArgumentException(
                        "That pattern is taking too long to run over this log. It is valid, but "
                                + "expensive — try anchoring it, or narrowing what it can repeat.");
            }
            return pattern.matcher(line).find();
        }
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
