package dev.sbomscope.bump;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** Reads npm declarations while retaining their exact locations in the source bytes. */
public class PackageJsonScanner {

    public record PackageScan(String path, String name, List<RawNpmDependency> dependencies,
                              TextRange overridesInsertionPoint) {}

    /**
     * @param section       "dependencies", "devDependencies" or "optionalDependencies"
     * @param literalRange  the value's byte range, quotes EXCLUDED, so a patch replaces the literal
     *                      and leaves the JSON string intact
     */
    public record RawNpmDependency(String name, String section, String versionLiteral,
                                   TextRange literalRange, int ordinal) {}

    public PackageScan scan(String path, String text) {
        ObjectValue root = new Parser(path, text).parseRoot();
        String name = stringMember(root, "name");
        List<RawNpmDependency> dependencies = new ArrayList<>();
        int ordinal = 0;
        for (Entry entry : root.entries()) {
            if (!isDependencySection(entry.name()) || !(entry.value() instanceof ObjectValue section)) {
                continue;
            }
            for (Entry dependency : section.entries()) {
                if (!(dependency.value() instanceof StringValue value)) {
                    continue;
                }
                String literal = text.substring(value.contentStart(), value.contentEnd());
                dependencies.add(new RawNpmDependency(dependency.name(), entry.name(), literal,
                        range(text, value.contentStart(), value.contentEnd()), ordinal++));
            }
        }
        JsonValue overrides = member(root, "overrides");
        ObjectValue insertionHost = overrides instanceof ObjectValue object ? object : root;
        int insertion = insertionHost.entries().isEmpty()
                ? insertionHost.open() + 1
                : insertionHost.entries().getLast().end();
        return new PackageScan(path, name, List.copyOf(dependencies),
                range(text, insertion, insertion));
    }

    static List<String> workspacePatterns(String path, String text) {
        ObjectValue root = new Parser(path, text).parseRoot();
        JsonValue workspaces = member(root, "workspaces");
        if (workspaces instanceof ObjectValue object) {
            workspaces = member(object, "packages");
        }
        if (!(workspaces instanceof ArrayValue array)) {
            return List.of();
        }
        return array.values().stream().filter(StringValue.class::isInstance)
                .map(StringValue.class::cast).map(StringValue::value).toList();
    }

    private static boolean isDependencySection(String name) {
        return "dependencies".equals(name) || "devDependencies".equals(name)
                || "optionalDependencies".equals(name);
    }

    private static String stringMember(ObjectValue object, String name) {
        JsonValue value = member(object, name);
        return value instanceof StringValue string ? string.value() : null;
    }

    private static JsonValue member(ObjectValue object, String name) {
        return object.entries().stream().filter(entry -> entry.name().equals(name))
                .map(Entry::value).findFirst().orElse(null);
    }

    private static TextRange range(String text, int startCharacter, int endCharacter) {
        int byteStart = text.substring(0, startCharacter).getBytes(StandardCharsets.UTF_8).length;
        int byteEnd = text.substring(0, endCharacter).getBytes(StandardCharsets.UTF_8).length;
        int line = 1;
        int column = 1;
        for (int index = 0; index < startCharacter; index++) {
            if (text.charAt(index) == '\n') {
                line++;
                column = 1;
            } else {
                column++;
            }
        }
        return new TextRange(byteStart, byteEnd, line, column);
    }

    private sealed interface JsonValue permits ObjectValue, ArrayValue, StringValue, ScalarValue {}
    private record ObjectValue(int open, List<Entry> entries) implements JsonValue {}
    private record ArrayValue(List<JsonValue> values) implements JsonValue {}
    private record StringValue(String value, int contentStart, int contentEnd) implements JsonValue {}
    private record ScalarValue() implements JsonValue {}
    private record Entry(String name, JsonValue value, int end) {}

    /** A small JSON reader avoids translating character offsets after a second parser has run. */
    private static final class Parser {
        private final String path;
        private final String text;
        private int cursor;

        private Parser(String path, String text) {
            this.path = path;
            this.text = text;
        }

        private ObjectValue parseRoot() {
            skipWhitespace();
            JsonValue value = parseValue();
            skipWhitespace();
            if (cursor != text.length() || !(value instanceof ObjectValue object)) {
                throw error("package.json must contain one JSON object");
            }
            return object;
        }

        private JsonValue parseValue() {
            skipWhitespace();
            if (cursor >= text.length()) {
                throw error("unexpected end of input");
            }
            return switch (text.charAt(cursor)) {
                case '{' -> parseObject();
                case '[' -> parseArray();
                case '"' -> parseString();
                case 't' -> scalar("true");
                case 'f' -> scalar("false");
                case 'n' -> scalar("null");
                default -> parseNumber();
            };
        }

        private ObjectValue parseObject() {
            int open = cursor++;
            skipWhitespace();
            List<Entry> entries = new ArrayList<>();
            Set<String> names = new HashSet<>();
            if (take('}')) {
                return new ObjectValue(open, List.of());
            }
            while (true) {
                skipWhitespace();
                StringValue name = parseString();
                if (!names.add(name.value())) {
                    throw error("duplicate key '" + name.value() + "'");
                }
                skipWhitespace();
                require(':');
                JsonValue value = parseValue();
                entries.add(new Entry(name.value(), value, cursor));
                skipWhitespace();
                if (take('}')) {
                    return new ObjectValue(open, List.copyOf(entries));
                }
                require(',');
            }
        }

        private ArrayValue parseArray() {
            cursor++;
            skipWhitespace();
            List<JsonValue> values = new ArrayList<>();
            if (take(']')) {
                return new ArrayValue(List.of());
            }
            while (true) {
                values.add(parseValue());
                skipWhitespace();
                if (take(']')) {
                    return new ArrayValue(List.copyOf(values));
                }
                require(',');
            }
        }

        private StringValue parseString() {
            require('"');
            int contentStart = cursor;
            StringBuilder decoded = new StringBuilder();
            while (cursor < text.length()) {
                char value = text.charAt(cursor++);
                if (value == '"') {
                    return new StringValue(decoded.toString(), contentStart, cursor - 1);
                }
                if (value < 0x20) {
                    throw error("unescaped control character in string");
                }
                if (value != '\\') {
                    decoded.append(value);
                    continue;
                }
                if (cursor >= text.length()) {
                    throw error("unfinished escape sequence");
                }
                char escape = text.charAt(cursor++);
                switch (escape) {
                    case '"', '\\', '/' -> decoded.append(escape);
                    case 'b' -> decoded.append('\b');
                    case 'f' -> decoded.append('\f');
                    case 'n' -> decoded.append('\n');
                    case 'r' -> decoded.append('\r');
                    case 't' -> decoded.append('\t');
                    case 'u' -> decoded.append(readUnicode());
                    default -> throw error("invalid escape sequence");
                }
            }
            throw error("unterminated string");
        }

        private char readUnicode() {
            if (cursor + 4 > text.length()) {
                throw error("unfinished unicode escape");
            }
            try {
                char value = (char) Integer.parseInt(text.substring(cursor, cursor + 4), 16);
                cursor += 4;
                return value;
            } catch (NumberFormatException exception) {
                throw error("invalid unicode escape");
            }
        }

        private ScalarValue parseNumber() {
            int start = cursor;
            if (take('-') && cursor >= text.length()) {
                throw error("unfinished number");
            }
            if (take('0')) {
                if (cursor < text.length() && Character.isDigit(text.charAt(cursor))) {
                    throw error("leading zero in number");
                }
            } else {
                digits();
            }
            if (take('.')) {
                digits();
            }
            if (cursor < text.length() && (text.charAt(cursor) == 'e' || text.charAt(cursor) == 'E')) {
                cursor++;
                if (cursor < text.length() && (text.charAt(cursor) == '+' || text.charAt(cursor) == '-')) {
                    cursor++;
                }
                digits();
            }
            if (cursor == start) {
                throw error("unexpected token");
            }
            return new ScalarValue();
        }

        private void digits() {
            int start = cursor;
            while (cursor < text.length() && Character.isDigit(text.charAt(cursor))) {
                cursor++;
            }
            if (cursor == start) {
                throw error("expected a digit");
            }
        }

        private ScalarValue scalar(String expected) {
            if (!text.startsWith(expected, cursor)) {
                throw error("unexpected token");
            }
            cursor += expected.length();
            return new ScalarValue();
        }

        private boolean take(char expected) {
            if (cursor < text.length() && text.charAt(cursor) == expected) {
                cursor++;
                return true;
            }
            return false;
        }

        private void require(char expected) {
            if (!take(expected)) {
                throw error("expected '" + expected + "'");
            }
        }

        private void skipWhitespace() {
            while (cursor < text.length() && switch (text.charAt(cursor)) {
                case ' ', '\t', '\r', '\n' -> true;
                default -> false;
            }) {
                cursor++;
            }
        }

        private IllegalArgumentException error(String message) {
            return new IllegalArgumentException("Cannot read " + path + " at character "
                    + cursor + ": " + message);
        }
    }
}
