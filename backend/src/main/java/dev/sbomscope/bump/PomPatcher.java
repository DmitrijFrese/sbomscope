package dev.sbomscope.bump;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Applies the narrow source edits a preview needs without reserializing a pom. */
public class PomPatcher {

    /**
     * Patches one pom. Ranges are UTF-8 byte offsets, just as {@link PomScanner} reports them.
     */
    public PreviewFile patch(PomFile file, List<PlannedEdit> edits) {
        byte[] original = file.text().getBytes(StandardCharsets.UTF_8);
        List<ResolvedEdit> resolved = resolve(edits, original);
        rejectOverlaps(resolved);

        List<ResolvedEdit> ordered = resolved.stream().sorted(Comparator
                .comparingInt(ResolvedEdit::start)
                .thenComparing(edit -> edit.site().id()))
                .toList();
        ByteArrayOutputStream patched = new ByteArrayOutputStream(original.length);
        List<ChangedBytes> changed = new ArrayList<>();
        int cursor = 0;
        for (ResolvedEdit edit : ordered) {
            patched.writeBytes(slice(original, cursor, edit.start()));
            int changedStart = patched.size();
            patched.writeBytes(edit.replacement());
            changed.add(new ChangedBytes(changedStart, patched.size()));
            cursor = edit.end();
        }
        patched.writeBytes(slice(original, cursor, original.length));

        byte[] patchedBytes = patched.toByteArray();
        String text = new String(patchedBytes, StandardCharsets.UTF_8);
        return new PreviewFile(file.path(), file.fingerprint(), text,
                changed.stream().map(change -> range(text, patchedBytes, change)).toList(),
                edits.size());
    }

    private List<ResolvedEdit> resolve(List<PlannedEdit> edits, byte[] original) {
        List<ResolvedEdit> resolved = new ArrayList<>();
        Map<Integer, List<PlannedEdit>> npmInsertions = new LinkedHashMap<>();
        for (PlannedEdit edit : edits) {
            if (edit.structural() && edit.site().ecosystem() == Ecosystem.NPM) {
                TextRange point = edit.site().insertionPoint();
                if (point == null || point.start() != point.end()) {
                    throw new IllegalArgumentException("Invalid range for site " + edit.site().id());
                }
                npmInsertions.computeIfAbsent(point.start(), ignored -> new ArrayList<>()).add(edit);
            } else {
                resolved.add(resolve(edit, original));
            }
        }
        String text = new String(original, StandardCharsets.UTF_8);
        for (Map.Entry<Integer, List<PlannedEdit>> insertion : npmInsertions.entrySet()) {
            int position = insertion.getKey();
            if (position < 0 || position > original.length) {
                throw new IllegalArgumentException("Invalid npm overrides insertion point");
            }
            List<PlannedEdit> grouped = insertion.getValue().stream()
                    .sorted(Comparator.comparing(edit -> edit.site().id())).toList();
            resolved.add(new ResolvedEdit(grouped.getFirst().site(), position, position,
                    npmInsertion(grouped, text, position).getBytes(StandardCharsets.UTF_8)));
        }
        return resolved;
    }

    private ResolvedEdit resolve(PlannedEdit edit, byte[] original) {
        DeclarationSite site = edit.site();
        TextRange range = edit.structural() ? site.insertionPoint() : site.versionRange();
        if (range == null || range.start() < 0 || range.end() < range.start()
                || range.end() > original.length) {
            throw new IllegalArgumentException("Invalid range for site " + site.id());
        }
        if (!edit.structural()) {
            String actual = new String(slice(original, range.start(), range.end()),
                    StandardCharsets.UTF_8);
            String expected = site.kind() == SiteKind.NPM_DIRECT
                    ? site.versionLiteral() : site.currentVersion();
            if (!actual.equals(expected)) {
                throw new IllegalArgumentException("Range for site " + site.id()
                        + " no longer contains " + expected);
            }
        } else if (range.start() != range.end()) {
            throw new IllegalArgumentException("Insertion point for site " + site.id()
                    + " is not zero-width");
        }
        byte[] replacement = edit.structural()
                ? insertion(site, edit.newVersion(), new String(original, StandardCharsets.UTF_8))
                : replacement(site, edit.newVersion()).getBytes(StandardCharsets.UTF_8);
        return new ResolvedEdit(site, range.start(), range.end(), replacement);
    }

    private String replacement(DeclarationSite site, String version) {
        return site.kind() == SiteKind.NPM_DIRECT
                ? NpmRange.rewrite(site.versionLiteral(), version) : version;
    }

    private void rejectOverlaps(List<ResolvedEdit> edits) {
        List<ResolvedEdit> ordered = edits.stream().sorted(Comparator
                .comparingInt(ResolvedEdit::start).thenComparingInt(ResolvedEdit::end)).toList();
        for (int index = 1; index < ordered.size(); index++) {
            ResolvedEdit previous = ordered.get(index - 1);
            ResolvedEdit current = ordered.get(index);
            if (current.start() < previous.end() && previous.start() < current.end()) {
                throw new IllegalArgumentException("Edits for sites " + previous.site().id()
                        + " and " + current.site().id() + " overlap");
            }
        }
    }

    private byte[] insertion(DeclarationSite site, String version, String text) {
        String lineEnding = text.contains("\r\n") ? "\r\n" : "\n";
        String unit = indentationUnit(text);
        String base = indentationAt(text, site.insertionPoint().start());
        // The source before the insertion point already holds the closing tag's indentation.
        // Start with only the extra level so that indentation is not duplicated on this line.
        String dependency = unit + "<dependency>" + lineEnding
                + base + unit + unit + "<groupId>" + site.groupId() + "</groupId>" + lineEnding
                + base + unit + unit + "<artifactId>" + site.artifactId() + "</artifactId>" + lineEnding
                + base + unit + unit + "<version>" + version + "</version>" + lineEnding;
        if (site.type() != null && !site.type().isBlank() && !"jar".equals(site.type())) {
            dependency += base + unit + unit + "<type>" + site.type() + "</type>" + lineEnding;
        }
        if (site.classifier() != null && !site.classifier().isBlank()) {
            dependency += base + unit + unit + "<classifier>" + site.classifier()
                    + "</classifier>" + lineEnding;
        }
        return (dependency + base + unit + "</dependency>" + lineEnding + base)
                .getBytes(StandardCharsets.UTF_8);
    }

    private String npmInsertion(List<PlannedEdit> edits, String text, int byteOffset) {
        String lineEnding = text.contains("\r\n") ? "\r\n" : "\n";
        String unit = indentationUnit(text);
        int characterOffset = new String(text.getBytes(StandardCharsets.UTF_8), 0, byteOffset,
                StandardCharsets.UTF_8).length();
        List<Integer> braces = objectBracesAt(text, characterOffset);
        if (braces.isEmpty()) {
            throw new IllegalArgumentException("npm overrides insertion point is outside an object");
        }
        int opening = braces.getLast();
        String base = lineIndentationAt(text, opening);
        boolean existingOverrides = braces.size() > 1;
        boolean objectHasMembers = !text.substring(opening + 1, characterOffset).isBlank();
        String memberIndent = base + unit;
        String entries = edits.stream().map(edit -> memberIndent + jsonString(npmName(edit.site()))
                        + ": " + jsonString(edit.newVersion()))
                .collect(java.util.stream.Collectors.joining("," + lineEnding));
        if (existingOverrides) {
            return (objectHasMembers ? "," : "") + lineEnding + entries + lineEnding + base;
        }
        String overrideIndent = memberIndent;
        String overrideEntries = edits.stream().map(edit -> overrideIndent + unit
                        + jsonString(npmName(edit.site())) + ": " + jsonString(edit.newVersion()))
                .collect(java.util.stream.Collectors.joining("," + lineEnding));
        return (objectHasMembers ? "," : "") + lineEnding + overrideIndent + "\"overrides\": {"
                + lineEnding + overrideEntries + lineEnding + overrideIndent + "}"
                + lineEnding + base;
    }

    private List<Integer> objectBracesAt(String text, int offset) {
        List<Integer> braces = new ArrayList<>();
        boolean string = false;
        boolean escaped = false;
        for (int index = 0; index < offset; index++) {
            char value = text.charAt(index);
            if (string) {
                if (escaped) escaped = false;
                else if (value == '\\') escaped = true;
                else if (value == '"') string = false;
            } else if (value == '"') {
                string = true;
            } else if (value == '{') {
                braces.add(index);
            } else if (value == '}' && !braces.isEmpty()) {
                braces.removeLast();
            }
        }
        return braces;
    }

    private String lineIndentationAt(String text, int offset) {
        int start = Math.max(text.lastIndexOf('\n', Math.max(0, offset - 1)),
                text.lastIndexOf('\r', Math.max(0, offset - 1))) + 1;
        int end = start;
        while (end < text.length() && Character.isWhitespace(text.charAt(end))
                && text.charAt(end) != '\r' && text.charAt(end) != '\n') {
            end++;
        }
        return text.substring(start, end);
    }

    private String npmName(DeclarationSite site) {
        return site.groupId() == null || site.groupId().isBlank()
                ? site.artifactId() : site.groupId() + "/" + site.artifactId();
    }

    private String jsonString(String value) {
        StringBuilder escaped = new StringBuilder("\"");
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            switch (character) {
                case '"' -> escaped.append("\\\"");
                case '\\' -> escaped.append("\\\\");
                case '\b' -> escaped.append("\\b");
                case '\f' -> escaped.append("\\f");
                case '\n' -> escaped.append("\\n");
                case '\r' -> escaped.append("\\r");
                case '\t' -> escaped.append("\\t");
                default -> {
                    if (character < 0x20) escaped.append(String.format("\\u%04x", (int) character));
                    else escaped.append(character);
                }
            }
        }
        return escaped.append('"').toString();
    }

    private String indentationAt(String text, int byteOffset) {
        byte[] bytes = text.getBytes(StandardCharsets.UTF_8);
        String prefix = new String(bytes, 0, byteOffset, StandardCharsets.UTF_8);
        int lineStart = Math.max(prefix.lastIndexOf('\n'), prefix.lastIndexOf('\r')) + 1;
        String whitespace = prefix.substring(lineStart);
        return whitespace.chars().allMatch(Character::isWhitespace) ? whitespace : "";
    }

    private String indentationUnit(String text) {
        Map<String, Integer> counts = new HashMap<>();
        String previous = "";
        for (String line : text.split("\\R", -1)) {
            String indent = line.substring(0, leadingWhitespace(line));
            if (indent.length() > previous.length() && indent.startsWith(previous)) {
                String increment = indent.substring(previous.length());
                counts.merge(increment, 1, Integer::sum);
            }
            if (!line.isBlank()) {
                previous = indent;
            }
        }
        return counts.entrySet().stream().max(Comparator
                .comparingInt(Map.Entry<String, Integer>::getValue)
                .thenComparing(entry -> entry.getKey().length()))
                .map(Map.Entry::getKey).orElse("  ");
    }

    private int leadingWhitespace(String line) {
        int index = 0;
        while (index < line.length() && Character.isWhitespace(line.charAt(index))) {
            index++;
        }
        return index;
    }

    private TextRange range(String text, byte[] bytes, ChangedBytes changed) {
        String before = new String(bytes, 0, changed.start(), StandardCharsets.UTF_8);
        int line = 1;
        int column = 1;
        for (int index = 0; index < before.length(); index++) {
            if (before.charAt(index) == '\n') {
                line++;
                column = 1;
            } else {
                column++;
            }
        }
        return new TextRange(changed.start(), changed.end(), line, column);
    }

    private byte[] slice(byte[] bytes, int start, int end) {
        byte[] result = new byte[end - start];
        System.arraycopy(bytes, start, result, 0, result.length);
        return result;
    }

    public record PlannedEdit(DeclarationSite site, String newVersion, boolean structural) {}

    private record ResolvedEdit(DeclarationSite site, int start, int end, byte[] replacement) {}
    private record ChangedBytes(int start, int end) {}
}
