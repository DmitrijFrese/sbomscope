package dev.sbomscope.bump;

import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;

/** Reads the locations and declarations in one pom without resolving anything outside it. */
public class PomScanner {

    public record PomScan(
            String path, String moduleArtifactId, String parentRelativePath,
            List<String> modules, Map<String, PropertyDefinition> properties,
            List<RawDependency> dependencies, List<RawDependency> managed,
            TextRange managementInsertionPoint) {}

    public record PropertyDefinition(String name, String value, TextRange valueRange) {}

    public record RawDependency(
            String groupId, String artifactId, String type, String classifier, String scope,
            String versionLiteral, TextRange versionRange, boolean bomImport,
            List<String> exclusions, int ordinal) {}

    public PomScan scan(String path, String text) {
        XMLInputFactory factory = XMLInputFactory.newFactory();
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        factory.setProperty("javax.xml.stream.isSupportingExternalEntities", false);

        List<String> modules = new ArrayList<>();
        Map<String, PropertyDefinition> properties = new LinkedHashMap<>();
        List<RawDependency> dependencies = new ArrayList<>();
        List<RawDependency> managed = new ArrayList<>();
        Deque<String> elements = new ArrayDeque<>();
        DependencyBuilder dependency = null;
        Capture capture = null;
        String artifactId = "";
        String parentRelativePath = null;
        boolean parentSeen = false;
        TextRange insertionPoint = null;
        int ordinal = 0;

        try {
            XMLStreamReader reader = factory.createXMLStreamReader(new StringReader(text));
            while (reader.hasNext()) {
                int event = reader.next();
                if (event == XMLStreamConstants.START_ELEMENT) {
                    String name = reader.getLocalName();
                    elements.addLast(name);
                    if (isPath(elements, "project", "parent")) {
                        parentSeen = true;
                    }
                    if ("dependency".equals(name) && isDependency(elements)) {
                        dependency = new DependencyBuilder(isManaged(elements), ordinal++);
                    }
                    if (isCapturedValue(elements, dependency)) {
                        capture = new Capture(name, contentStart(reader, text));
                    }
                } else if ((event == XMLStreamConstants.CHARACTERS
                        || event == XMLStreamConstants.CDATA) && capture != null) {
                    capture.value.append(reader.getText());
                } else if (event == XMLStreamConstants.END_ELEMENT) {
                    String name = reader.getLocalName();
                    if (capture != null && capture.name.equals(name)) {
                        String value = capture.value.toString().trim();
                        TextRange range = valueRange(text, capture.contentStart,
                                closeTagStart(reader, text), value);
                        if (dependency != null && isDependencyField(elements, name)) {
                            dependency.accept(name, value, range,
                                    isPath(elements, "dependency", "exclusions", "exclusion", name));
                        } else if (isPath(elements, "project", "artifactId")) {
                            artifactId = value;
                        } else if (isPath(elements, "project", "parent", "relativePath")) {
                            parentRelativePath = value;
                        } else if (isPath(elements, "project", "modules", "module")) {
                            modules.add(value);
                        } else if (isProperty(elements)) {
                            properties.put(name, new PropertyDefinition(name, value, range));
                        }
                        capture = null;
                    }
                    if ("dependency".equals(name) && dependency != null
                            && isDependency(elements)) {
                        RawDependency raw = dependency.build();
                        (dependency.managed ? managed : dependencies).add(raw);
                        dependency = null;
                    }
                    if (isPath(elements, "project", "dependencyManagement", "dependencies")) {
                        insertionPoint = zeroRange(text, closeTagStart(reader, text));
                    } else if (insertionPoint == null
                            && isPath(elements, "project", "dependencyManagement")) {
                        insertionPoint = zeroRange(text, closeTagStart(reader, text));
                    } else if (insertionPoint == null && isPath(elements, "project")) {
                        insertionPoint = zeroRange(text, closeTagStart(reader, text));
                    }
                    elements.removeLast();
                }
            }
            reader.close();
        } catch (XMLStreamException e) {
            // The parser's own message is precise, low-level, and — because StAX localises it —
            // sometimes not even in the reader's language. On its own it reads as a defect in
            // SBOMscope. The sentence in front of it says what actually happened and what it
            // means: the file is not valid XML, so `mvn` will not build it either. That turns
            // "the bump screen is broken" into "this pom needs fixing", which is the truth.
            //
            // The case that prompted this was a literal `--` inside an XML comment, which the
            // spec forbids and Maven rejects with "Non-parseable POM". Being lenient there would
            // mean reading a pom nobody can build.
            throw new IllegalArgumentException(path + " is not valid XML, so Maven cannot build it"
                    + " either — the parser reports: " + e.getMessage(), e);
        }

        String effectiveParentPath = parentSeen && parentRelativePath == null
                ? "../pom.xml" : parentRelativePath;
        return new PomScan(path, artifactId, effectiveParentPath, List.copyOf(modules),
                Map.copyOf(properties), List.copyOf(dependencies), List.copyOf(managed),
                insertionPoint);
    }

    private boolean isCapturedValue(Deque<String> elements, DependencyBuilder dependency) {
        String name = elements.getLast();
        return dependency != null && isDependencyField(elements, name)
                || isPath(elements, "project", "artifactId")
                || isPath(elements, "project", "parent", "relativePath")
                || isPath(elements, "project", "modules", "module")
                || isProperty(elements);
    }

    private boolean isDependencyField(Deque<String> elements, String name) {
        if (isPath(elements, "dependency", name)) {
            return List.of("groupId", "artifactId", "type", "classifier", "scope", "version")
                    .contains(name);
        }
        return isPath(elements, "dependency", "exclusions", "exclusion", name)
                && ("groupId".equals(name) || "artifactId".equals(name));
    }

    private boolean isDependency(Deque<String> elements) {
        return isPath(elements, "project", "dependencies", "dependency")
                || isPath(elements, "project", "dependencyManagement", "dependencies", "dependency");
    }

    private boolean isManaged(Deque<String> elements) {
        return isPath(elements, "project", "dependencyManagement", "dependencies", "dependency");
    }

    private boolean isProperty(Deque<String> elements) {
        return elements.size() == 3 && isPath(elements, "project", "properties", elements.getLast());
    }

    private boolean isPath(Deque<String> elements, String... suffix) {
        if (elements.size() < suffix.length) {
            return false;
        }
        int skip = elements.size() - suffix.length;
        int index = 0;
        for (String element : elements) {
            if (index >= skip && !element.equals(suffix[index - skip])) {
                return false;
            }
            index++;
        }
        return true;
    }

    private int contentStart(XMLStreamReader reader, String text) {
        int offset = reader.getLocation().getCharacterOffset();
        return offset >= 0 ? Math.min(offset, text.length()) : 0;
    }

    private int closeTagStart(XMLStreamReader reader, String text) {
        int offset = reader.getLocation().getCharacterOffset();
        int before = offset < 0 ? text.length() : Math.min(offset, text.length());
        int start = text.lastIndexOf("</", before);
        return Math.max(0, start);
    }

    private TextRange valueRange(String text, int contentStart, int contentEnd, String value) {
        int start = Math.max(0, Math.min(contentStart, contentEnd));
        while (start < contentEnd && Character.isWhitespace(text.charAt(start))) {
            start++;
        }
        int end = Math.max(start, contentEnd);
        while (end > start && Character.isWhitespace(text.charAt(end - 1))) {
            end--;
        }
        // Entity references are unusual in Maven versions. If one occurs, preserve the exact
        // source range while the resolved value still comes from StAX.
        if (value.isEmpty()) {
            end = start;
        }
        return range(text, start, end);
    }

    private TextRange zeroRange(String text, int characterOffset) {
        TextRange at = range(text, characterOffset, characterOffset);
        return new TextRange(at.start(), at.start(), at.line(), at.column());
    }

    private TextRange range(String text, int startCharacter, int endCharacter) {
        int byteStart = text.substring(0, startCharacter).getBytes(StandardCharsets.UTF_8).length;
        int byteEnd = text.substring(0, endCharacter).getBytes(StandardCharsets.UTF_8).length;
        int line = 1;
        int column = 1;
        for (int i = 0; i < startCharacter; i++) {
            if (text.charAt(i) == '\n') {
                line++;
                column = 1;
            } else {
                column++;
            }
        }
        return new TextRange(byteStart, byteEnd, line, column);
    }

    private static final class Capture {
        private final String name;
        private final int contentStart;
        private final StringBuilder value = new StringBuilder();

        private Capture(String name, int contentStart) {
            this.name = name;
            this.contentStart = contentStart;
        }
    }

    private static final class DependencyBuilder {
        private final boolean managed;
        private final int ordinal;
        private String groupId;
        private String artifactId;
        private String type;
        private String classifier;
        private String scope;
        private String version;
        private TextRange versionRange;
        private String exclusionGroup;
        private final List<String> exclusions = new ArrayList<>();

        private DependencyBuilder(boolean managed, int ordinal) {
            this.managed = managed;
            this.ordinal = ordinal;
        }

        private void accept(String name, String value, TextRange range, boolean exclusion) {
            if (exclusion) {
                if ("groupId".equals(name)) {
                    exclusionGroup = value;
                } else if ("artifactId".equals(name) && exclusionGroup != null) {
                    exclusions.add(exclusionGroup + ":" + value);
                    exclusionGroup = null;
                }
                return;
            }
            switch (name) {
                case "groupId" -> groupId = value;
                case "artifactId" -> artifactId = value;
                case "type" -> type = value;
                case "classifier" -> classifier = value;
                case "scope" -> scope = value;
                case "version" -> {
                    version = value;
                    versionRange = range;
                }
                default -> { }
            }
        }

        private RawDependency build() {
            return new RawDependency(groupId, artifactId, type, classifier, scope, version,
                    versionRange, "pom".equals(type) && "import".equals(scope),
                    List.copyOf(exclusions), ordinal);
        }
    }
}
