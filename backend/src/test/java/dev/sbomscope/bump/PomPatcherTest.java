package dev.sbomscope.bump;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.List;

import org.junit.jupiter.api.Test;

import dev.sbomscope.bump.PomPatcher.PlannedEdit;
import tools.jackson.databind.ObjectMapper;

class PomPatcherTest {

    private final PomPatcher patcher = new PomPatcher();

    @Test
    void replacesOnlyTheVersionBytes() {
        String text = "<project>\n  <!-- keep this comment -->\n  <version>1.0</version>\n</project>\n";
        DeclarationSite site = replacementSite("pom.xml", "direct", text, "1.0");

        PreviewFile preview = patcher.patch(file("pom.xml", text),
                List.of(new PlannedEdit(site, "2.0", false)));

        assertThat(preview.patched()).isEqualTo(
                "<project>\n  <!-- keep this comment -->\n  <version>2.0</version>\n</project>\n");
        assertThat(preview.editCount()).isEqualTo(1);
        assertThat(preview.fingerprint()).isEqualTo(fingerprint(text));
    }

    @Test
    void preservesCrLfDuringInsertion() {
        String text = "<project>\r\n  <dependencyManagement>\r\n    <dependencies>\r\n"
                + "    </dependencies>\r\n  </dependencyManagement>\r\n</project>\r\n";
        int insertion = byteOffset(text, "</dependencies>");
        DeclarationSite site = structuralSite("pom.xml", "bom", text, insertion, "org.example", "library",
                "jar", "");

        PreviewFile preview = patcher.patch(file("pom.xml", text),
                List.of(new PlannedEdit(site, "2.1", true)));

        assertThat(preview.patched()).contains("      <dependency>\r\n")
                .contains("        <version>2.1</version>\r\n");
        assertThat(preview.patched().replace("\r\n", "")).doesNotContain("\n");
    }

    @Test
    void honoursUtf8ByteOffsetsBeforeTheVersion() {
        String text = "<project>\n  <!-- café -->\n  <version>1.0</version>\n</project>\n";
        DeclarationSite site = replacementSite("pom.xml", "unicode", text, "1.0");

        PreviewFile preview = patcher.patch(file("pom.xml", text),
                List.of(new PlannedEdit(site, "2.0", false)));

        assertThat(preview.patched()).contains("<!-- café -->").contains("<version>2.0</version>");
    }

    @Test
    void refusesOverlappingEditsWithBothSiteIds() {
        String text = "<version>1.0</version>";
        DeclarationSite first = replacementSite("pom.xml", "first", text, "1.0");
        DeclarationSite second = replacementSite("pom.xml", "second", text, "1.0");

        assertThatThrownBy(() -> patcher.patch(file("pom.xml", text), List.of(
                new PlannedEdit(first, "2.0", false), new PlannedEdit(second, "3.0", false))))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("first").hasMessageContaining("second").hasMessageContaining("overlap");
    }

    @Test
    void refusesAStaleVersionRange() {
        String text = "<version>1.1</version>";
        int start = byteOffset(text, "1.1");
        DeclarationSite site = new DeclarationSite("stale", "pom.xml", "", SiteKind.DIRECT,
                "org.example", "library", "jar", "", "1.0", null, List.of(), List.of(),
                new TextRange(start, start + utf8Length("1.1"), 1, 1), null,
                Ecosystem.MAVEN, "1.0", false);

        assertThatThrownBy(() -> patcher.patch(file("pom.xml", text),
                List.of(new PlannedEdit(site, "2.0", false))))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("stale");
    }

    @Test
    void insertsWithFourSpaceIndentationAndNonDefaultCoordinateParts() {
        String text = "<project>\n    <dependencyManagement>\n        <dependencies>\n"
                + "        </dependencies>\n    </dependencyManagement>\n</project>\n";
        int insertion = byteOffset(text, "</dependencies>");
        DeclarationSite site = structuralSite("pom.xml", "insert", text, insertion, "org.example", "library",
                "test-jar", "tests");

        PreviewFile preview = patcher.patch(file("pom.xml", text),
                List.of(new PlannedEdit(site, "2.0", true)));

        assertThat(preview.patched()).contains("            <dependency>\n")
                .contains("                <groupId>org.example</groupId>\n")
                .contains("                <type>test-jar</type>\n")
                .contains("                <classifier>tests</classifier>\n")
                .contains("            </dependency>\n        </dependencies>");
    }

    /**
     * Two undeclared transitives share one insertion point, and both are zero-width there, so
     * the overlap guard deliberately lets them through. Worth pinning rather than reasoning
     * about: a workspace with several vulnerable transitives is the ordinary case, and a
     * cursor that mishandled the second would emit malformed XML that only the apply path,
     * writing to a real file, would ever show.
     */
    @Test
    void insertsTwoEntriesAtOneInsertionPoint() {
        String text = "<project>\n    <dependencyManagement>\n        <dependencies>\n"
                + "        </dependencies>\n    </dependencyManagement>\n</project>\n";
        int insertion = byteOffset(text, "</dependencies>");
        DeclarationSite first = structuralSite("pom.xml", "one", text, insertion,
                "org.example", "alpha", "jar", "");
        DeclarationSite second = structuralSite("pom.xml", "two", text, insertion,
                "org.example", "beta", "jar", "");

        PreviewFile preview = patcher.patch(file("pom.xml", text), List.of(
                new PlannedEdit(first, "1.1", true), new PlannedEdit(second, "2.2", true)));

        assertThat(preview.patched()).contains("<artifactId>alpha</artifactId>")
                .contains("<artifactId>beta</artifactId>");
        assertThat(preview.patched().split("<dependency>", -1)).hasSize(3);
        assertThat(preview.editCount()).isEqualTo(2);
        assertThat(preview.changed()).hasSize(2);
        // Both entries must land inside the element, not after its closing tag.
        assertThat(preview.patched().indexOf("<artifactId>beta</artifactId>"))
                .isLessThan(preview.patched().indexOf("</dependencies>"));
    }

    @Test
    void insertsAnNpmEntryIntoExistingOverridesAsValidJson() throws Exception {
        String text = "{\n  \"name\": \"fixture\",\n  \"overrides\": {\n    \"one\": \"1.0.0\"\n  }\n}\n";
        DeclarationSite site = npmStructuralSite("transitive", text);

        PreviewFile preview = patcher.patch(file("package.json", text),
                List.of(new PlannedEdit(site, "2.0.0", true)));

        assertThat(preview.patched()).contains("\"one\": \"1.0.0\",")
                .contains("\"transitive\": \"2.0.0\"");
        assertThat(new ObjectMapper().readTree(preview.patched())).isNotNull();
    }

    @Test
    void createsNpmOverridesAsValidJson() throws Exception {
        String text = "{\n  \"name\": \"fixture\"\n}\n";
        DeclarationSite site = npmStructuralSite("transitive", text);

        PreviewFile preview = patcher.patch(file("package.json", text),
                List.of(new PlannedEdit(site, "2.0.0", true)));

        assertThat(preview.patched()).contains("\"overrides\": {")
                .contains("\"transitive\": \"2.0.0\"");
        assertThat(new ObjectMapper().readTree(preview.patched())).isNotNull();
    }

    @Test
    void createsOneOverridesObjectForTwoNpmEntriesAtOnePoint() throws Exception {
        String text = "{\n  \"name\": \"fixture\"\n}\n";
        DeclarationSite first = npmStructuralSite("alpha", text);
        DeclarationSite second = npmStructuralSite("beta", text);

        PreviewFile preview = patcher.patch(file("package.json", text), List.of(
                new PlannedEdit(first, "1.1.0", true),
                new PlannedEdit(second, "2.2.0", true)));

        assertThat(preview.patched().split("\"overrides\"", -1)).hasSize(2);
        assertThat(preview.patched()).contains("\"alpha\": \"1.1.0\"")
                .contains("\"beta\": \"2.2.0\"");
        assertThat(new ObjectMapper().readTree(preview.patched())).isNotNull();
    }

    @Test
    void reportsChangedRangesInThePatchedUtf8Text() {
        String text = "<project>\n  <!-- café -->\n  <version>1.0</version>\n</project>\n";
        DeclarationSite site = replacementSite("pom.xml", "range", text, "1.0");

        PreviewFile preview = patcher.patch(file("pom.xml", text),
                List.of(new PlannedEdit(site, "2.0.1", false)));

        TextRange changed = preview.changed().getFirst();
        byte[] patched = preview.patched().getBytes(StandardCharsets.UTF_8);
        assertThat(new String(patched, changed.start(), changed.end() - changed.start(),
                StandardCharsets.UTF_8)).isEqualTo("2.0.1");
    }

    private PomFile file(String path, String text) {
        return new PomFile(path, fingerprint(text), true, text);
    }

    private DeclarationSite replacementSite(String path, String id, String text, String current) {
        int start = byteOffset(text, current);
        return new DeclarationSite(id, path, "", SiteKind.DIRECT, "org.example", "library", "jar", "",
                current, null, List.of(), List.of(),
                new TextRange(start, start + utf8Length(current), 1, 1), null,
                Ecosystem.MAVEN, current, false);
    }

    private DeclarationSite structuralSite(String path, String id, String text, int insertion,
                                          String group, String artifact, String type, String classifier) {
        return new DeclarationSite(id, path, "", SiteKind.UNDECLARED, group, artifact, type, classifier,
                "1.0", null, List.of(), List.of(), null,
                new TextRange(insertion, insertion, 1, 1), Ecosystem.MAVEN, "1.0", false);
    }

    private DeclarationSite npmStructuralSite(String artifact, String text) {
        TextRange insertion = new PackageJsonScanner().scan("package.json", text)
                .overridesInsertionPoint();
        return new DeclarationSite("package.json#" + artifact, "package.json", "",
                SiteKind.UNDECLARED, "", artifact, "", "", "1.0.0", null, List.of(),
                List.of(), null, insertion, Ecosystem.NPM, "1.0.0", false);
    }

    private int byteOffset(String text, String value) {
        return utf8Length(text.substring(0, text.indexOf(value)));
    }

    private int utf8Length(String value) {
        return value.getBytes(StandardCharsets.UTF_8).length;
    }

    private String fingerprint(String text) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(text.getBytes(StandardCharsets.UTF_8));
            return java.util.HexFormat.of().formatHex(digest);
        } catch (java.security.NoSuchAlgorithmException exception) {
            throw new AssertionError(exception);
        }
    }
}
