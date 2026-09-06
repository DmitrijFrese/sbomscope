package dev.sbomscope.bump;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PomScannerTest {

    private final PomScanner scanner = new PomScanner();

    @Test
    void separatesDeclarationsAndPinsUtf8ByteRanges() throws IOException {
        String text = resource("module-a.pom.txt");

        PomScanner.PomScan scan = scanner.scan("module-a/pom.xml", text);

        assertThat(scan.moduleArtifactId()).isEqualTo("module-a");
        assertThat(scan.dependencies()).hasSize(4);
        PomScanner.RawDependency direct = scan.dependencies().getFirst();
        assertThat(direct.versionLiteral()).isEqualTo("1.2.3");
        assertThat(direct.exclusions()).containsExactly("old:unused");
        assertThat(slice(text, direct.versionRange())).isEqualTo("1.2.3");
        assertThat(direct.versionRange().start())
                .isEqualTo(text.substring(0, text.indexOf("1.2.3"))
                        .getBytes(StandardCharsets.UTF_8).length);
    }

    @Test
    void readsManagedPropertiesModulesAndInsertionPoint() throws IOException {
        String text = resource("root.pom.txt");

        PomScanner.PomScan scan = scanner.scan("pom.xml", text);

        assertThat(scan.managed()).hasSize(5);
        assertThat(scan.managed().getLast().bomImport()).isTrue();
        assertThat(scan.properties().get("shared.version").value()).isEqualTo("2.0.0");
        assertThat(scan.modules()).containsExactly("module-a", "module-b");
        assertThat(scan.managementInsertionPoint().start())
                .isEqualTo(scan.managementInsertionPoint().end());
        assertThat(new String(text.getBytes(StandardCharsets.UTF_8), 0,
                scan.managementInsertionPoint().start(), StandardCharsets.UTF_8))
                .endsWith("    ");
    }

    private String resource(String name) throws IOException {
        try (var stream = getClass().getResourceAsStream("/bump/" + name)) {
            return new String(stream.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private String slice(String text, TextRange range) {
        byte[] bytes = text.getBytes(StandardCharsets.UTF_8);
        return new String(bytes, range.start(), range.end() - range.start(), StandardCharsets.UTF_8);
    }
    /**
     * `--` inside an XML comment is forbidden by the spec, and Maven rejects such a pom outright
     * with "Non-parseable POM". Refusing it is therefore correct rather than strict — but the
     * message has to say so, because the parser's own wording is low-level and is localised by
     * the JVM, so a reader can be handed a German sentence about character sequences and conclude
     * the bump screen is broken.
     */
    @Test
    void explainsThatAnInvalidPomIsNotOursToFix() {
        String text = "<project>\n  <!-- a comment with --omit dev in it -->\n</project>\n";

        assertThatThrownBy(() -> scanner.scan("pom.xml", text))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("pom.xml")
                .hasMessageContaining("not valid XML")
                .hasMessageContaining("Maven cannot build it");
    }
}
