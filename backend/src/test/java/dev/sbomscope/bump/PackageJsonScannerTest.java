package dev.sbomscope.bump;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

import dev.sbomscope.bump.PackageJsonScanner.PackageScan;

class PackageJsonScannerTest {

    private final PackageJsonScanner scanner = new PackageJsonScanner();

    @Test
    void readsAllThreeSupportedDependencySections() throws IOException {
        PackageScan scan = scanner.scan("package.json", fixture());

        assertThat(scan.dependencies()).extracting(dependency -> dependency.section())
                .contains("dependencies", "devDependencies");
        PackageScan child = scanner.scan("packages/child/package.json", childFixture());
        assertThat(child.dependencies()).extracting(dependency -> dependency.section())
                .containsExactly("optionalDependencies");
    }

    @Test
    void keepsScopedPackageAsOneDependencyName() throws IOException {
        PackageScan scan = scanner.scan("package.json", fixture());

        assertThat(scan.dependencies()).extracting(dependency -> dependency.name())
                .contains("@scope/name");
    }

    @Test
    void reportsUtf8ByteOffsetsAfterNonAsciiText() throws IOException {
        String text = fixture();
        var dependency = scanner.scan("package.json", text).dependencies().stream()
                .filter(value -> value.name().equals("lodash")).findFirst().orElseThrow();
        byte[] bytes = text.getBytes(StandardCharsets.UTF_8);

        assertThat(new String(bytes, dependency.literalRange().start(),
                dependency.literalRange().end() - dependency.literalRange().start(),
                StandardCharsets.UTF_8)).isEqualTo("^4.17.20");
        assertThat(dependency.literalRange().start())
                .isGreaterThan(text.indexOf("^4.17.20"));
    }

    @Test
    void excludesTheJsonQuotesFromTheLiteralRange() throws IOException {
        var dependency = scanner.scan("package.json", fixture()).dependencies().getFirst();

        assertThat(dependency.versionLiteral()).isEqualTo("^4.17.20");
        assertThat(dependency.literalRange().end() - dependency.literalRange().start())
                .isEqualTo("^4.17.20".length());
    }

    @Test
    void reportsAnInsertionPointInsideExistingOverrides() {
        String text = "{\n  \"overrides\": {\n    \"one\": \"1.0.0\"\n  }\n}";

        TextRange insertion = scanner.scan("package.json", text).overridesInsertionPoint();

        assertThat(insertion.start()).isEqualTo(insertion.end());
        assertThat(new String(text.getBytes(StandardCharsets.UTF_8), 0, insertion.start(),
                StandardCharsets.UTF_8)).endsWith("\"1.0.0\"");
    }

    @Test
    void reportsWhereANewTopLevelOverridesObjectBelongs() {
        String text = "{\n  \"name\": \"fixture\"\n}";

        TextRange insertion = scanner.scan("package.json", text).overridesInsertionPoint();

        assertThat(insertion.start()).isEqualTo(insertion.end());
        assertThat(new String(text.getBytes(StandardCharsets.UTF_8), 0, insertion.start(),
                StandardCharsets.UTF_8)).endsWith("\"fixture\"");
    }

    @Test
    void refusesDuplicateKeys() {
        assertThatThrownBy(() -> scanner.scan("package.json",
                "{\"dependencies\":{\"one\":\"1.0.0\",\"one\":\"2.0.0\"}}"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("duplicate key 'one'");
    }

    private String fixture() throws IOException {
        return resource("npm-root.package.txt");
    }

    private String childFixture() throws IOException {
        return resource("npm-child.package.txt");
    }

    private String resource(String name) throws IOException {
        try (var stream = getClass().getResourceAsStream("/bump/" + name)) {
            return new String(stream.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
