package dev.sbomscope.probe;

import dev.sbomscope.logging.ActivityLogger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

class MetadataPrimerTest {

    private static final MavenArtifact CRYPTO =
            new MavenArtifact("org.springframework.security", "spring-security-crypto");

    private static ProbeContext contextFor(Path repository, EffectivePomFragments lifted) {
        return new ProbeContext("mvn", repository.toString(), lifted, Duration.ofMinutes(1), null,
                "org.apache.maven.plugins:maven-dependency-plugin:3.6.1:tree");
    }

    private static MetadataPrimer primer() {
        return new MetadataPrimer(new ActivityLogger(new ObjectMapper()));
    }

    // --- the generated POM ----------------------------------------------------------------

    /**
     * The isolation claim in this class rests entirely on there being nothing to resolve. A
     * dependency here would reintroduce exactly the atomic failure the per-coordinate design
     * exists to avoid, so it is asserted rather than trusted to review.
     */
    @Test
    void theGeneratedPomDeclaresNoDependencies() {
        String pom = MetadataPrimer.repositoriesOnlyPom(contextFor(Path.of("target/none"), null));

        assertThat(pom).doesNotContain("<dependency>").doesNotContain("<dependencies>");
        assertThat(pom).contains("<packaging>pom</packaging>");
    }

    /**
     * The one thing the POM is for: a supplier's Nexus is usually declared in the project rather
     * than in settings.xml, and without this splice their artifacts could never be primed.
     */
    @Test
    void theGeneratedPomCarriesTheWorkspaceRepositories() {
        String repositories = "  <repositories>\n"
                + "    <repository><id>acme-nexus</id><url>https://nexus.acme.invalid/repo</url></repository>\n"
                + "  </repositories>";
        String pom = MetadataPrimer.repositoriesOnlyPom(
                contextFor(Path.of("target/none"), new EffectivePomFragments(null, repositories)));

        assertThat(pom).contains("acme-nexus").contains("https://nexus.acme.invalid/repo");
    }

    /** dependencyManagement is deliberately not lifted: nothing is being resolved to manage. */
    @Test
    void theGeneratedPomIgnoresLiftedDependencyManagement() {
        String pom = MetadataPrimer.repositoriesOnlyPom(contextFor(Path.of("target/none"),
                new EffectivePomFragments("  <dependencyManagement>...</dependencyManagement>", null)));

        assertThat(pom).doesNotContain("dependencyManagement");
    }

    @Test
    void aWorkspaceWithNoRepositoriesOfItsOwnStillProducesAValidPom() {
        assertThat(MetadataPrimer.repositoriesOnlyPom(contextFor(Path.of("target/none"), null)))
                .startsWith("<?xml")
                .endsWith("</project>\n");
    }

    // --- recognising what is on disk -------------------------------------------------------

    /**
     * Maven writes maven-metadata-&lt;repository id&gt;.xml, never the bare name, and puts a
     * checksum beside it. Counting the .sha1 would claim coverage this class has not delivered.
     */
    @Test
    void onlyMetadataXmlCounts() {
        assertThat(MetadataPrimer.isMetadataFile("maven-metadata-central.xml")).isTrue();
        assertThat(MetadataPrimer.isMetadataFile("maven-metadata.xml")).isTrue();
        assertThat(MetadataPrimer.isMetadataFile("maven-metadata-acme-nexus.xml")).isTrue();
        assertThat(MetadataPrimer.isMetadataFile("maven-metadata-central.xml.sha1")).isFalse();
        assertThat(MetadataPrimer.isMetadataFile("resolver-status.properties")).isFalse();
        assertThat(MetadataPrimer.isMetadataFile("spring-security-crypto-6.3.8.pom")).isFalse();
    }

    @Test
    void theMetadataDirectoryFollowsMavensGroupIdLayout(@TempDir Path repository) {
        assertThat(MetadataPrimer.metadataDirectory(CRYPTO, contextFor(repository, null)))
                .isEqualTo(repository.resolve("org/springframework/security/spring-security-crypto"));
    }

    @Test
    void anArtifactWithNoDirectoryHasNoMetadata(@TempDir Path repository) {
        assertThat(primer()
                .hasMetadata(CRYPTO, contextFor(repository, null))).isFalse();
    }

    /**
     * The exact shape dependency:get leaves for a concrete version — measured 2026-09-07. It looks
     * like a populated artifact directory and answers nothing about which versions exist, which is
     * the mistake this class was written to correct.
     */
    @Test
    void aVersionDirectoryWithoutMetadataDoesNotCount(@TempDir Path repository) throws IOException {
        Path versionDirectory = MetadataPrimer.metadataDirectory(CRYPTO, contextFor(repository, null))
                .resolve("6.3.8");
        Files.createDirectories(versionDirectory);
        Files.writeString(versionDirectory.resolve("spring-security-crypto-6.3.8.pom"), "<project/>");
        Files.writeString(versionDirectory.resolve("_remote.repositories"), "");

        assertThat(primer()
                .hasMetadata(CRYPTO, contextFor(repository, null))).isFalse();
    }

    @Test
    void metadataAlreadyOnDiskIsRecognised(@TempDir Path repository) throws IOException {
        Path directory = MetadataPrimer.metadataDirectory(CRYPTO, contextFor(repository, null));
        Files.createDirectories(directory);
        Files.writeString(directory.resolve("maven-metadata-central.xml"), "<metadata/>");

        assertThat(primer()
                .hasMetadata(CRYPTO, contextFor(repository, null))).isTrue();
    }

    /**
     * The short circuit that makes priming a whole plan affordable: an artifact already on disk
     * must not spend a five-second Maven run to confirm it. The executable is deliberately one
     * that does not exist, so a run would fail and the result would not be primed.
     */
    @Test
    void anArtifactAlreadyOnDiskIsNotFetchedAgain(@TempDir Path repository) throws IOException {
        Path directory = MetadataPrimer.metadataDirectory(CRYPTO, contextFor(repository, null));
        Files.createDirectories(directory);
        Files.writeString(directory.resolve("maven-metadata-central.xml"), "<metadata/>");
        ProbeContext noMavenAtAll = new ProbeContext("mvn-that-does-not-exist", repository.toString(),
                null, Duration.ofMinutes(1), null,
                "org.apache.maven.plugins:maven-dependency-plugin:3.6.1:tree");

        MetadataPrimer.Result result = primer()
                .prime(CRYPTO, noMavenAtAll);

        assertThat(result.primed()).isTrue();
        assertThat(result.detail()).isNull();
    }

    @Test
    void noArtifactIsNotAQuestion(@TempDir Path repository) {
        MetadataPrimer.Result result = primer()
                .prime(null, contextFor(repository, null));

        assertThat(result.primed()).isFalse();
        assertThat(result.detail()).isNotBlank();
    }
}
