package dev.sbomscope.export;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class RegistryLinksTest {

    @Test
    void linksMavenCoordinatesToMavenCentral() {
        RegistryLinks.Links links =
                RegistryLinks.forPurl("pkg:maven/tools.jackson.core/jackson-databind@3.1.4?type=jar");

        assertThat(links.artifactUrl())
                .isEqualTo("https://central.sonatype.com/artifact/tools.jackson.core/jackson-databind");
        assertThat(links.versionUrl())
                .isEqualTo("https://central.sonatype.com/artifact/tools.jackson.core/jackson-databind/3.1.4");
    }

    @Test
    void linksNpmPackagesToNpmjs() {
        RegistryLinks.Links links = RegistryLinks.forPurl("pkg:npm/react@19.2.8");

        assertThat(links.artifactUrl()).isEqualTo("https://www.npmjs.com/package/react");
        assertThat(links.versionUrl()).isEqualTo("https://www.npmjs.com/package/react/v/19.2.8");
    }

    @Test
    void decodesNpmScopes() {
        // Scoped packages are percent-encoded in a purl but not in an npmjs.com URL.
        assertThat(RegistryLinks.forPurl("pkg:npm/%40types/react@19.2.17").versionUrl())
                .isEqualTo("https://www.npmjs.com/package/@types/react/v/19.2.17");
    }

    @Test
    void hasNoVersionLinkWhenThePurlCarriesNoVersion() {
        RegistryLinks.Links links = RegistryLinks.forPurl("pkg:maven/com.example/lib");

        assertThat(links.artifactUrl()).isEqualTo("https://central.sonatype.com/artifact/com.example/lib");
        assertThat(links.versionUrl()).isNull();
    }

    @Test
    void returnsNoLinksForEcosystemsWeCannotLink() {
        assertThat(RegistryLinks.forPurl("pkg:golang/github.com/example/mod@v1.0.0"))
                .isEqualTo(RegistryLinks.Links.NONE);
        assertThat(RegistryLinks.forPurl("not-a-purl")).isEqualTo(RegistryLinks.Links.NONE);
        assertThat(RegistryLinks.forPurl(null)).isEqualTo(RegistryLinks.Links.NONE);
    }

    // --- repository_url ----------------------------------------------------------------

    @Test
    void followsTheRepositoryUrlQualifierToAPublicVendorRepository() {
        // The a.b.c.d case this item exists for: Red Hat's rebuild has no page on Central,
        // and the purl says so itself rather than leaving it to be guessed.
        RegistryLinks.Links links = RegistryLinks.forPurl(
                "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.12.7.redhat-00001"
                        + "?type=jar&repository_url=https://maven.repository.redhat.com/ga/");

        assertThat(links.artifactUrl()).isEqualTo(
                "https://maven.repository.redhat.com/ga/com/fasterxml/jackson/core/jackson-databind/");
        assertThat(links.versionUrl()).isEqualTo(
                "https://maven.repository.redhat.com/ga/com/fasterxml/jackson/core/jackson-databind/"
                        + "2.12.7.redhat-00001/");
    }

    @Test
    void offersNoLinkAtAllForAPrivateRepository() {
        // The downstream-reader objection recorded in RegistryLinks: a link into somebody's
        // Artifactory is useless to whoever reads the spreadsheet, and Central would be a
        // confident 404. Neither is offered.
        assertThat(RegistryLinks.forPurl(
                "pkg:maven/com.acme/internal-billing@1.2.3.acme-4"
                        + "?repository_url=https://artifactory.acme.internal/libs-release"))
                .isEqualTo(RegistryLinks.Links.NONE);
    }

    @Test
    void treatsARepositoryUrlNamingCentralAsCentral() {
        assertThat(RegistryLinks.forPurl(
                "pkg:maven/com.example/lib@1.0.0?repository_url=https://repo1.maven.org/maven2")
                .versionUrl())
                .isEqualTo("https://central.sonatype.com/artifact/com.example/lib/1.0.0");
    }

    @Test
    void matchesTheHostRatherThanTheStringSoALookalikeUrlIsNotTrusted() {
        // https://evil.example/maven.repository.redhat.com/ contains an allowlisted name and
        // is not that host. Parsed, not substring-matched.
        assertThat(RegistryLinks.forPurl(
                "pkg:maven/com.example/lib@1.0.0"
                        + "?repository_url=https://evil.example/maven.repository.redhat.com/"))
                .isEqualTo(RegistryLinks.Links.NONE);
    }

    @Test
    void acceptsARepositoryUrlWithNoSchemeAndNeverLinksOverPlainHttp() {
        // The purl spec allows a bare host, and every allowlisted host serves https.
        assertThat(RegistryLinks.forPurl(
                "pkg:maven/org.example/lib@1.0.0?repository_url=maven.repository.redhat.com/ga")
                .artifactUrl())
                .isEqualTo("https://maven.repository.redhat.com/ga/org/example/lib/");

        assertThat(RegistryLinks.forPurl(
                "pkg:maven/org.example/lib@1.0.0?repository_url=http://maven.repository.redhat.com/ga/")
                .artifactUrl())
                .startsWith("https://");
    }

    @Test
    void ignoresAnUnrelatedQualifierBesideTheRepositoryUrl() {
        assertThat(RegistryLinks.forPurl(
                "pkg:maven/com.example/lib@1.0.0?classifier=sources&type=jar").versionUrl())
                .isEqualTo("https://central.sonatype.com/artifact/com.example/lib/1.0.0");
    }

    @Test
    void offersNoLinkForAPrivateNpmRegistry() {
        assertThat(RegistryLinks.forPurl(
                "pkg:npm/internal-widget@1.0.0?repository_url=https://npm.acme.internal/"))
                .isEqualTo(RegistryLinks.Links.NONE);
        assertThat(RegistryLinks.forPurl(
                "pkg:npm/react@19.2.8?repository_url=https://registry.npmjs.org").versionUrl())
                .isEqualTo("https://www.npmjs.com/package/react/v/19.2.8");
    }
}
