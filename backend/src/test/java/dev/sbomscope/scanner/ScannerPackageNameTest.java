package dev.sbomscope.scanner;

import java.util.UUID;

import org.junit.jupiter.api.Test;

import dev.sbomscope.sbom.DependencyScope;
import dev.sbomscope.sbom.StoredComponent;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tying a scanner's package name back to a stored component.
 *
 * <p>The report identifies packages by ecosystem, name and version and carries no purl, so
 * this lookup is the only thing connecting a finding to the component it belongs to. When it
 * misses, the finding is discarded — which is how a real advisory against
 * {@code @angular/common} went unreported with nothing but a log line to show for it.
 *
 * <p>Scoped npm packages are the hard case: generators disagree about whether the scope is
 * part of the name or a separate group, and only one of those spellings survives
 * {@code coordinates()} intact.
 */
class ScannerPackageNameTest {

    private StoredComponent component(String group, String name, String version) {
        return new StoredComponent(
                UUID.randomUUID(), "ref", group, name, version,
                "pkg:npm/whatever@" + version, "library", false, DependencyScope.DIRECT);
    }

    @Test
    void matchesAScopedPackageWhoseScopeIsASeparateGroup() {
        // coordinates() renders this as "@angular:common", using Maven's separator, while
        // osv-scanner always says "@angular/common".
        StoredComponent split = component("@angular", "common", "19.2.17");

        assertThat(ScanService.scannerNamesFor(split, "npm"))
                .contains("@angular/common", "@angular:common");
    }

    @Test
    void matchesAScopedPackageWhoseScopeIsPartOfTheName() {
        // What `npm sbom` emits: the full scoped name, with the group left empty.
        StoredComponent joined = component("", "@angular/common", "19.2.17");

        assertThat(ScanService.scannerNamesFor(joined, "npm")).contains("@angular/common");
    }

    @Test
    void bothSpellingsResolveToTheSameName() {
        // Whichever generator produced the document, the scanner's name is covered.
        assertThat(ScanService.scannerNamesFor(component("@angular", "common", "19.2.17"), "npm"))
                .containsAnyElementsOf(
                        ScanService.scannerNamesFor(component("", "@angular/common", "19.2.17"), "npm"));
    }

    @Test
    void keepsMavenCoordinatesUnchanged() {
        // Maven really does use group:artifact, and the slash form must not leak into it.
        StoredComponent maven = component("com.fasterxml.jackson.core", "jackson-databind", "2.18.0");

        assertThat(ScanService.scannerNamesFor(maven, "Maven"))
                .contains("com.fasterxml.jackson.core:jackson-databind")
                .doesNotContain("com.fasterxml.jackson.core/jackson-databind");
    }

    @Test
    void alwaysOffersTheBareName() {
        // An unscoped package, and the fallback for any generator that reports only the name.
        assertThat(ScanService.scannerNamesFor(component("", "left-pad", "1.0.0"), "npm"))
                .contains("left-pad");
    }
}
