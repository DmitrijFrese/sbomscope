package dev.sbomscope.sbom;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Wire-format mapping for the subset of CycloneDX JSON that SBOMscope reads.
 *
 * <p>Only components and the dependency graph are modelled. Everything else in the
 * specification — licences, services, signatures, tool metadata — is ignored rather
 * than mapped, which is what lets the same code read every spec version from 1.2
 * onwards without change.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
record CycloneDxDocument(
        String bomFormat,
        String specVersion,
        Metadata metadata,
        List<Component> components,
        List<Dependency> dependencies) {

    @JsonIgnoreProperties(ignoreUnknown = true)
    record Metadata(Component component) {}

    @JsonIgnoreProperties(ignoreUnknown = true)
    record Component(
            @JsonProperty("bom-ref") String bomRef,
            String type,
            String group,
            String name,
            String version,
            String purl,
            /* Components may nest arbitrarily; the parser flattens them. */
            List<Component> components) {}

    @JsonIgnoreProperties(ignoreUnknown = true)
    record Dependency(String ref, List<String> dependsOn) {}
}
