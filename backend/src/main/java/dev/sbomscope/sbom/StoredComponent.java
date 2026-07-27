package dev.sbomscope.sbom;

import java.util.UUID;

/** A component belonging to a stored SBOM. */
public record StoredComponent(
        UUID id,
        String bomRef,
        String group,
        String name,
        String version,
        String purl,
        String type,
        boolean root,
        DependencyScope scope) {

    /** {@code group:name} for Maven, plain name otherwise — how users refer to it. */
    public String coordinates() {
        return group == null || group.isBlank() ? name : group + ":" + name;
    }
}
