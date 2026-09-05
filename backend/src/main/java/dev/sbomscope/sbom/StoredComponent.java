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
        String mavenType,
        String mavenClassifier,
        boolean root,
        DependencyScope scope) {

    /** Kept for hand-built components that do not carry parsed Maven qualifiers. */
    public StoredComponent(UUID id, String bomRef, String group, String name, String version,
                           String purl, String type, boolean root, DependencyScope scope) {
        this(id, bomRef, group, name, version, purl, type, null, null, root, scope);
    }

    /**
     * {@code group:name} — the component's <b>matching</b> identity, and deliberately not its
     * display form.
     *
     * <p><b>This must never carry the Maven type or classifier.</b> It is what
     * {@code ScanService.scannerNamesFor} registers a component under, and osv-scanner reports
     * packages by group and artifact alone; a name of {@code g:a:sources} matches nothing the
     * scanner ever emits, so the component silently comes back clean. It also reaches
     * {@code MavenArtifact.fromCoordinates} through {@link GraphNode}, where an extra segment
     * would make the Maven probe resolve an artifact that does not exist.
     *
     * <p>B25 extended this method to the display form and both consequences followed
     * immediately: the classifier artifact stopped matching its advisory altogether, which is
     * worse than the collision B25 exists to fix. Use {@link #displayCoordinates()} for
     * anything a reader looks at. The plan states the same boundary in words — type and
     * classifier are identity and presentation, never inputs to matching.
     */
    public String coordinates() {
        return group == null || group.isBlank() ? name : group + ":" + name;
    }

    /**
     * What a reader is shown: {@link #coordinates()} plus the Maven parts that are not the
     * default. Never passed to a matcher, a scanner or the probe.
     */
    public String displayCoordinates() {
        return coordinatesOf(group, name, mavenType, mavenClassifier);
    }

    /** The one display rule used by stored components and finding rows. */
    public static String coordinatesOf(
            String group, String name, String mavenType, String mavenClassifier) {

        if (group == null || group.isBlank()) {
            return name;
        }

        StringBuilder coordinates = new StringBuilder(group).append(':').append(name);
        if (mavenType != null && !mavenType.isBlank() && !"jar".equalsIgnoreCase(mavenType)) {
            coordinates.append(':').append(mavenType);
        }
        if (mavenClassifier != null && !mavenClassifier.isBlank()) {
            coordinates.append(':').append(mavenClassifier);
        }
        return coordinates.toString();
    }
}
