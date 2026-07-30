package dev.sbomscope.probe;

/**
 * A Maven coordinate without a version — what the probe resolves a version <em>for</em>.
 */
public record MavenArtifact(String groupId, String artifactId) {

    /**
     * @param coordinates {@code group:artifact}, exactly the shape
     *                    {@link dev.sbomscope.sbom.StoredComponent#coordinates()} produces for
     *                    a Maven component. Maven coordinates never contain a colon
     *                    themselves, so splitting on the first one is exact, not a heuristic.
     */
    public static MavenArtifact fromCoordinates(String coordinates) {
        int colon = coordinates.indexOf(':');
        if (colon < 0) {
            throw new IllegalArgumentException("Not a group:artifact coordinate: " + coordinates);
        }
        return new MavenArtifact(coordinates.substring(0, colon), coordinates.substring(colon + 1));
    }

    public String gav(String version) {
        return "%s:%s:%s".formatted(groupId, artifactId, version);
    }
}
