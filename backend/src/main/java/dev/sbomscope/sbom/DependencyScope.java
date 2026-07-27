package dev.sbomscope.sbom;

/**
 * Where a component sits relative to the code being described.
 *
 * <p>Three values rather than a direct/transitive boolean, because that boolean could only
 * express "depended on by the root". In an aggregate Maven build the root is the parent pom
 * and the things it depends on are the project's own modules — so every genuinely declared
 * dependency was reported as transitive, and the only components reported as direct were
 * ones the user cannot upgrade because they wrote them.
 *
 * <p>The distinction that matters when triaging a finding is whether you can act on it
 * directly: change a version in your own manifest ({@link #DIRECT}), chase whoever pulled it
 * in ({@link #TRANSITIVE}), or fix the code yourself ({@link #APPLICATION}).
 */
public enum DependencyScope {

    /** Your own code: the root component, and the sibling modules of a multi-module build. */
    APPLICATION,

    /** Declared by your own code — what is written in pom.xml or package.json. */
    DIRECT,

    /** Pulled in by something else. */
    TRANSITIVE;

    public static DependencyScope parse(String value) {
        if (value == null || value.isBlank()) {
            return TRANSITIVE;
        }
        try {
            return valueOf(value.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            // A value written by a build this one does not know about. Reporting it as
            // transitive understates nothing: it is the weakest claim of the three.
            return TRANSITIVE;
        }
    }
}
