package dev.sbomscope.bump;

/**
 * @param ecosystem      which manifest this site lives in. MAVEN for a pom, NPM for a package.json
 * @param versionLiteral the declaration exactly as written, including any npm range operator
 *                       ("^4.17.20", "~1.2.3", "4.17.20"). For MAVEN this equals currentVersion
 *                       and carries no operator. This is what {@code versionRange} covers in the
 *                       file — the whole literal, quotes excluded
 * @param rangeAdmitsFix true only for NPM, and only when the declared range already permits the
 *                       minimal fix version. Such a row needs no manifest edit at all: what is
 *                       vulnerable is the lockfile's pin
 */
public record DeclarationSite(
        String id, String file, String module, SiteKind kind,
        String groupId, String artifactId, String type, String classifier,
        String currentVersion, String propertyName,
        java.util.List<String> sharedWith, java.util.List<String> exclusions,
        TextRange versionRange, TextRange insertionPoint,
        Ecosystem ecosystem, String versionLiteral, boolean rangeAdmitsFix) {}
