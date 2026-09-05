package dev.sbomscope.sbom;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

/** Reads the Maven qualifiers SBOMscope stores from a package URL. */
final class PurlQualifierParser {

    private static final MavenQualifiers NONE = new MavenQualifiers(null, null);

    private PurlQualifierParser() {}

    static MavenQualifiers mavenQualifiers(String purl) {
        if (purl == null || !purl.regionMatches(true, 0, "pkg:maven/", 0, "pkg:maven/".length())) {
            return NONE;
        }

        int queryStart = purl.indexOf('?');
        if (queryStart < 0) {
            return NONE;
        }
        int fragmentStart = purl.indexOf('#', queryStart + 1);
        String query = purl.substring(queryStart + 1, fragmentStart < 0 ? purl.length() : fragmentStart);

        String type = null;
        String classifier = null;
        for (String qualifier : query.split("&", -1)) {
            int separator = qualifier.indexOf('=');
            if (separator < 0) {
                continue;
            }
            String key = decode(qualifier.substring(0, separator));
            String value = decode(qualifier.substring(separator + 1));
            if ("type".equalsIgnoreCase(key)) {
                type = value;
            } else if ("classifier".equalsIgnoreCase(key)) {
                classifier = value;
            }
        }
        return new MavenQualifiers(type, classifier);
    }

    private static String decode(String value) {
        try {
            return URLDecoder.decode(value, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException malformedEscape) {
            // A malformed qualifier must not make an otherwise usable SBOM impossible to
            // import. Keeping the source spelling is more honest than silently dropping it.
            return value;
        }
    }

    record MavenQualifiers(String type, String classifier) {}
}
