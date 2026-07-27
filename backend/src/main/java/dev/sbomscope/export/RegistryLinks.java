package dev.sbomscope.export;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/**
 * Builds public registry links for a component.
 *
 * <p>Deliberately public rather than configurable to an internal mirror: an exported
 * spreadsheet is usually read by someone other than the person who produced it, often
 * outside the network it was produced on, and a link into a private Artifactory is
 * useless to them.
 */
public final class RegistryLinks {

    private RegistryLinks() {}

    /**
     * @param purl package URL, e.g. {@code pkg:maven/com.example/lib@1.2.3?type=jar}
     * @return a link to the public registry page, or null when the ecosystem is unknown
     */
    public static String forPurl(String purl) {
        if (purl == null || !purl.startsWith("pkg:")) {
            return null;
        }

        String withoutScheme = purl.substring("pkg:".length());
        int firstSlash = withoutScheme.indexOf('/');
        if (firstSlash < 0) {
            return null;
        }

        String type = withoutScheme.substring(0, firstSlash).toLowerCase();
        String remainder = stripQualifiers(withoutScheme.substring(firstSlash + 1));

        int at = remainder.lastIndexOf('@');
        String path = at > 0 ? remainder.substring(0, at) : remainder;
        String version = at > 0 ? decode(remainder.substring(at + 1)) : null;

        return switch (type) {
            case "maven" -> mavenCentral(path, version);
            case "npm" -> npm(path, version);
            default -> null;
        };
    }

    private static String mavenCentral(String path, String version) {
        int slash = path.indexOf('/');
        if (slash < 0) {
            return null;
        }
        String group = decode(path.substring(0, slash));
        String artifact = decode(path.substring(slash + 1));

        String base = "https://central.sonatype.com/artifact/%s/%s".formatted(encode(group), encode(artifact));
        return version == null ? base : base + "/" + encode(version);
    }

    private static String npm(String path, String version) {
        // Scoped packages arrive percent-encoded as %40scope/name; npmjs.com wants the
        // decoded @scope/name form in the URL path.
        String name = decode(path);
        String base = "https://www.npmjs.com/package/" + name;
        return version == null ? base : base + "/v/" + encode(version);
    }

    private static String stripQualifiers(String value) {
        int question = value.indexOf('?');
        String withoutQuery = question >= 0 ? value.substring(0, question) : value;
        int hash = withoutQuery.indexOf('#');
        return hash >= 0 ? withoutQuery.substring(0, hash) : withoutQuery;
    }

    private static String decode(String value) {
        return java.net.URLDecoder.decode(value, StandardCharsets.UTF_8);
    }

    private static String encode(String value) {
        // Path segments, so spaces must not become '+'.
        return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }
}
