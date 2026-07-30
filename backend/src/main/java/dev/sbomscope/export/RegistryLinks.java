package dev.sbomscope.export;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Builds public registry links for a component.
 *
 * <p><b>Public destinations only, and that is two decisions rather than one.</b> SBOMscope
 * has never offered a setting pointing these at an internal mirror, because an exported
 * spreadsheet is usually read by somebody other than the person who produced it, often
 * outside the network it was produced on, and a link into a private Artifactory is useless
 * to them. That still holds and is not what {@code repository_url} changes: configuring one
 * mirror as the base for <em>everything</em> is a different act from a purl <em>declaring
 * where that particular artifact actually lives</em>. The first substitutes our guess for
 * the reader's; the second is the document telling us Central is the wrong destination for
 * this one component.
 *
 * <p>So the qualifier is honoured, and the downstream-reader objection is preserved by only
 * following it to hosts on {@link #PUBLIC_MAVEN_REPOSITORIES} — publicly readable vendor
 * repositories, needing no credentials. An unrecognised host produces <b>no link at all</b>,
 * which is the better failure: a link to a private host is broken for the reader, and a link
 * to Central for a vendor build is broken for everybody.
 *
 * <p><b>Two destinations per component, split by how reliably they resolve.</b> A vendor
 * patch level ({@code a.b.c.d}) has no page on Central, so a single version-specific link
 * 404s and the reader has nowhere to go. The artifact page resolves whenever the artifact
 * exists at all, so the component name carries that and the version cell carries the
 * version-specific link. Landing on the artifact page you can find your version; landing on
 * a 404 you cannot.
 *
 * <p><b>Validating a link is not available to us.</b> Asking a registry whether a specific
 * artifact resolves is exactly the disclosure constraint 1 puts in category 3 — it names an
 * artifact the user holds. The only move is choosing targets that do not fail.
 */
public final class RegistryLinks {

    /**
     * Both destinations for one component.
     *
     * @param artifactUrl the artifact's own page, version-independent; null when the
     *                    ecosystem or host gives us nothing safe to link to
     * @param versionUrl  the page for this exact version, or null when the purl carries no
     *                    version — never a guess
     */
    public record Links(String artifactUrl, String versionUrl) {

        public static final Links NONE = new Links(null, null);
    }

    /**
     * Hosts whose contents Central's own web UI serves, so a purl naming them is not asking
     * for anything different from the default.
     */
    private static final Set<String> MAVEN_CENTRAL_HOSTS = Set.of(
            "repo1.maven.org", "repo.maven.apache.org", "central.sonatype.com");

    /**
     * Public vendor repositories, linked through the standard Maven layout.
     *
     * <p>Membership is not "is this repository well known" but "does the derived URL actually
     * resolve for a reader with no credentials" — these serve browsable directory listings,
     * which is what makes {@code group/artifact/version/} a usable destination. Red Hat's is
     * first because their rebuilds are precisely the {@code a.b.c.d} artifacts this exists
     * for. Adding a host means checking that property, not recognising the name.
     */
    private static final Set<String> PUBLIC_MAVEN_REPOSITORIES = Set.of(
            "maven.repository.redhat.com", "repository.jboss.org");

    /** The public npm registry, under the spellings a purl might carry. */
    private static final Set<String> PUBLIC_NPM_REGISTRIES = Set.of(
            "registry.npmjs.org", "registry.npmjs.com", "www.npmjs.com", "npmjs.org", "npmjs.com");

    private RegistryLinks() {}

    /**
     * @param purl package URL, e.g. {@code pkg:maven/com.example/lib@1.2.3?type=jar}
     * @return both links, either of which may be null; never null itself
     */
    public static Links forPurl(String purl) {
        if (purl == null || !purl.startsWith("pkg:")) {
            return Links.NONE;
        }

        String withoutScheme = purl.substring("pkg:".length());
        int firstSlash = withoutScheme.indexOf('/');
        if (firstSlash < 0) {
            return Links.NONE;
        }

        String type = withoutScheme.substring(0, firstSlash).toLowerCase(Locale.ROOT);
        String rest = withoutScheme.substring(firstSlash + 1);
        String repository = qualifier(rest, "repository_url");
        String remainder = stripQualifiers(rest);

        int at = remainder.lastIndexOf('@');
        String path = at > 0 ? remainder.substring(0, at) : remainder;
        String version = at > 0 ? decode(remainder.substring(at + 1)) : null;

        return switch (type) {
            case "maven" -> maven(path, version, repository);
            case "npm" -> npm(path, version, repository);
            default -> Links.NONE;
        };
    }

    private static Links maven(String path, String version, String repository) {
        int slash = path.indexOf('/');
        if (slash < 0) {
            return Links.NONE;
        }
        String group = decode(path.substring(0, slash));
        String artifact = decode(path.substring(slash + 1));

        if (repository == null) {
            return mavenCentral(group, artifact, version);
        }

        String host = hostOf(repository);
        if (host == null) {
            return Links.NONE;
        }
        if (MAVEN_CENTRAL_HOSTS.contains(host)) {
            return mavenCentral(group, artifact, version);
        }
        if (PUBLIC_MAVEN_REPOSITORIES.contains(host)) {
            return rawRepository(repository, group, artifact, version);
        }
        // A private or unknown host. No link beats a link that is wrong for every reader.
        return Links.NONE;
    }

    private static Links mavenCentral(String group, String artifact, String version) {
        String artifactPage = "https://central.sonatype.com/artifact/%s/%s"
                .formatted(encode(group), encode(artifact));
        return new Links(artifactPage,
                version == null ? null : artifactPage + "/" + encode(version));
    }

    /**
     * A plain Maven repository has no artifact "page", but its layout is fixed:
     * {@code <base>/group/with/slashes/artifact/version/}. The directory above the version
     * is the closest thing to an artifact page and lists every version that exists there,
     * which is exactly what a reader whose own version has no page needs.
     */
    private static Links rawRepository(String repository, String group, String artifact, String version) {
        String base = trimTrailingSlashes(withScheme(repository));
        String groupPath = Arrays.stream(group.split("\\."))
                .map(RegistryLinks::encode)
                .collect(Collectors.joining("/"));
        String artifactPath = base + "/" + groupPath + "/" + encode(artifact) + "/";
        return new Links(artifactPath,
                version == null ? null : artifactPath + encode(version) + "/");
    }

    private static Links npm(String path, String version, String repository) {
        // A purl naming a private npm registry is the same case as a private Maven host.
        if (repository != null) {
            String host = hostOf(repository);
            if (host == null || !PUBLIC_NPM_REGISTRIES.contains(host)) {
                return Links.NONE;
            }
        }

        // Scoped packages arrive percent-encoded as %40scope/name; npmjs.com wants the
        // decoded @scope/name form in the URL path.
        String artifactPage = "https://www.npmjs.com/package/" + decode(path);
        return new Links(artifactPage,
                version == null ? null : artifactPage + "/v/" + encode(version));
    }

    /**
     * Reads one purl qualifier out of the {@code ?key=value&…} tail.
     *
     * <p>{@link #stripQualifiers} discards this whole string, which is how the one field
     * naming where the artifact lives was being thrown away before linking to Central anyway.
     */
    private static String qualifier(String value, String key) {
        int question = value.indexOf('?');
        if (question < 0) {
            return null;
        }
        String query = value.substring(question + 1);
        int hash = query.indexOf('#');
        if (hash >= 0) {
            query = query.substring(0, hash);
        }
        for (String pair : query.split("&")) {
            int equals = pair.indexOf('=');
            if (equals > 0 && pair.substring(0, equals).equalsIgnoreCase(key)) {
                String found = decode(pair.substring(equals + 1)).trim();
                return found.isEmpty() ? null : found;
            }
        }
        return null;
    }

    /**
     * The host, lowercased, or null when the value does not parse as one.
     *
     * <p>Parsed rather than matched as a substring on purpose: {@code https://example.com/
     * maven.repository.redhat.com/} contains an allowlisted name and is not that host.
     */
    private static String hostOf(String repository) {
        try {
            String host = URI.create(withScheme(repository)).getHost();
            return host == null ? null : host.toLowerCase(Locale.ROOT);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /**
     * The purl spec allows {@code repository_url} without a scheme, and every allowlisted
     * host serves https — so an absent or plain-http scheme becomes https rather than being
     * rejected or followed insecurely.
     */
    private static String withScheme(String repository) {
        String trimmed = repository.trim();
        if (trimmed.regionMatches(true, 0, "http://", 0, "http://".length())) {
            return "https://" + trimmed.substring("http://".length());
        }
        if (trimmed.contains("://")) {
            return trimmed;
        }
        return "https://" + trimmed;
    }

    private static String trimTrailingSlashes(String value) {
        int end = value.length();
        while (end > 0 && value.charAt(end - 1) == '/') {
            end--;
        }
        return value.substring(0, end);
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
