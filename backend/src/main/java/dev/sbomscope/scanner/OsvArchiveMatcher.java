package dev.sbomscope.scanner;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.function.IntConsumer;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.ObjectMapper;

/**
 * Answers "which advisories affect package P at version V" for versions the user does not
 * have, from the downloaded archives.
 *
 * <p><b>This is not a second scanner, and the boundary is load-bearing.</b> What is
 * <em>installed</em> is reported by osv-scanner and nothing else; this exists only to
 * evaluate hypotheticals — "would 3.1.5 be clean?" — which osv-scanner does not take as a
 * question, since it scans a document describing what is present. If the two ever disagree
 * about a version the user actually has, the scanner is right by definition.
 *
 * <p>It reports the advisory's <b>GHSA rating</b>, never a CVSS score. OSV carries severity
 * as vector strings only — the numeric score on a finding was computed by the scanner — and
 * turning a vector into a number here would mean owning a CVSS implementation this project
 * has already declined to write.
 *
 * <h2>Why the index is on disk</h2>
 *
 * <p>The archive names its entries by advisory id, not by package, so finding one library's
 * advisories means parsing all of it: measured at 5.2 s and ~152 MB retained for npm's
 * 223,786 advisories over 220,027 packages. Almost all of that memory described packages the
 * project does not have. Parsed once into the database instead, a lookup is an indexed
 * SELECT, nothing is retained, and a restart costs nothing — which the in-memory version
 * could not manage however it was triggered.
 */
@Component
public class OsvArchiveMatcher {

    private static final Logger log = LoggerFactory.getLogger(OsvArchiveMatcher.class);

    /** Rows per batch. Large enough to be worth batching, small enough to stay bounded. */
    private static final int CHUNK = 2_000;

    private final ObjectMapper objectMapper;
    private final OsvIndexRepository repository;

    OsvArchiveMatcher(ObjectMapper objectMapper, OsvIndexRepository repository) {
        this.objectMapper = objectMapper;
        this.repository = repository;
    }

    /** One advisory that would apply to the version asked about. */
    public record AdvisoryHit(String osvId, String cveId, String rating) {}

    /**
     * @return the advisories affecting that version, or empty. <b>Empty is ambiguous on its
     *         own</b> — it also means "not indexed" — so callers ask {@link #isIndexed}
     *         first rather than reading silence as a clean bill of health.
     */
    public List<AdvisoryHit> advisoriesFor(String databaseDirectory, String ecosystem,
                                           String packageName, String version) {

        if (packageName == null || version == null || !isIndexed(databaseDirectory, ecosystem)) {
            return List.of();
        }

        List<AdvisoryHit> hits = new ArrayList<>();
        for (OsvIndexRepository.IndexRow row : repository.advisoriesFor(ecosystem, key(packageName))) {
            if (appliesTo(row, version)) {
                hits.add(new AdvisoryHit(row.osvId(), row.cveId(), row.rating()));
            }
        }
        return List.copyOf(hits);
    }

    private boolean appliesTo(OsvIndexRepository.IndexRow row, String version) {
        try {
            List<OsvReport.Affected> affected = objectMapper.readValue(
                    row.affected(), objectMapper.getTypeFactory()
                            .constructCollectionType(List.class, OsvReport.Affected.class));
            return affected.stream().anyMatch(entry -> AffectedVersions.affects(entry, version));
        } catch (JacksonException e) {
            // Stored by us from data we parsed, so this should not happen; if it does, the
            // safe reading of an unreadable row is "cannot say", not "clean".
            log.warn("Unreadable index row for {}: {}", row.osvId(), e.getMessage());
            return false;
        }
    }

    /** Whether an archive for this ecosystem is present at all. A file check, not a parse. */
    public boolean archivePresent(String databaseDirectory, String ecosystem) {
        if (databaseDirectory == null || databaseDirectory.isBlank() || ecosystem == null) {
            return false;
        }
        return Files.isRegularFile(OsvArchiveLayout.archivePath(databaseDirectory, ecosystem));
    }

    /**
     * Whether the index matches the archive currently on disk.
     *
     * <p>Compared by identity rather than mere presence, so refreshing a download makes the
     * old index stale by itself — nobody has to remember to invalidate it, which is exactly
     * the kind of thing nobody remembers.
     */
    public boolean isIndexed(String databaseDirectory, String ecosystem) {
        if (!archivePresent(databaseDirectory, ecosystem)) {
            return false;
        }
        String identity = identityOf(OsvArchiveLayout.archivePath(databaseDirectory, ecosystem));
        return identity != null
                && repository.sourceFor(ecosystem)
                        .map(source -> identity.equals(source.identity()))
                        .orElse(false);
    }

    public Optional<OsvIndexRepository.IndexSource> indexStatus(String ecosystem) {
        return repository.sourceFor(ecosystem);
    }

    /**
     * Parses the archive into the database. One pass, and the only expensive thing here.
     *
     * <p>Runs after a download, and on demand for an archive carried across by hand. The
     * whole file is read however little of it is wanted, because nothing can be skipped
     * without parsing it to find out which package it belongs to.
     *
     * @param onProgress advisories read so far, for the caller to report — the count is the
     *                   only measurable thing, since the archive gives no total up front
     */
    public void buildIndex(String databaseDirectory, String ecosystem, IntConsumer onProgress) {
        Path archive = OsvArchiveLayout.archivePath(databaseDirectory, ecosystem);
        if (!Files.isRegularFile(archive)) {
            throw new OsvScannerException(
                    "There is no %s database to index. Download it first.".formatted(ecosystem));
        }
        String identity = identityOf(archive);
        if (identity == null) {
            throw new OsvScannerException("Could not read the %s database.".formatted(ecosystem));
        }

        long startedAt = System.currentTimeMillis();
        repository.clear(ecosystem);

        List<OsvIndexRepository.IndexRow> chunk = new ArrayList<>(CHUNK);
        int advisories = 0;
        int packages = 0;

        try (InputStream in = Files.newInputStream(archive);
             ZipInputStream zip = new ZipInputStream(in)) {

            ZipEntry file;
            while ((file = zip.getNextEntry()) != null) {
                if (file.isDirectory() || !file.getName().endsWith(".json")) {
                    continue;
                }
                OsvReport.Vulnerability advisory;
                try {
                    advisory = objectMapper.readValue(zip.readAllBytes(), OsvReport.Vulnerability.class);
                } catch (JacksonException e) {
                    log.debug("Skipping unreadable advisory {}: {}", file.getName(), e.getMessage());
                    continue;
                }
                if (advisory == null || advisory.id() == null || advisory.affected() == null) {
                    continue;
                }

                advisories++;
                packages += rowsFor(advisory, chunk);

                if (chunk.size() >= CHUNK) {
                    repository.insertChunk(ecosystem, chunk);
                    chunk.clear();
                    onProgress.accept(advisories);
                }
            }
            repository.insertChunk(ecosystem, chunk);

        } catch (IOException e) {
            repository.clear(ecosystem);
            throw new OsvScannerException(
                    "Could not read the %s database: %s".formatted(ecosystem, e.getMessage()), e);
        }

        // Last, so an interrupted build leaves rows nothing considers usable.
        repository.recordSource(new OsvIndexRepository.IndexSource(
                ecosystem, identity, advisories, packages, java.time.Instant.now()));

        log.info("Indexed {} {} advisories over {} package entries in {} ms",
                advisories, ecosystem, packages, System.currentTimeMillis() - startedAt);
        onProgress.accept(advisories);
    }

    /**
     * One row per package the advisory names, carrying only that package's affected entries.
     *
     * <p>An advisory routinely covers several coordinates — the Jackson advisory names both
     * {@code com.fasterxml.jackson.core} and {@code tools.jackson.core} — and keeping the
     * others would mean evaluating a version against ranges belonging to a different
     * library, which is the mistake {@code fixedVersionFor} exists to avoid.
     */
    private int rowsFor(OsvReport.Vulnerability advisory, List<OsvIndexRepository.IndexRow> chunk) {
        Map<String, List<OsvReport.Affected>> perName = new HashMap<>();
        for (OsvReport.Affected affected : advisory.affected()) {
            if (affected.pkg() == null || affected.pkg().name() == null) {
                continue;
            }
            perName.computeIfAbsent(key(affected.pkg().name()), name -> new ArrayList<>()).add(affected);
        }

        String cve = firstCve(advisory.aliases());
        String rating = advisory.databaseSpecific() == null ? null : advisory.databaseSpecific().severity();

        perName.forEach((name, affected) -> chunk.add(new OsvIndexRepository.IndexRow(
                name, advisory.id(), cve, rating, objectMapper.writeValueAsString(affected))));

        return perName.size();
    }

    /** Size and modification time, so replacing an archive invalidates its index by itself. */
    private String identityOf(Path archive) {
        try {
            return archive + ":" + Files.size(archive) + ":" + Files.getLastModifiedTime(archive);
        } catch (IOException e) {
            log.warn("Could not read {}: {}", archive, e.getMessage());
            return null;
        }
    }

    private String firstCve(List<String> aliases) {
        if (aliases == null) {
            return null;
        }
        return aliases.stream()
                .filter(alias -> alias != null && alias.startsWith("CVE-"))
                .findFirst()
                .orElse(null);
    }

    /** Both sides of the lookup normalise the same way, as {@code PackageKey} already does. */
    private String key(String name) {
        return name.toLowerCase(Locale.ROOT);
    }
}
