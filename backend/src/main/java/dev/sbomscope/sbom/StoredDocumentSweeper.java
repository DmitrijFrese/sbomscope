package dev.sbomscope.sbom;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Stream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

/**
 * Removes stored SBOM documents that no longer have an SBOM row.
 *
 * <p>Documents and database rows live in two places that no transaction spans, so they can
 * drift: an import that fails after writing the file, a crash between the two, or — the
 * reason this exists now — a schema reset, which empties the tables and cannot reach the
 * disk. Left alone they accumulate silently, since nothing ever reads a file it has no row
 * for.
 *
 * <p>Deliberately one-directional. A row without its document is <em>not</em> cleaned up
 * here: that is a real SBOM whose re-scan will fail with a message saying so, and deleting
 * the user's inventory to tidy up after ourselves would be a much worse trade.
 *
 * <p>Runs once at startup rather than on a timer, so it can never race an import in flight.
 */
@Component
class StoredDocumentSweeper {

    private static final Logger log = LoggerFactory.getLogger(StoredDocumentSweeper.class);

    /**
     * Documents are written as {@code <uuid>.cdx.json} today. The bare {@code .json} form is
     * recognised too: uploads carried it before osv-scanner's filename-driven parser choice
     * forced the change, and those files are just as orphaned. What identifies one of ours is
     * the basename being a uuid — nothing else writes a file like that into this directory.
     */
    private static final List<String> SUFFIXES = List.of(".cdx.json", ".json");

    private final SbomRepository repository;
    private final SbomFileStore files;

    StoredDocumentSweeper(SbomRepository repository, SbomFileStore files) {
        this.repository = repository;
        this.files = files;
    }

    @EventListener(ApplicationReadyEvent.class)
    void sweep() {
        Path root = files.root();
        if (!Files.isDirectory(root)) {
            return;
        }

        Set<UUID> known = new HashSet<>();
        repository.findAll().forEach(sbom -> known.add(sbom.id()));

        int removed = 0;
        try (Stream<Path> stored = Files.list(root)) {
            for (Path file : stored.toList()) {
                UUID id = identify(file);
                // An unrecognised filename is left alone: this directory is the user's, and
                // deleting something we cannot account for is not a tidy-up.
                if (id != null && !known.contains(id)) {
                    removed += delete(file) ? 1 : 0;
                }
            }
        } catch (IOException e) {
            log.warn("Could not sweep stored SBOM documents in {}", root, e);
            return;
        }

        if (removed > 0) {
            log.info("Removed {} stored SBOM document(s) with no matching record", removed);
        }
    }

    /** The uuid a file is named for, or null when it is not one of ours. */
    private UUID identify(Path file) {
        if (!Files.isRegularFile(file)) {
            return null;
        }
        String name = file.getFileName().toString();

        for (String suffix : SUFFIXES) {
            if (!name.endsWith(suffix)) {
                continue;
            }
            try {
                return UUID.fromString(name.substring(0, name.length() - suffix.length()));
            } catch (IllegalArgumentException e) {
                // Not a uuid once the suffix is removed, so not ours — and the longer
                // suffix having failed, the shorter one cannot succeed either.
                return null;
            }
        }
        return null;
    }

    private boolean delete(Path file) {
        try {
            return Files.deleteIfExists(file);
        } catch (IOException e) {
            log.warn("Could not delete orphaned document {}", file, e);
            return false;
        }
    }
}
