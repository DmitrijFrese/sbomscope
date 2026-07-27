package dev.sbomscope.sbom;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Keeps the uploaded SBOM document itself, alongside the parsed components.
 *
 * <p>Needed because scanning runs the external tool against a real file, and because a
 * re-scan months later must use the document as uploaded rather than one reconstructed
 * from our own parse — which would quietly launder any parsing mistake into the input.
 */
@Component
public class SbomFileStore {

    private static final Logger log = LoggerFactory.getLogger(SbomFileStore.class);

    private final Path root;

    SbomFileStore(@Value("${sbomscope.data-directory:${user.home}/.sbomscope}") String dataDirectory) {
        this.root = Path.of(dataDirectory, "sboms");
    }

    /**
     * The {@code .cdx.json} suffix is required, not cosmetic. osv-scanner selects its
     * parser by filename, so a document stored as {@code <uuid>.json} is rejected with
     * "could not determine extractor suitable to this file" no matter how valid its
     * contents are.
     */
    public Path pathFor(UUID sbomId) {
        return root.resolve(sbomId + ".cdx.json");
    }

    /** Where documents are kept, for the startup sweep that clears orphaned ones. */
    Path root() {
        return root;
    }

    public Path store(UUID sbomId, InputStream content) throws IOException {
        Files.createDirectories(root);
        Path target = pathFor(sbomId);
        Files.copy(content, target, StandardCopyOption.REPLACE_EXISTING);
        return target;
    }

    public boolean exists(UUID sbomId) {
        return Files.isRegularFile(pathFor(sbomId));
    }

    /** Best effort: a leftover file is untidy, not harmful, so it must not fail a delete. */
    public void delete(UUID sbomId) {
        try {
            Files.deleteIfExists(pathFor(sbomId));
        } catch (IOException e) {
            log.warn("Could not delete stored SBOM {}", sbomId, e);
        }
    }
}
