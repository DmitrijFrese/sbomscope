package dev.sbomscope.sbom;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Import and retrieval of SBOMs.
 *
 * <p>Import is a single transaction: an SBOM that fails partway through leaves nothing
 * behind, so the sidebar never shows a half-imported document.
 */
@Service
public class SbomService {

    private final CycloneDxParser parser;
    private final SbomRepository repository;
    private final SbomFileStore files;

    SbomService(CycloneDxParser parser, SbomRepository repository, SbomFileStore files) {
        this.parser = parser;
        this.repository = repository;
        this.files = files;
    }

    @Transactional
    public StoredSbom importSbom(String filename, String workspacePath, InputStream content) {
        String normalisedWorkspace = normaliseWorkspacePath(workspacePath);

        UUID id = UUID.randomUUID();

        // Stored before parsing, and parsed back off disk: scanning runs the external
        // tool against a real file, and a later re-scan must see the document as
        // uploaded rather than one reconstructed from our own parse.
        try {
            files.store(id, content);
        } catch (IOException e) {
            throw new InvalidSbomException("The uploaded file could not be saved.", e);
        }

        ParsedSbom parsed;
        try (InputStream stored = Files.newInputStream(files.pathFor(id))) {
            parsed = parser.parse(stored);
        } catch (IOException e) {
            files.delete(id);
            throw new InvalidSbomException("The saved file could not be read back.", e);
        } catch (RuntimeException e) {
            files.delete(id);
            throw e;
        }

        StoredSbom sbom = new StoredSbom(
                id,
                filename,
                Instant.now(),
                normalisedWorkspace,
                parsed.specVersion(),
                parsed.components().size());

        repository.insertSbom(sbom);
        repository.insertComponents(sbom.id(), parsed.components());
        repository.insertEdges(sbom.id(), parsed.edges());

        return sbom;
    }

    public List<StoredSbom> findAll() {
        return repository.findAll();
    }

    public Optional<StoredSbom> findById(UUID id) {
        return repository.findById(id);
    }

    public List<StoredComponent> findComponents(UUID sbomId) {
        return repository.findComponents(sbomId);
    }

    /**
     * The component carrying this purl, for the Component Inspector.
     *
     * <p>A purl is not unique within an SBOM — the same library at the same version can be
     * listed under several bom-refs, which npm does when it installs a package at more than
     * one path. They describe one library, so returning the first is right; and because
     * {@link #findComponents} orders root first and then by scope, "first" is the most
     * significant of them rather than an arbitrary one.
     */
    public Optional<StoredComponent> findComponentByPurl(UUID sbomId, String purl) {
        if (purl == null || purl.isBlank()) {
            return Optional.empty();
        }
        return findComponents(sbomId).stream()
                .filter(component -> purl.equals(component.purl()))
                .findFirst();
    }

    @Transactional
    public boolean delete(UUID id) {
        boolean deleted = repository.deleteById(id);
        if (deleted) {
            files.delete(id);
        }
        return deleted;
    }

    /**
     * Validated at import time rather than when scanning starts, so a typo surfaces
     * immediately instead of hours later when the user finally opens the workspace view.
     */
    private String normaliseWorkspacePath(String workspacePath) {
        if (workspacePath == null || workspacePath.isBlank()) {
            return null;
        }

        Path path;
        try {
            path = Path.of(workspacePath.trim()).toAbsolutePath().normalize();
        } catch (InvalidPathException e) {
            throw new IllegalArgumentException(
                    "'%s' is not a valid path.".formatted(workspacePath), e);
        }

        if (!Files.exists(path)) {
            throw new IllegalArgumentException("Workspace path does not exist: " + path);
        }
        if (!Files.isDirectory(path)) {
            throw new IllegalArgumentException("Workspace path is not a directory: " + path);
        }
        if (!Files.isReadable(path)) {
            throw new IllegalArgumentException("Workspace path is not readable: " + path);
        }
        return path.toString();
    }
}
