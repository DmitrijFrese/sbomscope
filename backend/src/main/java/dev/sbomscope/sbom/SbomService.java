package dev.sbomscope.sbom;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import dev.sbomscope.logging.ActivityLogger;

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
    private final ActivityLogger activityLog;

    SbomService(CycloneDxParser parser, SbomRepository repository, SbomFileStore files,
                ActivityLogger activityLog) {
        this.parser = parser;
        this.repository = repository;
        this.files = files;
        this.activityLog = activityLog;
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

        activityLog.record(ActivityLogger.Category.DATA, "SBOM_UPLOADED",
                "%s (%d components)".formatted(filename, parsed.components().size()));
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

    public List<ParsedSbom.DependencyEdge> findEdges(UUID sbomId) {
        return repository.findEdges(sbomId);
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
            activityLog.record(ActivityLogger.Category.DATA, "SBOM_DELETED", id.toString());
        }
        return deleted;
    }

    /**
     * Sets, changes or clears a document's workspace after upload (B20).
     *
     * <p>Until 2026-08-06 the path could only be given as an upload request parameter, so a
     * document uploaded without one could never gain it and Phase 9's whole reachability
     * surface stayed permanently unavailable for it — the only workaround being to delete and
     * re-upload, discarding the document and its scan history to change one string.
     *
     * <p>Clearing is a real operation, not a malformed request: a workspace that has moved is
     * worse than none, because analysis then answers confidently about a directory that is no
     * longer the project. It reuses {@link #normaliseWorkspacePath} rather than validating
     * again, so the rules a path must satisfy are stated in exactly one place and the message
     * a typo produces is the same one the upload gives.
     *
     * @return the stored document with its new path, or empty when there is no such document
     */
    @Transactional
    public Optional<StoredSbom> attachWorkspace(UUID id, String workspacePath) {
        Optional<StoredSbom> existing = repository.findById(id);
        if (existing.isEmpty()) {
            return Optional.empty();
        }
        StoredSbom sbom = existing.get();
        String normalised = normaliseWorkspacePath(workspacePath);

        if (Objects.equals(normalised, sbom.workspacePath())) {
            return Optional.of(sbom);
        }

        repository.updateWorkspacePath(id, normalised);
        activityLog.record(ActivityLogger.Category.DATA, "SBOM_WORKSPACE", "UPDATED",
                normalised == null
                        ? "%s: workspace detached".formatted(sbom.filename())
                        : "%s: workspace set to %s".formatted(sbom.filename(), normalised));

        return Optional.of(new StoredSbom(id, sbom.filename(), sbom.uploadedAt(), normalised,
                sbom.specVersion(), sbom.componentCount(), sbom.folderId()));
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
