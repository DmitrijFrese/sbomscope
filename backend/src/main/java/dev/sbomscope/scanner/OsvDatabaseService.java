package dev.sbomscope.scanner;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicReference;

import javax.net.ssl.SSLException;

import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Maintains the offline OSV database that osv-scanner reads.
 *
 * <p>Unlike the scanner binary, this is data rather than executable code, so SBOMscope
 * will fetch it — but only when the user explicitly asks. Nothing here runs on a timer
 * or at startup.
 *
 * <p>Downloads run on a background thread and report progress, because the npm archive
 * is around 200 MB: holding an HTTP request open for the duration would tell the user
 * nothing until it finished, and look indistinguishable from a hang.
 *
 * <p>On a machine with no internet the same result is achieved by copying the database
 * directory across from a connected one; the layout below is all osv-scanner requires.
 */
@Service
public class OsvDatabaseService {

    private static final Logger log = LoggerFactory.getLogger(OsvDatabaseService.class);

    static final String BASE_URL = "https://osv-vulnerabilities.storage.googleapis.com";

    /**
     * Only the ecosystems SBOMscope targets. Downloaded individually rather than as a
     * set: at the time of writing npm's archive is around 200 MB against Maven's 10 MB,
     * so a developer working only in Java has no reason to pull the npm data — and in a
     * restricted environment that download may have to be carried across by hand.
     */
    public static final List<String> ECOSYSTEMS = List.of("Maven", "npm");

    private static final int BUFFER_BYTES = 64 * 1024;

    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(30))
            .followRedirects(HttpClient.Redirect.NORMAL)
            .build();

    /** Single thread: one download at a time is plenty, and it serialises writes. */
    private final ExecutorService downloads = Executors.newSingleThreadExecutor(runnable -> {
        Thread thread = new Thread(runnable, "osv-database-download");
        thread.setDaemon(true);
        return thread;
    });

    private final AtomicReference<DownloadProgress> progress =
            new AtomicReference<>(DownloadProgress.idle());

    /**
     * State of one ecosystem's database file.
     *
     * @param path      absolute location on disk, so the user can find, copy or delete it
     * @param sourceUrl exactly what would be fetched, so nothing is downloaded opaquely
     */
    public record EcosystemStatus(
            String ecosystem,
            boolean present,
            long sizeBytes,
            Instant lastModified,
            String path,
            String sourceUrl) {}

    public DownloadProgress progress() {
        return progress.get();
    }

    public List<EcosystemStatus> status(String databaseDirectory) {
        List<EcosystemStatus> statuses = new ArrayList<>();
        for (String ecosystem : ECOSYSTEMS) {
            Path file = archivePath(databaseDirectory, ecosystem);
            String url = sourceUrl(ecosystem);

            if (Files.isRegularFile(file)) {
                try {
                    statuses.add(new EcosystemStatus(ecosystem, true, Files.size(file),
                            Files.getLastModifiedTime(file).toInstant(), file.toString(), url));
                    continue;
                } catch (IOException e) {
                    log.warn("Could not read database file {}", file, e);
                }
            }
            statuses.add(new EcosystemStatus(ecosystem, false, 0L, null, file.toString(), url));
        }
        return statuses;
    }

    /**
     * Starts a download and returns immediately; poll {@link #progress()} for the rest.
     *
     * @throws IllegalStateException if one is already running
     */
    public DownloadProgress startDownload(String databaseDirectory, String ecosystem) {
        if (!ECOSYSTEMS.contains(ecosystem)) {
            throw new IllegalArgumentException(
                    "Unsupported ecosystem '%s'. SBOMscope targets %s."
                            .formatted(ecosystem, String.join(" and ", ECOSYSTEMS)));
        }
        if (progress.get().running()) {
            throw new IllegalStateException(
                    "A download is already running for " + progress.get().ecosystem() + ".");
        }

        progress.set(DownloadProgress.starting(ecosystem));
        downloads.submit(() -> {
            try {
                long size = downloadEcosystem(databaseDirectory, ecosystem);
                progress.updateAndGet(current -> current.completed(size));
            } catch (RuntimeException e) {
                log.warn("Download of the {} database failed", ecosystem, e);
                progress.updateAndGet(current -> current.failed(e.getMessage()));
            }
        });
        return progress.get();
    }

    private long downloadEcosystem(String databaseDirectory, String ecosystem) {
        Path target = archivePath(databaseDirectory, ecosystem);
        // Downloaded beside the target and moved into place, so an interrupted transfer
        // cannot leave a truncated archive that osv-scanner would fail on later.
        Path temporary = target.resolveSibling("all.zip.partial");

        try {
            Files.createDirectories(target.getParent());

            HttpResponse<InputStream> response = httpClient.send(
                    HttpRequest.newBuilder(URI.create(sourceUrl(ecosystem)))
                            .GET()
                            .timeout(Duration.ofMinutes(30))
                            .build(),
                    HttpResponse.BodyHandlers.ofInputStream());

            if (response.statusCode() != 200) {
                throw new OsvScannerException(
                        "Downloading the %s database failed with HTTP %d."
                                .formatted(ecosystem, response.statusCode()));
            }

            long total = response.headers().firstValueAsLong("content-length").orElse(-1L);
            long downloaded = copyReportingProgress(response.body(), temporary, total);

            Files.move(temporary, target,
                    StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            log.info("Downloaded OSV database for {} ({} bytes)", ecosystem, downloaded);
            return downloaded;

        } catch (SSLException e) {
            throw new OsvScannerException(
                    ("Could not establish a secure connection while downloading the %s database. "
                            + "If security software on this machine inspects HTTPS traffic, Java must be "
                            + "told to trust the system certificate store — on Windows, start SBOMscope "
                            + "with -Djavax.net.ssl.trustStoreType=Windows-ROOT.").formatted(ecosystem), e);
        } catch (IOException e) {
            throw new OsvScannerException(
                    "Could not download the %s database: %s".formatted(ecosystem, e.getMessage()), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new OsvScannerException("Interrupted while downloading the " + ecosystem + " database.", e);
        } finally {
            try {
                Files.deleteIfExists(temporary);
            } catch (IOException e) {
                log.warn("Could not clean up {}", temporary, e);
            }
        }
    }

    private long copyReportingProgress(InputStream source, Path target, long total) throws IOException {
        byte[] buffer = new byte[BUFFER_BYTES];
        long downloaded = 0;

        try (InputStream in = source; OutputStream out = Files.newOutputStream(target)) {
            int read;
            while ((read = in.read(buffer)) != -1) {
                out.write(buffer, 0, read);
                downloaded += read;
                long soFar = downloaded;
                progress.updateAndGet(current -> current.advanced(soFar, total));
            }
        }
        return downloaded;
    }

    /** Exactly the layout osv-scanner expects: {dir}/osv-scanner/{ecosystem}/all.zip */
    private Path archivePath(String databaseDirectory, String ecosystem) {
        return Path.of(databaseDirectory, "osv-scanner", ecosystem, "all.zip");
    }

    private String sourceUrl(String ecosystem) {
        return "%s/%s/all.zip".formatted(BASE_URL, ecosystem);
    }

    @PreDestroy
    void shutdown() {
        downloads.shutdownNow();
    }
}
