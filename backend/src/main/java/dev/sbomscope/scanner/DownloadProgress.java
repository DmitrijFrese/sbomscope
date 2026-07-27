package dev.sbomscope.scanner;

import java.time.Instant;

/**
 * Progress of a database download, polled by the UI.
 *
 * @param totalBytes total size, or -1 when the server did not send a Content-Length
 * @param message    the failure reason when {@link State#FAILED}, otherwise null
 */
public record DownloadProgress(
        String ecosystem,
        State state,
        long bytesDownloaded,
        long totalBytes,
        String message,
        Instant startedAt) {

    public enum State {
        /** Nothing has been downloaded in this session. */
        IDLE,
        RUNNING,
        COMPLETED,
        FAILED
    }

    public static DownloadProgress idle() {
        return new DownloadProgress(null, State.IDLE, 0, -1, null, null);
    }

    public static DownloadProgress starting(String ecosystem) {
        return new DownloadProgress(ecosystem, State.RUNNING, 0, -1, null, Instant.now());
    }

    public DownloadProgress advanced(long bytesDownloaded, long totalBytes) {
        return new DownloadProgress(
                ecosystem, State.RUNNING, bytesDownloaded, totalBytes, null, startedAt);
    }

    public DownloadProgress completed(long totalBytes) {
        return new DownloadProgress(
                ecosystem, State.COMPLETED, totalBytes, totalBytes, null, startedAt);
    }

    public DownloadProgress failed(String message) {
        return new DownloadProgress(
                ecosystem, State.FAILED, bytesDownloaded, totalBytes, message, startedAt);
    }

    public boolean running() {
        return state == State.RUNNING;
    }
}
