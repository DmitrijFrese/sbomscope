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
        Phase phase,
        long bytesDownloaded,
        long totalBytes,
        /**
         * Advisories read so far while indexing. The archive announces no total, so this
         * counts up without a ceiling — an honest spinner with a number rather than a bar
         * pretending to know how far along it is.
         */
        int advisoriesIndexed,
        String message,
        Instant startedAt) {

    public enum State {
        /** Nothing has been downloaded in this session. */
        IDLE,
        RUNNING,
        COMPLETED,
        FAILED
    }

    /**
     * Fetching the archive is one job; making it answerable is another.
     *
     * <p>They are reported separately because they fail separately, take different amounts
     * of time, and only one of them has a known total — presenting them as a single bar
     * would mean either a bar that stalls at 100% or one that lies about its scale.
     */
    public enum Phase {
        DOWNLOAD,
        INDEX
    }

    public static DownloadProgress idle() {
        return new DownloadProgress(null, State.IDLE, Phase.DOWNLOAD, 0, -1, 0, null, null);
    }

    public static DownloadProgress starting(String ecosystem) {
        return new DownloadProgress(
                ecosystem, State.RUNNING, Phase.DOWNLOAD, 0, -1, 0, null, Instant.now());
    }

    public DownloadProgress advanced(long bytesDownloaded, long totalBytes) {
        return new DownloadProgress(ecosystem, State.RUNNING, Phase.DOWNLOAD,
                bytesDownloaded, totalBytes, advisoriesIndexed, null, startedAt);
    }

    /** The archive is on disk; the remaining work is parsing it into the index. */
    public DownloadProgress indexing(int advisories) {
        return new DownloadProgress(ecosystem, State.RUNNING, Phase.INDEX,
                bytesDownloaded, totalBytes, advisories, null, startedAt);
    }

    public DownloadProgress completed(long totalBytes) {
        return new DownloadProgress(ecosystem, State.COMPLETED, phase,
                totalBytes, totalBytes, advisoriesIndexed, null, startedAt);
    }

    public DownloadProgress failed(String message) {
        return new DownloadProgress(ecosystem, State.FAILED, phase,
                bytesDownloaded, totalBytes, advisoriesIndexed, message, startedAt);
    }

    public boolean running() {
        return state == State.RUNNING;
    }
}
