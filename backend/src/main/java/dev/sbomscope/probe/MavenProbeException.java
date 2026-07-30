package dev.sbomscope.probe;

/** Raised when the configured {@code mvn} cannot be run at all — a settings-level problem. */
public class MavenProbeException extends RuntimeException {

    public MavenProbeException(String message) {
        super(message);
    }

    public MavenProbeException(String message, Throwable cause) {
        super(message, cause);
    }
}
