package dev.sbomscope.sbom;

/**
 * Raised when an uploaded file cannot be understood as a CycloneDX SBOM.
 *
 * <p>The message is shown to the user, so it should say what was wrong with their file
 * and, where possible, how to produce a usable one.
 */
public class InvalidSbomException extends RuntimeException {

    public InvalidSbomException(String message) {
        super(message);
    }

    public InvalidSbomException(String message, Throwable cause) {
        super(message, cause);
    }
}
