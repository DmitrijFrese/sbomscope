package dev.sbomscope.scanner;

/** Raised when the external scanner cannot be run, or failed while running. */
public class OsvScannerException extends RuntimeException {

    public OsvScannerException(String message) {
        super(message);
    }

    public OsvScannerException(String message, Throwable cause) {
        super(message, cause);
    }
}
