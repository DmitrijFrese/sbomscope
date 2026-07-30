package dev.sbomscope.api;

import java.time.Instant;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.multipart.MaxUploadSizeExceededException;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.resource.NoResourceFoundException;

import dev.sbomscope.probe.MavenProbeException;
import dev.sbomscope.sbom.InvalidSbomException;
import dev.sbomscope.scanner.OsvScannerException;

/**
 * Turns failures into a consistent JSON shape.
 *
 * <p>Messages from {@link InvalidSbomException} are written for users and are passed
 * through verbatim; anything unexpected is logged in full and reported generically,
 * so an internal failure never leaks its internals into the UI.
 */
@RestControllerAdvice
class ApiExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(ApiExceptionHandler.class);

    record ApiError(Instant timestamp, int status, String error, String message) {

        static ApiError of(HttpStatus status, String message) {
            return new ApiError(Instant.now(), status.value(), status.getReasonPhrase(), message);
        }
    }

    @ExceptionHandler(InvalidSbomException.class)
    ResponseEntity<ApiError> handleInvalidSbom(InvalidSbomException e) {
        return ResponseEntity.badRequest().body(ApiError.of(HttpStatus.BAD_REQUEST, e.getMessage()));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    ResponseEntity<ApiError> handleIllegalArgument(IllegalArgumentException e) {
        return ResponseEntity.badRequest().body(ApiError.of(HttpStatus.BAD_REQUEST, e.getMessage()));
    }

    /**
     * A malformed request body is the caller's mistake, not ours. Without this the
     * catch-all reports it as a 500, which sends people looking for a server fault that
     * does not exist.
     */
    @ExceptionHandler(HttpMessageNotReadableException.class)
    ResponseEntity<ApiError> handleUnreadableBody(HttpMessageNotReadableException e) {
        return ResponseEntity.badRequest()
                .body(ApiError.of(HttpStatus.BAD_REQUEST, "Request body could not be parsed as JSON."));
    }

    /** Asking for something that conflicts with work already in progress. */
    @ExceptionHandler(IllegalStateException.class)
    ResponseEntity<ApiError> handleConflict(IllegalStateException e) {
        return ResponseEntity.status(HttpStatus.CONFLICT)
                .body(ApiError.of(HttpStatus.CONFLICT, e.getMessage()));
    }

    /**
     * Scanner problems the user can act on: scanning switched off, no binary configured, a
     * missing database, an uploaded document no longer on disk.
     *
     * <p>Declared because without it the catch-all below reported every one of them as
     * "Something went wrong. Check the application log for details." — discarding messages
     * written specifically to tell the user what to do, and sending them to a log to find
     * out. The same trap the {@link ResponseStatusException} handler exists to avoid.
     */
    @ExceptionHandler(OsvScannerException.class)
    ResponseEntity<ApiError> handleScanner(OsvScannerException e) {
        return ResponseEntity.status(HttpStatus.CONFLICT)
                .body(ApiError.of(HttpStatus.CONFLICT, e.getMessage()));
    }

    /** The Maven probe's equivalent: mvn cannot be run at all, a settings-level problem. */
    @ExceptionHandler(MavenProbeException.class)
    ResponseEntity<ApiError> handleMavenProbe(MavenProbeException e) {
        return ResponseEntity.status(HttpStatus.CONFLICT)
                .body(ApiError.of(HttpStatus.CONFLICT, e.getMessage()));
    }

    @ExceptionHandler(MaxUploadSizeExceededException.class)
    ResponseEntity<ApiError> handleTooLarge(MaxUploadSizeExceededException e) {
        return ResponseEntity.status(HttpStatus.CONTENT_TOO_LARGE)
                .body(ApiError.of(HttpStatus.CONTENT_TOO_LARGE, "That SBOM is larger than the 64 MB limit."));
    }

    /**
     * Deliberately declared: without it the catch-all below would swallow every
     * {@link ResponseStatusException} and report it as a 500, turning an ordinary
     * "not found" into an apparent server failure.
     */
    @ExceptionHandler(ResponseStatusException.class)
    ResponseEntity<ApiError> handleResponseStatus(ResponseStatusException e) {
        HttpStatus status = HttpStatus.resolve(e.getStatusCode().value());
        if (status == null) {
            status = HttpStatus.INTERNAL_SERVER_ERROR;
        }
        return ResponseEntity.status(status).body(ApiError.of(status, e.getReason()));
    }

    /**
     * A path under {@code /api/} that maps to nothing is a 404, not a server failure.
     *
     * <p>The same trap as the handler above, one exception further along, and it does not catch
     * this one: {@link NoResourceFoundException} implements {@code ErrorResponse} but does
     * <b>not</b> extend {@link ResponseStatusException}, so it fell straight through to the
     * catch-all and every mistyped API URL was reported as a 500 with a stack trace in the log.
     *
     * <p>It also contradicted a stated design property. {@code SpaResourceConfig} forwards
     * unknown non-API paths to {@code index.html} but deliberately lets {@code /api/} ones fail,
     * precisely so a mistyped fetch URL fails as a missing endpoint rather than as an HTML parse
     * error — which only works if the failure it produces is a 404.
     */
    @ExceptionHandler(NoResourceFoundException.class)
    ResponseEntity<ApiError> handleNoResource(NoResourceFoundException e) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(ApiError.of(HttpStatus.NOT_FOUND, "No such endpoint: " + e.getResourcePath()));
    }

    @ExceptionHandler(Exception.class)
    ResponseEntity<ApiError> handleUnexpected(Exception e) {
        log.error("Unhandled failure while serving request", e);
        return ResponseEntity.internalServerError()
                .body(ApiError.of(HttpStatus.INTERNAL_SERVER_ERROR,
                        "Something went wrong. Check the application log for details."));
    }
}
