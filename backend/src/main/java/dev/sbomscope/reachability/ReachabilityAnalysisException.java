package dev.sbomscope.reachability;

/** An engine failure is incomplete evidence, not a negative reachability finding. */
public class ReachabilityAnalysisException extends RuntimeException {

    ReachabilityAnalysisException(String message, Throwable cause) {
        super(message, cause);
    }
}
