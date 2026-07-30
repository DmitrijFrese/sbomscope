package dev.sbomscope.probe;

/**
 * Why a probe could not resolve anything, classified so the panel can send the reader
 * somewhere useful instead of one generic "probe failed" message.
 *
 * <p>"Not found" sends them to add a repository; "authentication" sends them to their
 * credentials; "not runnable" is a settings problem; the rest is shown verbatim rather than
 * discarded, because a confident wrong classification is worse than an honest "other".
 */
public enum ProbeFailureReason {
    NOT_FOUND,
    AUTHENTICATION,
    NOT_RUNNABLE,
    TIMEOUT,
    OTHER
}
