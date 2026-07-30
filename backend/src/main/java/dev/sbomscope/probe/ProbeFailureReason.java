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
    /**
     * Maven ran, but could not obtain the plugin the probe drives. Separate from
     * {@link #NOT_FOUND} because it says nothing about the component being probed — the
     * isolated probe repository has no copy of the plugin and no route to one — and separate
     * from {@link #NOT_RUNNABLE} because {@code mvn} itself started perfectly well. Telling a
     * reader their dependency cannot be found, when the truth is the probe could not start
     * its own tooling, sends them to fix the wrong thing.
     */
    PLUGIN_UNAVAILABLE,
    TIMEOUT,
    OTHER
}
