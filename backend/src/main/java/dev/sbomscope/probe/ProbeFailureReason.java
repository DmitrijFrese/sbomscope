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
    /**
     * Maven reached the repository and the transfer failed for a reason that is not about the
     * artifact — most often a certificate it cannot verify, sometimes a host it cannot reach.
     *
     * <p>Split out for exactly the reason {@link #PLUGIN_UNAVAILABLE} was, and it was found the
     * same way: a real run on a machine with TLS-inspecting security software failed with
     * {@code PKIX path building failed}, and the panel reported <em>"Not found in any configured
     * repository"</em>. The artifact was in Central and perfectly findable. Every one of those
     * failures says {@code Could not transfer artifact}, which the {@code NOT_FOUND} test also
     * matches, so this must be decided <b>before</b> it — a genuinely absent artifact and an
     * untrusted certificate produce the same sentence from Maven and need opposite fixes.
     */
    REPOSITORY_UNREACHABLE,
    TIMEOUT,
    OTHER
}
