package dev.sbomscope.settings;

/**
 * Published whenever the Maven tool settings change.
 *
 * <p>Kept as a Spring event rather than a direct dependency so the settings package does not
 * have to know about the probe package's caches — anything holding a result computed against
 * "the current Maven config" listens for this instead.
 */
public record MavenSettingsChangedEvent() {}
