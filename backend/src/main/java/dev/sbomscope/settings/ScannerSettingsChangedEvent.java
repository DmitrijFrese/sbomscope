package dev.sbomscope.settings;

/**
 * Published whenever the vulnerability-scanner settings change.
 *
 * <p>The counterpart to {@link MavenSettingsChangedEvent}, and it exists for the opposite
 * reason. That one invalidates work computed against a configuration that no longer applies;
 * this one says work that was <em>skipped</em> may now be possible. {@code AutomaticScanner}
 * gives up silently when no scanner is configured — correct at the time, and it left the gap
 * open until the next restart, because nothing told it the obstacle had gone.
 *
 * <p>A Spring event rather than a direct call so the settings package stays unaware of the
 * scanner package, exactly as the Maven one does.
 */
public record ScannerSettingsChangedEvent() {}
