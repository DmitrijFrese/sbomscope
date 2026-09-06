package dev.sbomscope.bump;

public record PomFile(String path, String fingerprint, boolean editable, String text) {}
