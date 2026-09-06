package dev.sbomscope.bump;

public record PreviewFile(String path, String fingerprint, String patched,
                          java.util.List<TextRange> changed, int editCount) {}
