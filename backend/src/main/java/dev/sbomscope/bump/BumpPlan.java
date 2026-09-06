package dev.sbomscope.bump;

/** @param lockfileNotes one line per manifest whose lockfile now disagrees. Never silent */
public record BumpPlan(
        java.util.UUID sbomId, String workspace,
        java.util.List<PomFile> files, java.util.List<BumpRow> rows,
        java.util.List<String> notes, java.util.List<String> lockfileNotes) {}
