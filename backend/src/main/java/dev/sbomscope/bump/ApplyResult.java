package dev.sbomscope.bump;

import java.util.List;

/**
 * What an apply actually did, so the UI can report it without asking again.
 *
 * @param written  one entry per file whose bytes changed, workspace-relative
 * @param backups  the {@code .orig} file written beside each of those, in the same order.
 *                 Named rather than implied: this is the user's undo when the workspace is not
 *                 in git, and a path they cannot see is a path they cannot use
 * @param skipped  files an edit named whose content already matched what it asked for. Reported
 *                 rather than silently dropped — "nothing to do" and "did it" are different
 *                 answers and the reader is entitled to know which one happened
 */
public record ApplyResult(List<String> written, List<String> backups, List<String> skipped) {}
