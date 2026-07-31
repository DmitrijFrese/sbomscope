package dev.sbomscope.probe;

/**
 * One attempt the search made, and what came of it.
 *
 * <p>This was a bare string until 2026-07-31 — one prose line per probe, appended to a flat
 * list. Readable, and unusable for anything else: the panel wanted to show each attempt beside
 * the result it contributed to, and there was no key tying sixteen lines to three ranked
 * candidates. The only way to recover one from the client was to parse the prose, which is
 * exactly the fragile inference this codebase keeps refusing.
 *
 * <p><b>The prose is kept verbatim in {@link #text}.</b> It is what the activity log records and
 * what the panel still renders, so structuring this changed no wording — it only added the two
 * fields that were previously locked inside the sentence.
 *
 * @param major     which major line this attempt belongs to, or <b>null</b> for the steps that
 *                  belong to no line: calibration, the initial feasibility probe, and the
 *                  combination fallback. Null is a real answer here rather than missing data —
 *                  those steps precede the per-major search and grouping them under one would
 *                  misattribute them
 * @param kind      what the attempt was for, so the reader can tell "we checked the model was
 *                  sound" from "we tried this version"
 * @param requested exactly what was asked of Maven, e.g. {@code [2.4.13]}
 * @param outcome   how it came out, in a form something other than a human can branch on
 * @param text      the line as it has always read
 */
public record ProbeStep(
        Long major,
        Kind kind,
        String requested,
        Outcome outcome,
        String text) {

    public enum Kind {
        /** Resolving the untouched module, to prove the model matches the SBOM before trusting it. */
        CALIBRATION,
        /** The opening {@code [current,)} probe, which belongs to no single major. */
        FEASIBILITY,
        /** One exact version on one major line. */
        CANDIDATE,
        /** Every declaring ancestor bumped at once — the coarse fallback. */
        COMBINATION
    }

    public enum Outcome {
        /** Resolved, and the archive knows nothing against the version it produced. */
        CLEAN,
        /** Resolved, and the target still carries advisories. */
        AFFECTED,
        /**
         * Nothing was learned — the target was absent from the tree, the archive could not be
         * consulted, or the resolution produced a pre-release we refuse to offer. Deliberately
         * distinct from {@link #AFFECTED}: "we did not find out" is not "we found a problem".
         */
        NOT_CHECKED,
        /** Maven itself failed. */
        FAILED,
        /** Succeeded and carries information rather than a verdict — calibration's own result. */
        INFO
    }

    static ProbeStep calibration(Outcome outcome, String text) {
        return new ProbeStep(null, Kind.CALIBRATION, null, outcome, text);
    }

    static ProbeStep combination(Outcome outcome, String requested, String text) {
        return new ProbeStep(null, Kind.COMBINATION, requested, outcome, text);
    }

    /** A per-version attempt; {@code major} is null only for the opening feasibility probe. */
    static ProbeStep attempt(Long major, String requested, Outcome outcome, String text) {
        return new ProbeStep(major, major == null ? Kind.FEASIBILITY : Kind.CANDIDATE,
                requested, outcome, text);
    }
}
