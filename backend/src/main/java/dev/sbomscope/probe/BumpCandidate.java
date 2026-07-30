package dev.sbomscope.probe;

import java.util.List;

import dev.sbomscope.scanner.OsvArchiveMatcher.AdvisoryHit;

/**
 * One major line's answer to "what's the best version here, and what does it still carry" —
 * Tier 1's own "candidates, not a recommendation" shape, extended to Tier 2. One row per major
 * from the currently-declared one up to the latest that exists, never a single winner: the
 * feasibility probe being affected does not prove no earlier release is clean (the same
 * non-monotonicity this design already refuses to bisect past), so every major is looked at
 * rather than the search stopping at the first one that works.
 *
 * @param label                e.g. "Stay on 2.x", "Move to 3.x", "Move to 4.x (latest)"
 * @param ancestorCoordinates  which declaring ancestor this row bumps — every row from one
 *                             probe run shares it, since ranking is scoped to the primary
 *                             ancestor only
 * @param version              the version probed for this major, or null when {@code probed}
 *                             is false
 * @param targetVersion        the target's resolved version at that candidate, or null when
 *                             not probed, or when the target was absent from the resolved tree
 * @param probed               false when the run budget was exhausted before this major was
 *                             reached — reported honestly rather than implying "no fix" for a
 *                             major that was never checked
 * @param clean                true when nothing is known against {@code targetVersion} at all
 * @param clearsCriticalAndHigh true when nothing CRITICAL or HIGH remains, even if lower-rated
 *                              advisories do — the bar an upgrade is usually judged against
 * @param stillCarries         the advisories remaining at {@code targetVersion}, with their
 *                             GHSA ratings — never a count, since which one remains is the
 *                             decision this project keeps designing around
 * @param snippet              a paste-able dependency block for {@code version}, or null when
 *                             not probed
 * @param higherReleasesUnchecked true when the run budget ran out partway through this major,
 *                             leaving higher releases within it never looked at. Without this,
 *                             a row reading <em>"highest is 2.7.18, still carries X"</em> is
 *                             indistinguishable from <em>"we got as far as 2.7.18 and
 *                             stopped"</em> — the first claims every 2.x was checked, the
 *                             second claims nothing about the ones above. That is the same
 *                             unproven-versus-disproven distinction the feasibility
 *                             short-circuit was removed for, one level down; a reader deciding
 *                             not to stay on 2.x deserves to know which of the two they are
 *                             looking at. Never true where the walk stopped because it found
 *                             its earliest clean release: ascending order makes that a complete
 *                             answer, since nothing above it would be preferred anyway.
 */
public record BumpCandidate(
        String label,
        String ancestorCoordinates,
        long major,
        String version,
        String targetVersion,
        boolean probed,
        boolean clean,
        boolean clearsCriticalAndHigh,
        List<AdvisoryHit> stillCarries,
        String snippet,
        boolean higherReleasesUnchecked) {

    static BumpCandidate notProbed(String label, String ancestorCoordinates, long major) {
        return new BumpCandidate(
                label, ancestorCoordinates, major, null, null, false, false, false, List.of(), null, false);
    }
}
