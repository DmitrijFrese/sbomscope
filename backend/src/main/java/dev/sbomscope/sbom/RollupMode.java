package dev.sbomscope.sbom;

import java.util.Locale;

/**
 * How a folder contributes its documents' severity counts to its own row and to its ancestors'
 * (B19, V11).
 *
 * <p><b>The rollup is a sum, and a sum is only sound over disjoint things.</b> A project holding
 * three modules is disjoint; a folder holding five versions of one product is not, and summing
 * it reports the same product five times. The mode is therefore a statement about what the
 * documents beneath a folder <i>are</i>, made once per folder by the reader.
 *
 * <p>It is deliberately never inferred. Deciding that five documents are versions of each other
 * would mean parsing filenames or root-component versions and guessing — this codebase carries
 * exactly one heuristic on purpose ({@code ScopeClassifier}) and says so.
 */
public enum RollupMode {

    /** Separate things: add every document beneath this folder up. The default, and V9's behaviour. */
    SUM,

    /**
     * Versions of one thing: contribute exactly one document, the first in this folder's own
     * display order.
     *
     * <p>Which is the newest upload until the reader drags another to the top, since a new or
     * moved document takes {@code MIN(sort_order) - 1}. Chosen over "greatest uploaded_at"
     * because that is invisible on screen and wrong when somebody backfills an older SBOM, and
     * over parsing a version out of the filename because that is a heuristic.
     */
    CURRENT,

    /**
     * Archived or scratch material: contribute nothing, here or upward.
     *
     * <p>The row states that it is not counted rather than rendering empty. A folder with 146
     * High findings beneath it and a blank severity area is the {@code NONE}-versus-{@code CLEAN}
     * failure one level out — "not counted" and "nothing found" must not look alike.
     */
    MUTED;

    /** The mode a folder has when nothing has said otherwise. */
    public static final RollupMode DEFAULT = SUM;

    /**
     * Parses a stored or submitted value, naming the mode that was not recognised.
     *
     * <p>Null and blank fall back to the default rather than failing: the column is only NOT
     * NULL from V11 onward, and a request omitting the field means "leave it alone" at the
     * service boundary, not "reject this".
     */
    public static RollupMode parse(String raw) {
        if (raw == null || raw.isBlank()) {
            return DEFAULT;
        }
        try {
            return valueOf(raw.strip().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(
                    "\"%s\" is not a rollup mode. Expected one of SUM, CURRENT or MUTED."
                            .formatted(raw));
        }
    }
}
