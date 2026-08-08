package dev.sbomscope.sbom;

import java.util.Locale;

/**
 * What {@link FolderService#sort} orders one level's folders and documents by.
 *
 * <p>Direction is carried separately as a plain {@code boolean ascending}, matching
 * {@code FindingQuery.ascending} — a field and a direction are independent choices, and this
 * codebase already has one convention for the second half of that pair.
 */
public enum FolderSortField {

    /** Case-insensitive, matching {@code FolderRepository.siblingNameExists}. */
    NAME,

    /** A folder's {@code created_at}; a document's {@code uploaded_at}. */
    DATE;

    public static final FolderSortField DEFAULT = NAME;

    /**
     * Parses a submitted value, naming the fields that exist when it is not one of them.
     *
     * <p>Null and blank fall back to the default rather than failing, the same reasoning as
     * {@link RollupMode#parse}: a request omitting the field means "the ordinary sort", not a
     * rejected one.
     */
    public static FolderSortField parse(String raw) {
        if (raw == null || raw.isBlank()) {
            return DEFAULT;
        }
        try {
            return valueOf(raw.strip().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(
                    "\"%s\" is not a sort field. Expected NAME or DATE.".formatted(raw));
        }
    }
}
