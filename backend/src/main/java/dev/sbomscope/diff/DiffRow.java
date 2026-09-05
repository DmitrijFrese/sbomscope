package dev.sbomscope.diff;

import java.util.List;
import java.util.Map;

import dev.sbomscope.scanner.FindingQuery;

public record DiffRow(String coordinates, String group, String name,
                      Side left, Side right, Change change) {

    /**
     * @param cveIds       the advisory identifiers on this side — the CVE where one exists and
     *                     the OSV id where it does not, which is what the filter searches and
     *                     what the workbook prints
     * @param advisoryUrls where each of those identifiers points, keyed by the identifier. A
     *                     map rather than a second list, because two lists that must stay the
     *                     same length is a defect waiting for the first identifier with no
     *                     link. The destination differs by kind — a CVE goes to NVD, an
     *                     OSV-only advisory to osv.dev — and {@code AdvisoryLinks} is the one
     *                     statement of both, so the diff cannot point somewhere the findings
     *                     table does not
     */
    public record Side(String purl, String version,
                       Map<FindingQuery.SeverityBand, Integer> counts,
                       List<String> cveIds,
                       Map<String, String> advisoryUrls) {

        /**
         * For callers with no links to offer — the workbook never linked these identifiers,
         * because a spreadsheet cell takes one hyperlink and a diff cell holds several.
         */
        public Side(String purl, String version,
                    Map<FindingQuery.SeverityBand, Integer> counts, List<String> cveIds) {
            this(purl, version, counts, cveIds, Map.of());
        }
    }

    public enum Change {
        ADDED,
        REMOVED,
        VERSION_CHANGED,
        UNCHANGED
    }
}
