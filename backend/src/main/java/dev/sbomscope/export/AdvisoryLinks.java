package dev.sbomscope.export;

/**
 * Where an advisory identifier points.
 *
 * <p>The two destinations are deliberately different. The OSV record carries the affected
 * version ranges and ecosystem detail that made the finding, and NVD carries the canonical
 * CVE description — pointing both columns at the same page would waste one of them.
 *
 * <p>Built here rather than at each call site so the table and the spreadsheet cannot drift
 * apart, which is the same reason component registry links live in {@link RegistryLinks}.
 */
public final class AdvisoryLinks {

    private AdvisoryLinks() {}

    /** The advisory's own record, whatever database it came from. */
    public static String osvUrl(String osvId) {
        return isBlank(osvId) ? null : "https://osv.dev/vulnerability/" + osvId;
    }

    /**
     * Derived from the identifier alone, which is why SBOMscope needs no NVD API key —
     * and why dropping that API cost nothing here.
     */
    public static String cveUrl(String cveId) {
        return isBlank(cveId) ? null : "https://nvd.nist.gov/vuln/detail/" + cveId;
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
