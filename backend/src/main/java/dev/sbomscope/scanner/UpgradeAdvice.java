package dev.sbomscope.scanner;

import java.math.BigDecimal;
import java.util.List;

import dev.sbomscope.sbom.DependencyScope;

/**
 * What to actually change about a vulnerable component, and where.
 *
 * <p>Deliberately not "which version should I move to". For most findings that question has
 * no answer, because <b>you cannot upgrade what you do not declare</b>: the advisory names a
 * fixed version, and the project's manifest has never mentioned the library. A remedy has to
 * name something the reader can put in a file.
 *
 * <p>Everything here is derived from data SBOMscope already holds — the advisories' own fix
 * versions and the dependency graph — so it works with no network and no lookups enabled.
 * What it therefore <em>cannot</em> say is stated rather than estimated: see
 * {@link #targetIsUnverified()}.
 *
 * @param pinTarget  the highest fix version named by the advisories against this component,
 *                   so one pin addresses all of them as each describes itself. Null when no
 *                   advisory names a fix at all
 * @param declaredBy the dependencies your own code declares that lead here — who to talk to
 *                   about a transitive finding, taken from the routes Phase 7 computed
 */
/**
 * @param targetEvaluated  the target was checked against the local archives. <b>Read this
 *                         before {@code targetAdvisories}</b>: an empty list means "clean"
 *                         only when this is true, and "not checked" otherwise — the same
 *                         distinction the scan table draws between no findings and never
 *                         looked, one level further in
 * @param targetAdvisories what the target version itself carries. Knowing 3.1.5 fixes
 *                         <em>this</em> advisory was never the same as knowing 3.1.5 is
 *                         clean, and until the local matcher existed the panel could only
 *                         say so rather than answer it
 */
public record UpgradeAdvice(
        String currentVersion,
        DependencyScope scope,
        String pinTarget,
        List<AdvisoryFix> advisories,
        List<String> declaredBy,
        List<Remedy> remedies,
        RemedyKind suggested,
        boolean targetEvaluated,
        List<OsvArchiveMatcher.AdvisoryHit> targetAdvisories) {

    /** One advisory against this component, and what it says fixes it. */
    public record AdvisoryFix(
            String osvId,
            String cveId,
            BigDecimal severityScore,
            /** Null when the advisory offers no fix on this component's branch. */
            String fixedVersion) {}

    public enum RemedyKind {

        /** Change the version in your own manifest. Only when you declare it. */
        UPGRADE,

        /**
         * Force a version you do not declare: Maven {@code dependencyManagement}, npm
         * {@code overrides}. Precise, paste-able, and independent of what the ancestor does.
         */
        PIN,

        /** Move the thing that pulls it in to a version that ships the fix. */
        BUMP_ANCESTOR,

        /** Remove it. Only ever safe when the code does not use it. */
        EXCLUDE
    }

    /**
     * @param available false when this remedy cannot be offered here, with {@code note}
     *                  saying why — an option greyed out for a stated reason is worth more
     *                  than one silently missing
     * @param clears    advisories whose own fix version this remedy reaches
     * @param leaves    advisories it cannot address, because they name no fix at all
     */
    public record Remedy(
            RemedyKind kind,
            boolean available,
            String target,
            String snippet,
            List<String> clears,
            List<String> leaves,
            String note) {}
}
