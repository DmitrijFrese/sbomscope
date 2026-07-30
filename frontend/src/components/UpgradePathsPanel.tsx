import { useEffect, useRef, useState } from 'react';
import { Link } from 'react-router-dom';

import { REMEDY_LABELS, continueBump, fetchBumpProgress, fetchUpgradeAdvice, startBump } from '../api/client';
import type { AdvisoryFix, AdvisoryHit, BumpCandidate, BumpProgress, BumpScope, BumpState, Remedy, UpgradeAdvice } from '../api/client';
import { bandOf, BAND_LABELS } from '../findings/presentation';

const BUMP_POLL_INTERVAL_MS = 1500;

/** QUEUED and RUNNING both mean "keep polling, nothing to act on yet" — the single background
 *  thread that runs every probe serialises them, so a queued one has not started. */
function inFlight(state: BumpState): boolean {
  return state === 'RUNNING' || state === 'QUEUED';
}

/** A band a reader can compare across sources — the CVSS scale and GHSA's own scale differ
 *  in name (MEDIUM vs MODERATE), so both are recognised rather than only one. */
const BAND_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'MODERATE', 'LOW', 'UNSCORED', 'UNRATED'];

/** The severity styling is keyed on the CVSS band names, so GHSA's MODERATE maps onto medium
 *  rather than getting a colour of its own for the same level. */
const BAND_STYLE: Record<string, string> = {
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  MODERATE: 'medium',
  LOW: 'low',
  UNSCORED: 'none',
  UNRATED: 'none',
};

const BAND_TEXT: Record<string, string> = {
  CRITICAL: 'Critical',
  HIGH: 'High',
  MEDIUM: 'Medium',
  MODERATE: 'Moderate',
  LOW: 'Low',
  UNSCORED: 'unscored',
  UNRATED: 'unrated',
};

interface AdvisoryRow {
  osvId: string;
  cveId: string | null;
  band: string;
}

/** Worst first. Anything whose band is not recognised sorts last rather than silently
 *  ranking as the least severe thing present. */
function bySeverity(rows: AdvisoryRow[]): AdvisoryRow[] {
  const rank = (band: string) => {
    const index = BAND_ORDER.indexOf(band);
    return index < 0 ? BAND_ORDER.length : index;
  };
  return [...rows].sort((a, b) => rank(a.band) - rank(b.band));
}

/**
 * Mirrors the backend's {@code AdvisoryLinks} — the same two destinations, derived from the
 * identifier alone, so no API round trip is needed just to link a row.
 */
function advisoryUrl(row: AdvisoryRow): string {
  return row.cveId
    ? `https://nvd.nist.gov/vuln/detail/${row.cveId}`
    : `https://osv.dev/vulnerability/${row.osvId}`;
}

function rowsFromHits(hits: AdvisoryHit[]): AdvisoryRow[] {
  return hits.map((hit) => ({ osvId: hit.osvId, cveId: hit.cveId, band: hit.rating ?? 'UNRATED' }));
}

/** {@code Remedy.clears}/{@code leaves} are bare OSV IDs; the CVE and severity come from the
 *  same {@code advisories} list the page already fetched, looked up rather than re-sent. */
function rowsFromIds(ids: string[], advisories: AdvisoryFix[]): AdvisoryRow[] {
  const byId = new Map(advisories.map((advisory) => [advisory.osvId, advisory]));
  return ids.map((osvId) => {
    const match = byId.get(osvId);
    const band = match?.severityScore == null ? 'UNSCORED' : bandOf(match.severityScore).toUpperCase();
    return { osvId, cveId: match?.cveId ?? null, band };
  });
}

function Snippet({ code }: { code: string }) {
  return (
    <pre className="snippet">
      <code>{code}</code>
    </pre>
  );
}

/**
 * A count by severity band, with the full list — CVE-linked where one exists, OSV-linked
 * otherwise — behind a details toggle. Never only a count: "clears 3 of 4" cannot be acted on,
 * so the specific advisories stay one click away rather than gone.
 */
function AdvisorySummary({
  rows,
  verb,
  suffix,
  tone,
}: {
  rows: AdvisoryRow[];
  verb: string;
  /** Trailing clarification, e.g. "no fix named" — kept singular/plural-neutral on purpose. */
  suffix?: string;
  tone?: 'left';
}) {
  const [expanded, setExpanded] = useState(false);
  if (rows.length === 0) return null;

  // Sorted here rather than at each call site, so every list of advisories in this panel —
  // the bump rows, both remedy cards, the target's own notice — reads worst first. The order
  // the backend happened to return them in is an implementation detail of a lookup, not a
  // ranking, and the first thing anyone wants from such a list is its worst entry.
  const ordered = bySeverity(rows);

  const counts = new Map<string, number>();
  for (const row of rows) {
    counts.set(row.band, (counts.get(row.band) ?? 0) + 1);
  }
  const summary = BAND_ORDER.filter((band) => counts.has(band))
    .map((band) => `${counts.get(band)} ${band.toLowerCase()}`)
    .join(', ');

  return (
    <div>
      <p className={tone === 'left' ? 'remedy__effect remedy__effect--left' : 'remedy__effect'}>
        {verb} {rows.length} {rows.length === 1 ? 'advisory' : 'advisories'}
        {summary && ` (${summary})`}
        {suffix && ` — ${suffix}`}.{' '}
        <button type="button" className="button button--small" onClick={() => setExpanded((v) => !v)}>
          {expanded ? 'Hide details' : 'Details'}
        </button>
      </p>
      {expanded && (
        <ul className="target-advisories">
          {ordered.map((row) => (
            <li key={row.osvId}>
              <a href={advisoryUrl(row)} target="_blank" rel="noreferrer" className="mono">
                {row.cveId ?? row.osvId}
              </a>
              <span className="badge"> {row.band}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

/**
 * One remedy, offered or explained away.
 *
 * <p>An unavailable option is shown with its reason rather than hidden. "You do not declare
 * this dependency" is itself the useful part of the answer — it is why the obvious remedy is
 * not the right one, and a reader who cannot see the option cannot learn that.
 */
function RemedyCard({
  remedy,
  suggested,
  advisories,
}: {
  remedy: Remedy;
  suggested: boolean;
  advisories: AdvisoryFix[];
}) {
  return (
    <section className="remedy" data-available={remedy.available} data-suggested={suggested}>
      <h3 className="remedy__title">
        {REMEDY_LABELS[remedy.kind]}
        {suggested && <span className="badge badge--suggested">suggested</span>}
        {remedy.target && remedy.available && (
          <span className="remedy__target mono">{remedy.target}</span>
        )}
      </h3>

      {remedy.note && <p className="remedy__note">{remedy.note}</p>}

      {remedy.snippet && <Snippet code={remedy.snippet} />}

      {remedy.available && (
        <AdvisorySummary verb="Clears" rows={rowsFromIds(remedy.clears, advisories)} />
      )}

      <AdvisorySummary
        verb="Leaves"
        suffix="no fix named"
        rows={rowsFromIds(remedy.leaves, advisories)}
        tone="left"
      />
    </section>
  );
}

/** The highest severity a candidate leaves behind, in the same chip the findings table uses. */
function WorstRemaining({ hits }: { hits: AdvisoryHit[] }) {
  const worst = bySeverity(rowsFromHits(hits))[0];
  if (!worst) return null;
  return (
    <span className="severity" data-band={BAND_STYLE[worst.band] ?? 'none'}>
      <span className="severity__label">{BAND_TEXT[worst.band] ?? worst.band.toLowerCase()}</span>
    </span>
  );
}

/**
 * One major line's ranked answer: a label, the version verified, and whatever it still
 * carries — a count by severity first, the full list (CVE-linked where one exists) one click
 * away, since "clears 3 of 4" alone cannot be acted on.
 */
function BumpCandidateRow({ candidate }: { candidate: BumpCandidate }) {
  return (
    <tr>
      <td>{candidate.label}</td>
      <td className="mono">
        {candidate.probed ? candidate.version : '—'}
        {/* Qualifies the version itself, because the version is what would otherwise be
            misread: it looks like this major's highest when it is only where we stopped. */}
        {candidate.higherReleasesUnchecked && <span className="badge badge--warn">checked up to here</span>}
      </td>
      <td>
        {!candidate.probed && <span className="panel__hint">not probed</span>}
        {candidate.probed && candidate.clean && <span className="badge">clean</span>}
        {/* The worst band left, stated plainly. It replaces a critical/high binary and is
            both more informative and one concept fewer — "Moderate" already says critical and
            high are gone. Derived from the same array the cell beside it lists, so the two
            cannot disagree. An unrated advisory reads as unrated, never as clean: that is the
            NONE-versus-CLEAN rule, one level further down. */}
        {candidate.probed && !candidate.clean && <WorstRemaining hits={candidate.stillCarries} />}
      </td>
      <td>
        <AdvisorySummary verb="Carries" rows={rowsFromHits(candidate.stillCarries)} />
        {candidate.higherReleasesUnchecked && (
          <p className="panel__hint">
            The run budget ran out partway through {candidate.major}.x, so releases above{' '}
            <span className="mono">{candidate.version}</span> were not checked — one of them may
            well be clean.
          </p>
        )}
      </td>
      <td>{candidate.probed && candidate.clean && candidate.snippet && <Snippet code={candidate.snippet} />}</td>
    </tr>
  );
}

/**
 * Ranked candidates for the primary declaring ancestor, one row per major line — Tier 1's own
 * "candidates, not a recommendation" shape, extended here because no single verdict can claim
 * to be the earliest without checking every major. A later major being affected does not prove
 * an earlier one is not clean, so every reachable major gets a row rather than the search
 * stopping at the first one that works.
 */
/**
 * What the rows below are an answer about: which library is being bumped, and where the answer
 * holds. Both were previously decided in silence — the panel showed a version with no
 * indication of what it was a version *of*, and named neither the module nor the competing
 * declarations that make the choice non-obvious.
 */
function BumpScopeCaption({ scope }: { scope: BumpScope }) {
  return (
    <div className="bump-scope">
      <p className="bump-scope__line">
        Bumping <span className="mono">{scope.ancestor}</span>
        {scope.ancestorVersion && (
          <>
            , currently <span className="mono">{scope.ancestorVersion}</span>
          </>
        )}
        {scope.module && (
          <>
            , in <span className="mono">{scope.module}</span>
          </>
        )}
        .
      </p>

      {/* The sentence that turns an inexplicable "still affected" into an understandable one.
          Maven resolves through one declaration; bumping any of the others moves nothing, and
          without saying so the reader reads that result as "upstream has not fixed it". */}
      {scope.otherAncestors.length > 0 && (
        <p className="panel__hint">
          {scope.otherAncestors.length === 1 ? 'It is also pulled in by ' : 'It is also pulled in by '}
          {scope.otherAncestors.map((other, index) => (
            <span key={other}>
              {index > 0 && ', '}
              <span className="mono">{other}</span>
            </span>
          ))}
          .{' '}
          {scope.decidedByMaven
            ? `Maven resolves it through ${scope.ancestor} (nearest wins), so bumping ${
                scope.otherAncestors.length === 1 ? 'that one' : 'those'
              } alone would not move it.`
            : `Which declaration Maven honours could not be read from the resolved tree, so this
               ranks the shortest route rather than the proven winner — treat it as the likely
               one, not the verified one.`}
        </p>
      )}

      {scope.otherModules.length > 0 && (
        <p className="panel__hint">
          Verified against <span className="mono">{scope.module}</span> only.{' '}
          {scope.otherModules.map((other, index) => (
            <span key={other}>
              {index > 0 && ', '}
              <span className="mono">{other}</span>
            </span>
          ))}{' '}
          also {scope.otherModules.length === 1 ? 'pulls' : 'pull'} this in and{' '}
          {scope.otherModules.length === 1 ? 'was' : 'were'} not probed — their direct sets
          differ, so their answer may too.
        </p>
      )}
    </div>
  );
}

function BumpCandidateTable({ candidates, scope }: { candidates: BumpCandidate[]; scope: BumpScope | null }) {
  return (
    <div className="table-scroll">
      {scope && <BumpScopeCaption scope={scope} />}
      <table className="data-table">
        <thead>
          <tr>
            <th scope="col">Option</th>
            {/* Reads as a sentence with the caption above: "Bumping keycloak-core … Bump to 9.0.3". */}
            <th scope="col">Bump to</th>
            <th scope="col">Status</th>
            <th scope="col">Still carries</th>
            <th scope="col">Snippet</th>
          </tr>
        </thead>
        <tbody>
          {candidates.map((candidate) => (
            <BumpCandidateRow key={candidate.major} candidate={candidate} />
          ))}
        </tbody>
      </table>
    </div>
  );
}

/**
 * The {@code BUMP_ANCESTOR} remedy, specialised: it is the one remedy Tier 1 can only explain
 * away, never compute — answering it needs a real external process that can take real time,
 * which is why this drives {@code /component/bump} (start, then poll) rather than reading a
 * field already present in {@link UpgradeAdvice}.
 *
 * <p>A completed probe reports ranked candidates, one per major line, rather than a single
 * verdict — a later major being affected does not prove an earlier one is not clean. {@code
 * remedy} only appears alongside them for the multi-ancestor combination result, or in place of
 * them for an outright failure; the static Tier-1 placeholder shows until a probe is started.
 */
function BumpAncestorCard({
  sbomId,
  purl,
  remedy,
  suggested,
  checkable,
  advisories,
}: {
  sbomId: string;
  purl: string;
  remedy: Remedy;
  suggested: boolean;
  checkable: boolean;
  advisories: AdvisoryFix[];
}) {
  const [progress, setProgress] = useState<BumpProgress | null>(null);
  const [checking, setChecking] = useState(false);
  const pollTimer = useRef<number | null>(null);

  useEffect(() => {
    let cancelled = false;
    setProgress(null);
    setChecking(false);

    // The backend keeps a probe's progress for the process lifetime, keyed by (module,
    // target) — navigating away and back (e.g. to the Activity log) must not throw that
    // away and show "Check for a bump" again for one already running or finished.
    fetchBumpProgress(sbomId, purl)
      .then((current) => {
        if (cancelled || current.state === 'IDLE') return;
        setProgress(current);
        if (inFlight(current.state)) {
          setChecking(true);
          pollUntilDone();
        }
      })
      .catch(() => {
        // No cached progress to hydrate from; the "Check for a bump" button covers this.
      });

    return () => {
      cancelled = true;
      if (pollTimer.current !== null) window.clearTimeout(pollTimer.current);
    };
  }, [sbomId, purl]);

  function pollUntilDone() {
    pollTimer.current = window.setTimeout(async () => {
      try {
        const current = await fetchBumpProgress(sbomId, purl);
        setProgress(current);
        if (inFlight(current.state)) {
          pollUntilDone();
        } else {
          setChecking(false);
        }
      } catch {
        setChecking(false);
      }
    }, BUMP_POLL_INTERVAL_MS);
  }

  async function run(start: () => Promise<BumpProgress>) {
    setChecking(true);
    try {
      const current = await start();
      setProgress(current);
      if (inFlight(current.state)) {
        pollUntilDone();
      } else {
        setChecking(false);
      }
    } catch {
      setChecking(false);
    }
  }

  const check = () => run(() => startBump(sbomId, purl));
  const resume = () => run(() => continueBump(sbomId, purl));

  // A completed probe reports ranked candidates and/or a remedy (the combination result, or a
  // failure). Before that, the static Tier-1 placeholder is shown — it is always unavailable,
  // since Tier 1 can only explain why this remedy needs a probe, never compute it.
  const completed = progress?.state === 'COMPLETED';
  const candidates = completed ? progress.candidates : [];
  const completionRemedy = completed ? progress.remedy : null;
  const hasResult = candidates.length > 0 || completionRemedy !== null;
  // Nothing running, and nothing the reader can act on: either it never started (no button
  // pressed yet), it was refused outright, or it completed without ranking a single version.
  const retryable =
    !progress || progress.state === 'FAILED' || (completed && candidates.length === 0);
  const dataAvailable = hasResult
    ? candidates.some((candidate) => candidate.clean) || completionRemedy?.available === true
    : remedy.available;

  return (
    <section className="remedy" data-available={dataAvailable} data-suggested={suggested && dataAvailable}>
      <h3 className="remedy__title">
        {REMEDY_LABELS.BUMP_ANCESTOR}
        {suggested && dataAvailable && <span className="badge badge--suggested">suggested</span>}
      </h3>

      {!hasResult && remedy.note && <p className="remedy__note">{remedy.note}</p>}

      {candidates.length > 0 && (
        <BumpCandidateTable candidates={candidates} scope={progress?.scope ?? null} />
      )}

      {/* Only where the search actually left something unfinished — a run that settled every
          major has nothing to continue, and offering it anyway would imply otherwise. */}
      {completed && candidates.some((candidate) => !candidate.probed || candidate.higherReleasesUnchecked) && (
        <p>
          <button type="button" className="button button--small" onClick={resume} disabled={checking}>
            {checking ? 'Checking…' : 'Continue the search'}
          </button>{' '}
          <span className="panel__hint">
            Spends another {' '}
            <Link to="/settings#settings-maven">budget's worth</Link> on the majors above, keeping
            what is already answered.
          </span>
        </p>
      )}

      {completionRemedy && (
        <>
          {completionRemedy.note && <p className="remedy__note">{completionRemedy.note}</p>}
          {completionRemedy.snippet && <Snippet code={completionRemedy.snippet} />}
          {completionRemedy.available && (
            <AdvisorySummary verb="Clears" rows={rowsFromIds(completionRemedy.clears, advisories)} />
          )}
        </>
      )}

      {/* Also offered after a failure, and after a run that produced no rows at all. Both were
          dead ends: the panel hid the button as soon as any result existed, so someone who
          followed the Settings link, configured Maven and came back had no way to ask again
          without restarting the application. A result the reader cannot act on is exactly when
          they most need to retry. */}
      {checkable && retryable && (
        <p>
          <button
            type="button"
            className="button button--small"
            onClick={progress ? resume : check}
            disabled={checking}
          >
            {checking ? 'Checking…' : progress ? 'Try again' : 'Check for a bump'}
          </button>{' '}
          <Link to="/settings#settings-maven">Maven settings</Link>
        </p>
      )}

      {progress?.state === 'QUEUED' && (
        <p className="panel__hint" role="status">
          {progress.message}
        </p>
      )}

      {progress?.state === 'RUNNING' && (
        <p className="panel__hint" role="status">
          Probing your own Maven…
        </p>
      )}

      {progress?.state === 'FAILED' && (
        <p className="form-error" role="alert">
          {progress.message}
        </p>
      )}

      {/* A completed run carries a message only when it is shorter than a full one — today
          that means it was stopped from Monitoring. Without this the run would look like an
          ordinary completion, and "no candidates" would read as "nothing works" rather than
          as "nobody looked". */}
      {completed && progress.message && (
        <p className="notice notice--warn" role="status">
          {progress.message}
        </p>
      )}

      {progress && progress.verdicts.length > 0 && (
        <ul className="target-advisories">
          {progress.verdicts.map((verdict, index) => (
            <li key={index} className="mono">
              {verdict}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

/**
 * What to change about this component, and where.
 *
 * <p>Not "which version should I move to". For a library you do not declare that question
 * has no usable answer, so the panel leads with the remedies and treats the version as one
 * input to them.
 */
export function UpgradePathsPanel({ sbomId, purl }: { sbomId: string; purl: string }) {
  const [advice, setAdvice] = useState<UpgradeAdvice | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);

    fetchUpgradeAdvice(sbomId, purl)
      .then((result) => {
        if (!cancelled) setAdvice(result);
      })
      .catch((e: unknown) => {
        if (!cancelled) {
          setAdvice(null);
          setError(e instanceof Error ? e.message : 'Could not work out an upgrade path.');
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [sbomId, purl]);

  if (loading) return <p>Loading…</p>;
  if (error) {
    return (
      <p className="form-error" role="alert">
        {error}
      </p>
    );
  }
  if (!advice) return null;

  if (advice.advisories.length === 0) {
    return (
      <p className="panel__hint">
        Nothing is known against this component, so there is nothing to remedy.
      </p>
    );
  }

  return (
    <>
      <section>
        <h2 className="panel__title">What the advisories say fixes this</h2>
        {/* Capped rather than left to grow with the finding count — a heavily-vulnerable
            library can carry dozens, and the verdict below must stay visible without
            scrolling past all of them to reach it. */}
        <div className="fixlist-scroll">
          <ul className="fixlist">
            {advice.advisories.map((advisory) => {
              const band = advisory.severityScore === null ? 'none' : bandOf(advisory.severityScore);
              return (
                <li key={advisory.osvId} className="fixlist__row">
                  <span className="severity" data-band={band}>
                    <strong>
                      {advisory.severityScore === null ? '?' : advisory.severityScore.toFixed(1)}
                    </strong>
                    <span className="severity__label">
                      {advisory.severityScore === null ? 'unscored' : BAND_LABELS[band]}
                    </span>
                  </span>
                  <span className="mono">{advisory.osvId}</span>
                  <span className="fixlist__fix mono">
                    {advisory.fixedVersion ? `fixed in ${advisory.fixedVersion}` : 'no fix offered'}
                  </span>
                </li>
              );
            })}
          </ul>
        </div>

        {advice.declaredBy.length > 0 && (
          <p className="panel__hint">
            Pulled in by {advice.declaredBy.join(', ')} — that is who declares it, and who to
            ask about it.
          </p>
        )}

        {/* What the target itself carries, checked against the local archives. The three
            states are kept apart deliberately: carries something, checked and clean, and
            nobody looked — the last of which must never render as the second. */}
        {advice.pinTarget && !advice.targetEvaluated && (
          <p className="notice">
            <strong>{advice.pinTarget}</strong> clears the advisories that named it. Whether
            it carries advisories of its own could not be checked — no OSV archive for this
            ecosystem is downloaded.
          </p>
        )}

        {advice.pinTarget && advice.targetEvaluated && advice.targetAdvisories.length === 0 && (
          <p className="notice notice--ok">
            <strong>{advice.pinTarget}</strong> has nothing known against it in the offline
            database. Whether a newer release exists still needs a registry lookup.
          </p>
        )}

        {advice.targetEvaluated && advice.targetAdvisories.length > 0 && (
          <div className="notice notice--warn">
            <strong>{advice.pinTarget}</strong> carries advisories of its own:
            <AdvisorySummary verb="Carries" rows={rowsFromHits(advice.targetAdvisories)} />
            Moving there trades one problem for another.
          </div>
        )}
      </section>

      <section className="remedies">
        <h2 className="panel__title">Remedies</h2>
        {advice.remedies.map((remedy) =>
          remedy.kind === 'BUMP_ANCESTOR' ? (
            <BumpAncestorCard
              key={remedy.kind}
              sbomId={sbomId}
              purl={purl}
              remedy={remedy}
              suggested={advice.suggested === remedy.kind}
              checkable={advice.scope === 'TRANSITIVE' && advice.declaredBy.length > 0}
              advisories={advice.advisories}
            />
          ) : (
            <RemedyCard
              key={remedy.kind}
              remedy={remedy}
              suggested={advice.suggested === remedy.kind}
              advisories={advice.advisories}
            />
          ),
        )}
      </section>
    </>
  );
}
