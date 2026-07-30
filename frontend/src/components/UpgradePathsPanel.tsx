import { useEffect, useRef, useState } from 'react';
import { Link } from 'react-router-dom';

import { REMEDY_LABELS, fetchBumpProgress, fetchUpgradeAdvice, startBump } from '../api/client';
import type { AdvisoryFix, AdvisoryHit, BumpCandidate, BumpProgress, BumpState, Remedy, UpgradeAdvice } from '../api/client';
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

interface AdvisoryRow {
  osvId: string;
  cveId: string | null;
  band: string;
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
          {rows.map((row) => (
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

/**
 * One major line's ranked answer: a label, the version verified, and whatever it still
 * carries — a count by severity first, the full list (CVE-linked where one exists) one click
 * away, since "clears 3 of 4" alone cannot be acted on.
 */
function BumpCandidateRow({ candidate }: { candidate: BumpCandidate }) {
  return (
    <tr>
      <td>{candidate.label}</td>
      <td className="mono">{candidate.probed ? candidate.version : '—'}</td>
      <td>
        {!candidate.probed && <span className="panel__hint">not probed</span>}
        {candidate.probed && candidate.clean && <span className="badge">clean</span>}
        {candidate.probed && !candidate.clean && (
          <span className={candidate.clearsCriticalAndHigh ? 'badge' : 'badge badge--warn'}>
            {candidate.clearsCriticalAndHigh ? 'clears critical/high' : 'still critical/high'}
          </span>
        )}
      </td>
      <td>
        <AdvisorySummary verb="Carries" rows={rowsFromHits(candidate.stillCarries)} />
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
function BumpCandidateTable({ candidates }: { candidates: BumpCandidate[] }) {
  return (
    <div className="table-scroll">
      <table className="data-table">
        <thead>
          <tr>
            <th scope="col">Option</th>
            <th scope="col">Version</th>
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

  async function check() {
    setChecking(true);
    try {
      const current = await startBump(sbomId, purl);
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

  // A completed probe reports ranked candidates and/or a remedy (the combination result, or a
  // failure). Before that, the static Tier-1 placeholder is shown — it is always unavailable,
  // since Tier 1 can only explain why this remedy needs a probe, never compute it.
  const completed = progress?.state === 'COMPLETED';
  const candidates = completed ? progress.candidates : [];
  const completionRemedy = completed ? progress.remedy : null;
  const hasResult = candidates.length > 0 || completionRemedy !== null;
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

      {candidates.length > 0 && <BumpCandidateTable candidates={candidates} />}

      {completionRemedy && (
        <>
          {completionRemedy.note && <p className="remedy__note">{completionRemedy.note}</p>}
          {completionRemedy.snippet && <Snippet code={completionRemedy.snippet} />}
          {completionRemedy.available && (
            <AdvisorySummary verb="Clears" rows={rowsFromIds(completionRemedy.clears, advisories)} />
          )}
        </>
      )}

      {checkable && !progress && (
        <p>
          <button type="button" className="button button--small" onClick={check} disabled={checking}>
            {checking ? 'Checking…' : 'Check for a bump'}
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
