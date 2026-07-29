import { useEffect, useState } from 'react';

import { REMEDY_LABELS, fetchUpgradeAdvice } from '../api/client';
import type { Remedy, UpgradeAdvice } from '../api/client';
import { bandOf, BAND_LABELS } from '../findings/presentation';

function Snippet({ code }: { code: string }) {
  return (
    <pre className="snippet">
      <code>{code}</code>
    </pre>
  );
}

/**
 * One remedy, offered or explained away.
 *
 * <p>An unavailable option is shown with its reason rather than hidden. "You do not declare
 * this dependency" is itself the useful part of the answer — it is why the obvious remedy is
 * not the right one, and a reader who cannot see the option cannot learn that.
 */
function RemedyCard({ remedy, suggested }: { remedy: Remedy; suggested: boolean }) {
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

      {remedy.available && remedy.clears.length > 0 && (
        <p className="remedy__effect">
          Clears {remedy.clears.length}{' '}
          {remedy.clears.length === 1 ? 'advisory' : 'advisories'}: {remedy.clears.join(', ')}.
        </p>
      )}

      {remedy.leaves.length > 0 && (
        <p className="remedy__effect remedy__effect--left">
          Leaves {remedy.leaves.join(', ')} — {remedy.leaves.length === 1 ? 'it names' : 'they name'}{' '}
          no fix at all.
        </p>
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
            <strong>{advice.pinTarget}</strong> carries{' '}
            {advice.targetAdvisories.length}{' '}
            {advice.targetAdvisories.length === 1 ? 'advisory' : 'advisories'} of its own:
            <ul className="target-advisories">
              {advice.targetAdvisories.map((hit) => (
                <li key={hit.osvId}>
                  <span className="mono">{hit.osvId}</span>
                  {hit.cveId && <span className="mono"> · {hit.cveId}</span>}
                  {/* GHSA's own scale, not a CVSS band — the two are different claims and
                      this project keeps them in separate columns everywhere else. */}
                  {hit.rating && <span className="badge"> {hit.rating}</span>}
                </li>
              ))}
            </ul>
            Moving there trades one problem for another.
          </div>
        )}
      </section>

      <section className="remedies">
        <h2 className="panel__title">Remedies</h2>
        {advice.remedies.map((remedy) => (
          <RemedyCard
            key={remedy.kind}
            remedy={remedy}
            suggested={advice.suggested === remedy.kind}
          />
        ))}
      </section>
    </>
  );
}
