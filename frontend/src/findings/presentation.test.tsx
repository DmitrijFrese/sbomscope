import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import type { FindingRow } from '../api/client';
import { EpssCell, KevCell, formatEpssProbability, formatPercentile } from './presentation';

/**
 * How the two exploitation columns describe themselves.
 *
 * <p>The formatters are here because both ends of their range are dangerous: a probability
 * rounded up to 100% claims certainty that EPSS never asserts, and one rounded down to 0%
 * claims impossibility. The first of those shipped and was caught in the browser — 0.99945
 * rendered as "100%" — which is what this file exists to stop happening again.
 *
 * <p>The cells are here because an empty one has three different meanings and only two are
 * visible per row. Reading either as "this is not exploited" is the failure the whole column
 * shape was argued over.
 */

const base: FindingRow = {
  purl: 'pkg:maven/org.example/lib@1.0.0',
  coordinates: 'org.example:lib',
  group: 'org.example',
  name: 'lib',
  version: '1.0.0',
  root: false,
  scope: 'DIRECT',
  osvId: 'GHSA-aaaa-bbbb-cccc',
  cveId: 'CVE-2026-0001',
  summary: null,
  severityScore: 7.5,
  severityRating: 'HIGH',
  cvssVersion: 'CVSS_V3',
  cvssVector: null,
  fixedVersion: null,
  publishedAt: null,
  osvUrl: null,
  cveUrl: null,
  registryArtifactUrl: null,
  registryVersionUrl: null,
  kevListedOn: null,
  kevRansomware: false,
  epssScore: null,
  epssPercentile: null,
  kevUrl: null,
};

function row(overrides: Partial<FindingRow>): FindingRow {
  return { ...base, ...overrides };
}

describe('formatEpssProbability', () => {
  it('never rounds up to certainty', () => {
    // The bug this file was written for. toFixed(0) turned 0.99945 into "100%", stating
    // certainty about a probability that is not 1 — and EPSS never publishes 1.
    expect(formatEpssProbability(0.99945)).not.toBe('100%');
    expect(formatEpssProbability(0.99999)).not.toBe('100%');
    expect(formatEpssProbability(0.996)).not.toBe('100%');
    expect(formatEpssProbability(0.9951)).not.toBe('100%');
  });

  it('never rounds down to impossibility', () => {
    // The mirror failure: "0%" reads as "this will not happen".
    expect(formatEpssProbability(0.00001)).toBe('<0.1%');
    expect(formatEpssProbability(0.0004)).toBe('<0.1%');
    expect(formatEpssProbability(0)).toBe('<0.1%');
  });

  it('keeps a decimal where rounding would reach 100', () => {
    expect(formatEpssProbability(0.9927)).toBe('99.2%');
    expect(formatEpssProbability(0.99677)).toBe('99.6%');
    expect(formatEpssProbability(0.99999)).toBe('>99.9%');
  });

  it('drops the decimal in the middle of the range, where it says nothing', () => {
    expect(formatEpssProbability(0.5)).toBe('50%');
    expect(formatEpssProbability(0.104)).toBe('10%');
  });

  it('keeps one decimal for small values, which are most of the set', () => {
    expect(formatEpssProbability(0.03244)).toBe('3.2%');
    expect(formatEpssProbability(0.0558)).toBe('5.6%');
    expect(formatEpssProbability(0.0011)).toBe('0.1%');
  });
});

describe('formatPercentile', () => {
  it('reserves the top of the scale for the top of the scale', () => {
    // EPSS does publish an exact 1.0; anything below it must not claim that rank.
    expect(formatPercentile(1)).toBe('100th');
    expect(formatPercentile(0.99973)).toBe('>99th');
    expect(formatPercentile(0.9999)).toBe('>99th');
  });

  it('uses the ordinal that matches the number', () => {
    expect(formatPercentile(0.87)).toBe('87th');
    expect(formatPercentile(0.01)).toBe('1st');
    expect(formatPercentile(0.02)).toBe('2nd');
    expect(formatPercentile(0.03)).toBe('3rd');
    expect(formatPercentile(0.11)).toBe('11th');
    expect(formatPercentile(0.12)).toBe('12th');
    expect(formatPercentile(0.13)).toBe('13th');
    expect(formatPercentile(0.21)).toBe('21st');
  });
});

describe('KevCell', () => {
  it('says "not listed" rather than "no" for a CVE CISA does not list', () => {
    // KEV is a positive list. "No" would claim somebody established the flaw is not
    // exploited, which nobody did.
    render(<KevCell row={row({ cveId: 'CVE-2026-0001', kevListedOn: null })} />);

    expect(screen.getByText('not listed')).toBeTruthy();
    expect(screen.queryByText('No')).toBeNull();
  });

  it('distinguishes a finding with no CVE from one that is simply unlisted', () => {
    // The catalogue is keyed by CVE, so for these the question cannot be asked at all —
    // a different statement from "asked, not listed", and 3% of the Maven set.
    const { container } = render(<KevCell row={row({ cveId: null })} />);

    expect(container.textContent).toBe('—');
    expect(screen.queryByText('not listed')).toBeNull();
  });

  it('carries the date, because how long it has been known is the point', () => {
    render(<KevCell row={row({ kevListedOn: '2022-03-25', kevUrl: 'https://cisa.example/x' })} />);

    expect(screen.getByText('Exploited')).toBeTruthy();
    expect(screen.getByText('since 2022-03-25')).toBeTruthy();
  });

  it('links only when listed, so no cell points at an empty search', () => {
    const listed = render(
      <KevCell row={row({ kevListedOn: '2022-03-25', kevUrl: 'https://cisa.example/x' })} />,
    );
    expect(listed.container.querySelector('a')).not.toBeNull();

    const unlisted = render(<KevCell row={row({ kevListedOn: null })} />);
    expect(unlisted.container.querySelector('a')).toBeNull();
  });

  it('marks ransomware only when CISA confirmed it', () => {
    // Scoped to each render's own container rather than to the document: cleanup runs
    // between tests, not between two renders inside one, so a document-wide query for
    // "is this absent" would find the node rendered three lines earlier.
    const confirmed = render(
      <KevCell row={row({ kevListedOn: '2021-12-10', kevRansomware: true })} />,
    );
    expect(confirmed.container.textContent).toContain('ransomware');

    // 'Unknown' in the catalogue means no confirmation, not a denial — so the absence of the
    // mark must never be rendered as "no ransomware".
    const unconfirmed = render(
      <KevCell row={row({ kevListedOn: '2021-12-10', kevRansomware: false })} />,
    );
    expect(unconfirmed.container.textContent).not.toContain('ransomware');
  });
});

describe('EpssCell', () => {
  it('says "unscored" for a CVE EPSS does not cover', () => {
    render(<EpssCell row={row({ cveId: 'CVE-2026-0001', epssScore: null })} />);

    expect(screen.getByText('unscored')).toBeTruthy();
  });

  it('distinguishes that from a finding with no CVE to score', () => {
    const { container } = render(<EpssCell row={row({ cveId: null })} />);

    expect(container.textContent).toBe('—');
  });

  it('shows the percentile under the score, because either alone says less', () => {
    const { container } = render(
      <EpssCell row={row({ epssScore: 0.03244, epssPercentile: 0.87056 })} />,
    );

    expect(screen.getByText('3.2%')).toBeTruthy();
    // The word is spelled out: two bare numbers stacked in one cell both read as
    // probabilities, and nothing would tell the reader the second is a rank.
    expect(container.textContent).toContain('87th percentile');
  });

  it('says what the percentile is a percentile of, where there is room', () => {
    // Asked in use: "is the percentile a global number or local to my SBOM?" It is global —
    // straight from FIRST's file, a rank among every scored CVE — and the short form was being
    // read as a rank among the findings on screen. The card has the width to say so.
    const card = render(
      <EpssCell row={row({ epssScore: 0.44, epssPercentile: 0.99 })} detailed />,
    );
    expect(card.container.textContent).toContain('of all scored CVEs');

    // The table cell does not, and must not grow: it carries the same claim in its tooltip.
    const cell = render(<EpssCell row={row({ epssScore: 0.44, epssPercentile: 0.99 })} />);
    expect(cell.container.textContent).not.toContain('of all scored CVEs');
    expect(cell.container.querySelector('.epss__percentile')?.getAttribute('title')).toContain(
      'not a rank within this SBOM',
    );
  });

  it('shows the score alone when no percentile came with it', () => {
    const { container } = render(
      <EpssCell row={row({ epssScore: 0.5, epssPercentile: null })} />,
    );

    expect(container.textContent).toContain('50%');
  });
});
