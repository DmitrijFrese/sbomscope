import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { ApiError } from '../api/client';
import type { DiffResult, DiffRow, Sbom } from '../api/client';
import type { DiffRun } from '../sboms/SbomProvider';
import { DiffPage, FindingDeltaCell, findingDelta } from './DiffPage';

const fetchDiffMock = vi.hoisted(() => vi.fn());
let diffSelection: { left: Sbom | null; right: Sbom | null };

/**
 * The comparison the session is holding when the page mounts.
 *
 * <p>The real value lives in `SbomProvider`, above the router, so that leaving the page and
 * coming back does not discard it. What this file can check is the half that belongs to the
 * page: that a finished comparison is handed up rather than kept locally, and that one handed
 * down is rendered without asking the backend again. Whether it survives an actual navigation
 * is a property of the provider and was verified in the running application.
 */
let heldRun: DiffRun | null = null;
const rememberedRuns: DiffRun[] = [];
const selectForDiffMock = vi.hoisted(() => vi.fn());
const swapDiffSidesMock = vi.hoisted(() => vi.fn());

vi.mock('../api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api/client')>();
  return { ...actual, fetchDiff: fetchDiffMock };
});

vi.mock('../sboms/SbomProvider', async () => {
  const { useState } = await vi.importActual<typeof import('react')>('react');
  return {
    useSboms: () => {
      // A real hook, so remembering a run re-renders the page exactly as the provider would.
      const [run, setRun] = useState<DiffRun | null>(heldRun);
      return {
        diffSelection,
        selectForDiff: selectForDiffMock,
        swapDiffSides: swapDiffSidesMock,
        diffRun: run,
        rememberDiffRun: (next: DiffRun) => {
          rememberedRuns.push(next);
          setRun(next);
        },
      };
    },
  };
});

const leftSbom = sbom('left-id', 'baseline.cdx.json', '2026-09-01T10:00:00Z');
const rightSbom = sbom('right-id', 'new-state.cdx.json', '2026-09-05T12:00:00Z');

function sbom(id: string, filename: string, uploadedAt: string): Sbom {
  return {
    id,
    filename,
    uploadedAt,
    specVersion: '1.6',
    componentCount: 10,
    scannedComponents: 10,
    severityCounts: {},
    scanning: false,
  };
}

function row(overrides: Partial<DiffRow> = {}): DiffRow {
  return {
    coordinates: 'org.example:library',
    group: 'org.example',
    name: 'library',
    left: {
      purl: 'pkg:maven/org.example/library@1.0.0',
      version: '1.0.0',
      counts: {},
      cveIds: ['CVE-2026-0001', 'CVE-2026-0002'],
      advisoryUrls: {
        'CVE-2026-0001': 'https://nvd.nist.gov/vuln/detail/CVE-2026-0001',
        'CVE-2026-0002': 'https://nvd.nist.gov/vuln/detail/CVE-2026-0002',
      },
    },
    right: {
      purl: 'pkg:maven/org.example/library@2.0.0',
      version: '2.0.0',
      counts: {},
      cveIds: ['CVE-2026-0002', 'CVE-2026-0003'],
      advisoryUrls: { 'CVE-2026-0003': 'https://nvd.nist.gov/vuln/detail/CVE-2026-0003' },
    },
    change: 'VERSION_CHANGED',
    ...overrides,
  };
}

const result: DiffResult = {
  rows: [
    row(),
    row({
      coordinates: 'org.example:unchanged',
      name: 'unchanged',
      right: {
        purl: 'pkg:maven/org.example/unchanged@1.0.0',
        version: '1.0.0',
        counts: {},
        cveIds: ['CVE-2026-0004'],
        advisoryUrls: {},
      },
      left: {
        purl: 'pkg:maven/org.example/unchanged@1.0.0',
        version: '1.0.0',
        counts: {},
        cveIds: ['CVE-2026-0004'],
        advisoryUrls: {},
      },
      change: 'UNCHANGED',
    }),
  ],
  summary: {
    changes: { ADDED: 3, REMOVED: 2, VERSION_CHANGED: 1, UNCHANGED: 7 },
    cveIdsGained: 4,
    cveIdsLost: 5,
  },
};

function renderPage() {
  return render(
    <MemoryRouter>
      <DiffPage />
    </MemoryRouter>,
  );
}

beforeEach(() => {
  window.localStorage.clear();
  fetchDiffMock.mockReset();
  selectForDiffMock.mockReset();
  swapDiffSidesMock.mockReset();
  rememberedRuns.length = 0;
  heldRun = null;
  diffSelection = { left: leftSbom, right: rightSbom };
});

describe('FindingDeltaCell', () => {
  it('derives gained and lost CVEs without treating a shared CVE as a change', () => {
    expect(findingDelta(row())).toEqual({
      gained: ['CVE-2026-0003'],
      lost: ['CVE-2026-0001'],
    });

    render(<FindingDeltaCell row={row()} />);
    expect(screen.getByText('CVE-2026-0003')).toBeTruthy();
    expect(screen.getByText('CVE-2026-0001')).toBeTruthy();
    expect(screen.queryByText('CVE-2026-0002')).toBeNull();
  });

  it('links each identifier where its own side says it points', () => {
    // Gained ids come from the right side and lost ids from the left, so each list has to read
    // the map belonging to the side that actually holds it — crossing them would link a CVE
    // through a document that never carried it.
    render(<FindingDeltaCell row={row()} />);

    expect(screen.getByRole('link', { name: 'CVE-2026-0003' }).getAttribute('href'))
      .toBe('https://nvd.nist.gov/vuln/detail/CVE-2026-0003');
    expect(screen.getByRole('link', { name: 'CVE-2026-0001' }).getAttribute('href'))
      .toBe('https://nvd.nist.gov/vuln/detail/CVE-2026-0001');
  });

  it('still shows an identifier that has no link rather than dropping it', () => {
    const { container } = render(
      <FindingDeltaCell
        row={row({
          left: { purl: null, version: '1', counts: {}, cveIds: ['OSV-ONLY-2026'], advisoryUrls: {} },
          right: { purl: null, version: '2', counts: {}, cveIds: [], advisoryUrls: {} },
        })}
      />,
    );

    expect(container.textContent).toContain('LostOSV-ONLY-2026');
    expect(container.querySelector('a')).toBeNull();
  });

  it('distinguishes the same findings from no findings on either side', () => {
    const same = render(
      <FindingDeltaCell
        row={row({
          left: { purl: null, version: '1', counts: {}, cveIds: ['CVE-2026-0001'], advisoryUrls: {} },
          right: { purl: null, version: '2', counts: {}, cveIds: ['CVE-2026-0001'], advisoryUrls: {} },
        })}
      />,
    );
    expect(same.container.textContent).toBe('Same CVEs on both sides');

    // Scoped to this render: cleanup runs between tests, not between the two renders here.
    const none = render(
      <FindingDeltaCell
        row={row({
          left: { purl: null, version: '1', counts: {}, cveIds: [], advisoryUrls: {} },
          right: { purl: null, version: '2', counts: {}, cveIds: [], advisoryUrls: {} },
        })}
      />,
    );
    expect(none.container.textContent).toBe('No findings on either side');
  });

  it('states when only one direction changed instead of leaving half the delta blank', () => {
    const { container } = render(
      <FindingDeltaCell
        row={row({
          left: { purl: null, version: '1', counts: {}, cveIds: ['CVE-2026-0001'], advisoryUrls: {} },
          right: { purl: null, version: '2', counts: {}, cveIds: [], advisoryUrls: {} },
        })}
      />,
    );

    expect(container.textContent).toContain('GainedNone');
    expect(container.textContent).toContain('LostCVE-2026-0001');
  });
});

describe('DiffPage', () => {
  it('explains exactly which side is missing and does not compare automatically', () => {
    diffSelection = { left: leftSbom, right: null };
    renderPage();

    expect(screen.getByText(/Drag a document from the sidebar onto the missing right/)).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Compare' }).hasAttribute('disabled')).toBe(true);
    expect(fetchDiffMock).not.toHaveBeenCalled();
  });

  it('compares only on the button and labels whole-comparison totals independently of filters', async () => {
    fetchDiffMock.mockResolvedValue(result);
    renderPage();

    expect(screen.getByText('baseline.cdx.json')).toBeTruthy();
    expect(screen.getByText('new-state.cdx.json')).toBeTruthy();
    expect(fetchDiffMock).not.toHaveBeenCalled();

    fireEvent.click(screen.getByRole('button', { name: 'Compare' }));
    await waitFor(() => expect(fetchDiffMock).toHaveBeenCalledTimes(1));
    expect(fetchDiffMock).toHaveBeenCalledWith('left-id', 'right-id', {
      sort: 'COORDINATES',
      ascending: true,
      filter: '',
      regex: false,
      negate: false,
    });

    expect(screen.getByRole('heading', { name: 'Whole comparison' })).toBeTruthy();
    expect(screen.getByText(/do not change with the row filter/)).toBeTruthy();
    expect(screen.getByText('1 unchanged row hidden')).toBeTruthy();
    expect(screen.queryByText('org.example:unchanged')).toBeNull();
    expect(screen.getByText('org.example:library')).toBeTruthy();
    expect(screen.getByRole('link', { name: 'Export view (1)' }).getAttribute('href'))
      .toBe('/api/diff/export.xlsx?left=left-id&right=right-id&scope=visible&sort=COORDINATES&direction=asc');

    fireEvent.click(screen.getByRole('button', { name: 'Other export options' }));
    expect(screen.getByText('1 rows — current filter, unchanged excluded')).toBeTruthy();
    expect(screen.getByText('13 rows — every comparison row, unchanged included')).toBeTruthy();
    expect(screen.getByRole('menuitem', { name: /Export all/ }).getAttribute('href'))
      .toBe('/api/diff/export.xlsx?left=left-id&right=right-id&scope=all&sort=COORDINATES&direction=asc');

    fireEvent.click(screen.getByRole('checkbox', { name: 'Show unchanged' }));
    expect(screen.getByText('org.example:unchanged')).toBeTruthy();
  });

  it('shows the two version columns with no layout to choose', async () => {
    // The inline/split toggle is gone: inline only stacked two short strings into one cell
    // and made every row taller. Nothing to switch, and nothing stored about it either.
    fetchDiffMock.mockResolvedValue(result);
    renderPage();

    fireEvent.click(screen.getByRole('button', { name: 'Compare' }));
    await screen.findByText('org.example:library');

    expect(screen.getByRole('columnheader', { name: 'Left version' })).toBeTruthy();
    expect(screen.getByRole('columnheader', { name: 'Right version' })).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Inline' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Split' })).toBeNull();
    expect(window.localStorage.getItem('sbomscope.diff.view')).toBeNull();
  });

  it('re-runs the comparison when the filter changes, without a second Compare', async () => {
    // The filter is applied in SQL, so narrowing means asking again — and nothing on screen
    // said so. Typing looked like a broken filter: the rows did not move until Compare was
    // pressed a second time. Compare still guards the expensive half; what it no longer guards
    // is narrowing an answer already on screen.
    fetchDiffMock.mockResolvedValue(result);
    renderPage();

    fireEvent.click(screen.getByRole('button', { name: 'Compare' }));
    await waitFor(() => expect(fetchDiffMock).toHaveBeenCalledTimes(1));

    fireEvent.change(screen.getByLabelText('Filter diff rows'), { target: { value: 'jackson' } });

    await waitFor(() => expect(fetchDiffMock).toHaveBeenCalledTimes(2));
    expect(fetchDiffMock).toHaveBeenLastCalledWith('left-id', 'right-id', {
      sort: 'COORDINATES',
      ascending: true,
      filter: 'jackson',
      regex: false,
      negate: false,
    });
  });

  it('sorts through the comparison query and announces the active header direction', async () => {
    fetchDiffMock.mockResolvedValue(result);
    renderPage();

    fireEvent.click(screen.getByRole('button', { name: 'Compare' }));
    await waitFor(() => expect(fetchDiffMock).toHaveBeenCalledTimes(1));
    expect(screen.getByRole('columnheader', { name: 'Coordinates' }).getAttribute('aria-sort'))
      .toBe('ascending');
    expect(screen.getByRole('columnheader', { name: 'Change' }).getAttribute('aria-sort'))
      .toBe('none');

    fireEvent.click(screen.getByRole('button', { name: 'Change' }));
    await waitFor(() => expect(fetchDiffMock).toHaveBeenCalledTimes(2));
    expect(fetchDiffMock).toHaveBeenLastCalledWith('left-id', 'right-id', {
      sort: 'CHANGE',
      ascending: true,
      filter: '',
      regex: false,
      negate: false,
    });
    expect(screen.getByRole('columnheader', { name: 'Change' }).getAttribute('aria-sort'))
      .toBe('ascending');

    fireEvent.click(screen.getByRole('button', { name: 'Change' }));
    await waitFor(() => expect(fetchDiffMock).toHaveBeenCalledTimes(3));
    expect(fetchDiffMock).toHaveBeenLastCalledWith('left-id', 'right-id', {
      sort: 'CHANGE',
      ascending: false,
      filter: '',
      regex: false,
      negate: false,
    });
    expect(screen.getByRole('columnheader', { name: 'Change' }).getAttribute('aria-sort'))
      .toBe('descending');
  });

  it('does not re-run a comparison whose rows already answer the current filter', async () => {
    // The guard that keeps the session-held result useful: returning to the page must not
    // fire the query again, which is the whole reason the result lives above the router.
    heldRun = {
      leftId: 'left-id',
      rightId: 'right-id',
      filter: { sort: 'COORDINATES', ascending: true, filter: 'library', regex: false, negate: false },
      result,
    };
    renderPage();

    await waitFor(() => expect(screen.getByText('org.example:library')).toBeTruthy());
    expect(fetchDiffMock).not.toHaveBeenCalled();
  });

  it('hands a finished comparison to the session rather than keeping it on the page', async () => {
    fetchDiffMock.mockResolvedValue(result);
    renderPage();

    fireEvent.click(screen.getByRole('button', { name: 'Compare' }));
    await screen.findByText('org.example:library');

    expect(rememberedRuns).toHaveLength(1);
    expect(rememberedRuns[0]).toMatchObject({
      leftId: 'left-id',
      rightId: 'right-id',
      filter: { sort: 'COORDINATES', ascending: true, filter: '', regex: false, negate: false },
      result,
    });
  });

  it('renders a comparison the session is already holding without asking again', () => {
    // What the reader sees on coming back from another tab: the rows, the filter they typed,
    // and no second request for an answer that is already in hand.
    heldRun = {
      leftId: 'left-id',
      rightId: 'right-id',
      filter: { sort: 'COORDINATES', ascending: true, filter: 'library', regex: false, negate: false },
      result,
    };
    renderPage();

    expect(screen.getByText('org.example:library')).toBeTruthy();
    expect(screen.getByRole('heading', { name: 'Whole comparison' })).toBeTruthy();
    expect((screen.getByLabelText('Filter diff rows') as HTMLInputElement).value).toBe('library');
    expect(fetchDiffMock).not.toHaveBeenCalled();
  });

  it('ignores a held comparison whose sides are no longer the chosen pair', () => {
    heldRun = {
      leftId: 'left-id',
      rightId: 'someone-else',
      filter: { sort: 'COORDINATES', ascending: true, filter: '', regex: false, negate: false },
      result,
    };
    renderPage();

    // Not stale data to refresh quietly — it answers a different question, so nothing of it
    // is shown.
    expect(screen.queryByText('org.example:library')).toBeNull();
    expect(screen.getByText('Select Compare to run this comparison.')).toBeTruthy();
  });

  it('states both counts and their direction above the table', async () => {
    fetchDiffMock.mockResolvedValue(result);
    diffSelection = {
      left: { ...leftSbom, componentCount: 10, severityCounts: { CRITICAL: 2, HIGH: 3 } },
      right: { ...rightSbom, componentCount: 12, severityCounts: { CRITICAL: 1, HIGH: 1 } },
    };
    renderPage();

    fireEvent.click(screen.getByRole('button', { name: 'Compare' }));
    await screen.findByText('org.example:library');

    expect(screen.getByText('Components')).toBeTruthy();
    expect(screen.getByText('+2')).toBeTruthy();
    expect(screen.getByText('Vulnerabilities')).toBeTruthy();
    expect(screen.getByText('-3')).toBeTruthy();
  });

  it('breaks the vulnerability total down by band, including the bands at zero', async () => {
    // A total on its own can hide the answer: two criticals traded for three lows reads as
    // "+1". Every vulnerable band is listed so the parts add up to the headline beside them.
    fetchDiffMock.mockResolvedValue(result);
    diffSelection = {
      left: { ...leftSbom, severityCounts: { CRITICAL: 2, HIGH: 3, MEDIUM: 0, LOW: 0, NONE: 1 } },
      right: { ...rightSbom, severityCounts: { CRITICAL: 0, HIGH: 1, MEDIUM: 0, LOW: 4, NONE: 1 } },
    };
    renderPage();

    fireEvent.click(screen.getByRole('button', { name: 'Compare' }));
    await screen.findByText('org.example:library');

    const bands = [...document.querySelectorAll('.diff-stat__band')].map((b) => b.textContent);
    expect(bands).toEqual([
      'Critical2 → 0-2',
      'High3 → 1-2',
      'Medium0 → 0±0',
      'Low0 → 4+4',
      'Unscored1 → 1±0',
    ]);
  });

  it('offers no breakdown at all when one side was never scanned', () => {
    heldRun = {
      leftId: 'left-id',
      rightId: 'right-id',
      filter: { sort: 'COORDINATES', ascending: true, filter: '', regex: false, negate: false },
      result,
    };
    diffSelection = {
      left: { ...leftSbom, scannedComponents: 0, severityCounts: {} },
      right: { ...rightSbom, severityCounts: { HIGH: 4 } },
    };
    renderPage();

    // Zeroes for the unscanned side would be six false statements rather than one.
    expect(document.querySelectorAll('.diff-stat__band')).toHaveLength(0);
  });

  it('will not subtract a count from a document nobody has scanned', () => {
    // Zero findings and never looked are different statements, and a delta between them
    // would be a confident number about an unexamined document.
    heldRun = {
      leftId: 'left-id',
      rightId: 'right-id',
      filter: { sort: 'COORDINATES', ascending: true, filter: '', regex: false, negate: false },
      result,
    };
    diffSelection = {
      left: { ...leftSbom, scannedComponents: 0, severityCounts: {} },
      right: { ...rightSbom, severityCounts: { HIGH: 4 } },
    };
    renderPage();

    expect(screen.getByText('not scanned')).toBeTruthy();
  });

  it('puts a rejected regular expression on the search field and keeps it out of page alerts', async () => {
    fetchDiffMock.mockRejectedValue(new ApiError('Invalid regular expression: unclosed group', 400));
    renderPage();

    fireEvent.click(screen.getByTitle('Match as a regular expression'));
    fireEvent.change(screen.getByRole('searchbox'), { target: { value: '(' } });
    fireEvent.click(screen.getByRole('button', { name: 'Compare' }));

    expect(await screen.findByText('Invalid regular expression: unclosed group')).toBeTruthy();
    expect(screen.getByRole('searchbox').getAttribute('aria-invalid')).toBe('true');
    expect(screen.queryByRole('alert')).toBeNull();
  });
});
