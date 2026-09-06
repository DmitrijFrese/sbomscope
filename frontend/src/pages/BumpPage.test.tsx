import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { ApiError } from '../api/client';
import type { Sbom } from '../api/client';
import type { BumpPlan, BumpRow, DeclarationSite, SiteKind } from '../bump/model';
import { BumpPage } from './BumpPage';

const fetchBumpPlanMock = vi.hoisted(() => vi.fn());
const previewBumpMock = vi.hoisted(() => vi.fn());
const applyBumpMock = vi.hoisted(() => vi.fn());
const clipboardWriteMock = vi.hoisted(() => vi.fn());
let selected: Sbom | null;

vi.mock('../api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api/client')>();
  return {
    ...actual,
    fetchBumpPlan: fetchBumpPlanMock,
    previewBump: previewBumpMock,
    applyBump: applyBumpMock,
  };
});

vi.mock('../sboms/SbomProvider', () => ({ useSboms: () => ({ selected }) }));

function sbom(workspacePath: string | undefined = 'C:/workspace'): Sbom {
  return {
    id: 'sbom-id',
    filename: 'application.cdx.json',
    uploadedAt: '2026-09-06T10:00:00Z',
    workspacePath,
    specVersion: '1.6',
    componentCount: 3,
    scannedComponents: 3,
    severityCounts: {},
    scanning: false,
  };
}

function site(id: string, artifactId: string, kind: SiteKind = 'DIRECT'): DeclarationSite {
  const structural = kind === 'IMPORTED_BOM' || kind === 'UNDECLARED';
  return {
    id,
    file: 'module-a/pom.xml',
    module: 'module-a',
    kind,
    groupId: 'org.example',
    artifactId,
    type: '',
    classifier: '',
    currentVersion: '1.0.0',
    propertyName: kind === 'PROPERTY' ? 'shared.version' : null,
    sharedWith: [],
    exclusions: [],
    versionRange: structural ? null : { start: 10, end: 15, line: 2, column: 3 },
    insertionPoint: structural ? { start: 20, end: 20, line: 3, column: 1 } : null,
    ecosystem: 'MAVEN',
    versionLiteral: '1.0.0',
    rangeAdmitsFix: false,
  };
}

function row(id = 'module-a/pom.xml#0', artifactId = 'alpha', kind: SiteKind = 'DIRECT'): BumpRow {
  return {
    site: site(id, artifactId, kind),
    minimalTarget: '2.0.0',
    latestTarget: '3.0.0',
    advisories: [{
      osvId: 'OSV-2026-1', cveId: null,
      osvUrl: 'https://osv.dev/vulnerability/OSV-2026-1', cveUrl: null,
    }],
    highestSeverity: 'High',
    artifactUrl: 'https://central.sonatype.com/artifact/org.example/alpha',
    currentVersionUrl: 'https://central.sonatype.com/artifact/org.example/alpha/1.0.0',
    minimalTargetUrl: 'https://central.sonatype.com/artifact/org.example/alpha/2.0.0',
    latestTargetUrl: 'https://central.sonatype.com/artifact/org.example/alpha/3.0.0',
  };
}

function plan(rows: BumpRow[] = [row()]): BumpPlan {
  return {
    sbomId: 'sbom-id',
    workspace: 'C:/workspace',
    files: [{
      path: 'module-a/pom.xml',
      fingerprint: 'abc123',
      editable: true,
      text: '<project>original</project>',
    }],
    rows,
    notes: [],
    lockfileNotes: [],
  };
}

function preview(patched = '<project>preview 2.0.0</project>') {
  return {
    files: [{
      path: 'module-a/pom.xml',
      fingerprint: 'abc123',
      patched,
      changed: [{ start: 17, end: 22, line: 1, column: 18 }],
      editCount: 1,
    }],
    warnings: [],
  };
}

beforeEach(() => {
  vi.restoreAllMocks();
  selected = sbom();
  fetchBumpPlanMock.mockReset();
  previewBumpMock.mockReset();
  applyBumpMock.mockReset();
  clipboardWriteMock.mockReset();
  clipboardWriteMock.mockResolvedValue(undefined);
  Object.defineProperty(navigator, 'clipboard', {
    configurable: true,
    value: { writeText: clipboardWriteMock },
  });
  applyBumpMock.mockResolvedValue({ written: ['module-a/pom.xml'], backups: ['module-a/pom.xml.orig'], skipped: [] });
  fetchBumpPlanMock.mockResolvedValue(plan());
  previewBumpMock.mockResolvedValue(preview());
});

describe('BumpPage', () => {
  it('shows the document-selection empty state without requesting a plan', () => {
    selected = null;
    render(<BumpPage />);

    expect(screen.getByText(/Select an SBOM from the sidebar/)).toBeTruthy();
    expect(fetchBumpPlanMock).not.toHaveBeenCalled();
  });

  it('treats an unattached workspace as an expected empty state', () => {
    selected = { ...sbom(), workspacePath: undefined };
    render(<BumpPage />);

    expect(screen.getByText(/Attach a workspace.*⋯ menu/)).toBeTruthy();
    expect(screen.queryByRole('alert')).toBeNull();
    expect(fetchBumpPlanMock).not.toHaveBeenCalled();
  });

  it('preselects every available minimal target in one loaded plan', async () => {
    const rows = [row('pom.xml#0', 'alpha'), row('pom.xml#1', 'beta')];
    fetchBumpPlanMock.mockResolvedValue(plan(rows));
    render(<BumpPage />);

    expect((await screen.findByLabelText('Select org.example:alpha') as HTMLInputElement).checked).toBe(true);
    expect((screen.getByLabelText('Select org.example:beta') as HTMLInputElement).checked).toBe(true);
    expect((screen.getByLabelText('Minimal 2.0.0 for org.example:alpha') as HTMLInputElement).checked)
      .toBe(true);
    expect(screen.getByRole('button', { name: 'Undo' }).getAttribute('title')).toBe('Select 2 rows');
  });

  it('chooses the latest available target through the shared session', async () => {
    render(<BumpPage />);
    const latest = await screen.findByLabelText('Latest available 3.0.0 for org.example:alpha');

    fireEvent.click(latest);

    expect((latest as HTMLInputElement).checked).toBe(true);
    expect(screen.getByText('Will write').parentElement?.textContent).toContain('3.0.0');
    await waitFor(() => expect(previewBumpMock).toHaveBeenLastCalledWith('sbom-id', [
      { siteId: 'module-a/pom.xml#0', newVersion: '3.0.0', structural: false },
    ]));
  });

  it('states when latest metadata is not available instead of leaving an empty cell', async () => {
    const target = row();
    target.latestTarget = null;
    fetchBumpPlanMock.mockResolvedValue(plan([target]));
    render(<BumpPage />);

    await screen.findByLabelText('Select org.example:alpha');
    expect(screen.getByText('Not available')).toBeTruthy();
  });

  it('shows an npm declaration literal and the operator-preserving version to be written', async () => {
    const target = row('package.json#dependencies#alpha', 'alpha', 'NPM_DIRECT');
    Object.assign(target.site, {
      file: 'package.json', ecosystem: 'NPM', currentVersion: '4.17.20', versionLiteral: '^4.17.20',
    });
    target.minimalTarget = '4.17.21';
    fetchBumpPlanMock.mockResolvedValue(plan([target]));
    render(<BumpPage />);

    expect((await screen.findByText('^4.17.20')).closest('a')).toBeNull();
    expect(screen.getByText('Will write').parentElement?.textContent).toContain('^4.17.21');
  });

  it('links the CVE when present and otherwise links the OSV advisory', async () => {
    const cve = row('pom.xml#0', 'alpha');
    cve.advisories = [{
      osvId: 'GHSA-test', cveId: 'CVE-2026-1234',
      osvUrl: 'https://osv.example/GHSA-test', cveUrl: 'https://nvd.example/CVE-2026-1234',
    }, {
      osvId: 'OSV-2026-2', cveId: null,
      osvUrl: 'https://osv.example/OSV-2026-2', cveUrl: null,
    }];
    fetchBumpPlanMock.mockResolvedValue(plan([cve]));
    render(<BumpPage />);

    const cveLink = await screen.findByRole('link', { name: 'CVE-2026-1234' });
    const osvLink = screen.getByRole('link', { name: 'OSV-2026-2' });
    expect(cveLink.getAttribute('href')).toBe('https://nvd.example/CVE-2026-1234');
    expect(osvLink.getAttribute('href')).toBe('https://osv.example/OSV-2026-2');
    expect(screen.queryByText('GHSA-test')).toBeNull();
    expect(cveLink.getAttribute('target')).toBe('_blank');
    expect(cveLink.getAttribute('rel')).toBe('noreferrer');
  });

  it('renders a version without a registry URL as plain text', async () => {
    const target = row();
    target.minimalTargetUrl = null;
    fetchBumpPlanMock.mockResolvedValue(plan([target]));
    render(<BumpPage />);

    const radio = await screen.findByLabelText('Minimal 2.0.0 for org.example:alpha');
    expect(radio.parentElement?.querySelector('a')).toBeNull();
  });

  it('links an exact npm current version but never a range literal', async () => {
    const target = row('package.json#dependencies#alpha', 'alpha', 'NPM_DIRECT');
    Object.assign(target.site, {
      file: 'package.json', ecosystem: 'NPM', currentVersion: '1.0.0', versionLiteral: '1.0.0',
    });
    target.currentVersionUrl = 'https://www.npmjs.com/package/alpha/v/1.0.0';
    fetchBumpPlanMock.mockResolvedValue(plan([target]));
    render(<BumpPage />);

    const version = await screen.findByRole('link', { name: '1.0.0' });
    expect(version.getAttribute('href')).toBe('https://www.npmjs.com/package/alpha/v/1.0.0');
  });

  it('diagnoses an npm range that already admits the fix without offering it for selection', async () => {
    const target = row('package.json#dependencies#alpha', 'alpha', 'NPM_DIRECT');
    Object.assign(target.site, {
      file: 'package.json', ecosystem: 'NPM', currentVersion: '4.17.20', versionLiteral: '^4.17.20',
      rangeAdmitsFix: true,
    });
    target.minimalTarget = '4.17.21';
    fetchBumpPlanMock.mockResolvedValue(plan([target]));
    render(<BumpPage />);

    expect(await screen.findByText(/already allows 4.17.21/)).toBeTruthy();
    expect(screen.getByRole('note').textContent).toContain('run npm install');
    expect(screen.queryByLabelText('Select org.example:alpha')).toBeNull();
    expect(previewBumpMock).not.toHaveBeenCalled();
  });

  it('lists an unsupported npm literal without offering it for selection', async () => {
    const target = row('package.json#dependencies#alpha', 'alpha', 'NPM_DIRECT');
    Object.assign(target.site, {
      file: 'package.json', ecosystem: 'NPM', versionLiteral: 'workspace:*', versionRange: null,
    });
    const nextPlan = plan([target]);
    nextPlan.notes = ['package.json: alpha uses unsupported npm declaration workspace:*'];
    fetchBumpPlanMock.mockResolvedValue(nextPlan);
    render(<BumpPage />);

    expect((await screen.findByRole('note')).textContent).toContain('unsupported npm declaration workspace');
    expect(screen.queryByLabelText('Select org.example:alpha')).toBeNull();
  });

  it('renders lockfile notes separately from plan notes', async () => {
    const nextPlan = plan();
    nextPlan.notes = ['Could not read one manifest'];
    nextPlan.lockfileNotes = ['package-lock.json is stale; run npm install'];
    fetchBumpPlanMock.mockResolvedValue(nextPlan);
    render(<BumpPage />);

    expect((await screen.findByLabelText('Plan notes')).textContent).toContain('Could not read one manifest');
    expect(screen.getByLabelText('Lockfile notes').textContent).toContain('package-lock.json is stale');
  });

  it('names every coordinate affected by a shared property', async () => {
    const target = row('pom.xml#0', 'alpha', 'PROPERTY');
    target.site.sharedWith = ['org.example:beta', 'org.other:gamma'];
    fetchBumpPlanMock.mockResolvedValue(plan([target]));
    render(<BumpPage />);

    const warning = await screen.findByRole('note');
    expect(warning.textContent).toContain('org.example:alpha');
    expect(warning.textContent).toContain('org.example:beta');
    expect(warning.textContent).toContain('org.other:gamma');
  });

  it('presents an undeclared component as a structural managed-entry remedy', async () => {
    fetchBumpPlanMock.mockResolvedValue(plan([row('pom.xml#0', 'transitive', 'UNDECLARED')]));
    render(<BumpPage />);

    expect(await screen.findByText('Adds a new managed entry')).toBeTruthy();
    await waitFor(() => expect(previewBumpMock).toHaveBeenCalledWith('sbom-id', [
      { siteId: 'pom.xml#0', newVersion: '2.0.0', structural: true },
    ]));
  });

  it('presents an editable undeclared npm component as an overrides remedy', async () => {
    const target = row('package.json#transitive', 'transitive', 'UNDECLARED');
    Object.assign(target.site, { file: 'package.json', ecosystem: 'NPM' });
    fetchBumpPlanMock.mockResolvedValue(plan([target]));
    render(<BumpPage />);

    expect(await screen.findByText('Adds an npm overrides entry')).toBeTruthy();
    await waitFor(() => expect(previewBumpMock).toHaveBeenCalledWith('sbom-id', [
      { siteId: 'package.json#transitive', newVersion: '2.0.0', structural: true },
    ]));
  });

  it('diagnoses an undeclared npm component without an npm lockfile', async () => {
    const target = row('package.json#transitive', 'transitive', 'UNDECLARED');
    Object.assign(target.site, {
      file: 'package.json', ecosystem: 'NPM', insertionPoint: null,
    });
    const nextPlan = plan([target]);
    nextPlan.notes = [
      'Cannot add npm override for transitive in package.json: lockfile found: yarn.lock; declared dependency: parent',
    ];
    fetchBumpPlanMock.mockResolvedValue(nextPlan);
    render(<BumpPage />);

    expect((await screen.findByRole('note')).textContent).toContain('declared dependency: parent');
    expect(screen.getByText('Transitive npm dependency')).toBeTruthy();
    expect(screen.queryByLabelText('Select org.example:transitive')).toBeNull();
    expect(previewBumpMock).not.toHaveBeenCalled();
  });

  it('undoes a preview text edit back to the server preview on the same stack', async () => {
    render(<BumpPage />);
    const editor = await screen.findByLabelText('Edit module-a/pom.xml') as HTMLTextAreaElement;
    await waitFor(() => expect(editor.value).toBe('<project>preview 2.0.0</project>'));

    fireEvent.change(editor, { target: { value: '<project>typed by user</project>' } });
    expect(editor.value).toBe('<project>typed by user</project>');
    const undoButton = screen.getByRole('button', { name: 'Undo' });
    expect(undoButton.getAttribute('title')).toBe('Edit module-a/pom.xml');
    fireEvent.click(undoButton);

    expect(editor.value).toBe('<project>preview 2.0.0</project>');
  });

  it('copies the editor current text including a user edit', async () => {
    render(<BumpPage />);
    const editor = await screen.findByLabelText('Edit module-a/pom.xml') as HTMLTextAreaElement;
    await waitFor(() => expect(editor.value).toBe('<project>preview 2.0.0</project>'));
    fireEvent.change(editor, { target: { value: '<project>user edit</project>' } });

    fireEvent.click(screen.getByRole('button', { name: 'Copy whole file' }));

    await waitFor(() => expect(clipboardWriteMock)
      .toHaveBeenCalledWith('<project>user edit</project>'));
    expect(screen.getByRole('button', { name: 'Copied' })).toBeTruthy();
  });

  it('reports a clipboard rejection in the preview', async () => {
    clipboardWriteMock.mockRejectedValue(new Error('denied'));
    render(<BumpPage />);
    await screen.findByLabelText('Edit module-a/pom.xml');

    fireEvent.click(screen.getByRole('button', { name: 'Copy whole file' }));

    expect((await screen.findByRole('alert')).textContent)
      .toContain('Could not copy the displayed file');
  });

  it('keeps the last good preview visible when a later preview fails', async () => {
    previewBumpMock
      .mockResolvedValueOnce(preview('<project>last good</project>'))
      .mockRejectedValueOnce(new ApiError('Preview rejected the edit', 400));
    render(<BumpPage />);
    const editor = await screen.findByLabelText('Edit module-a/pom.xml') as HTMLTextAreaElement;
    await waitFor(() => expect(editor.value).toBe('<project>last good</project>'));

    fireEvent.click(screen.getByLabelText('Latest available 3.0.0 for org.example:alpha'));

    expect((await screen.findByRole('alert')).textContent).toContain('Preview rejected the edit');
    expect(editor.value).toBe('<project>last good</project>');
  });

  it('renders two rows sharing one property with independent checkboxes', async () => {
    const alpha = row('pom.xml#0', 'alpha', 'PROPERTY');
    const beta = row('pom.xml#0', 'beta', 'PROPERTY');
    alpha.site.sharedWith = ['org.example:beta'];
    beta.site.sharedWith = ['org.example:alpha'];
    fetchBumpPlanMock.mockResolvedValue(plan([alpha, beta]));
    render(<BumpPage />);

    const alphaBox = await screen.findByLabelText('Select org.example:alpha');
    const betaBox = screen.getByLabelText('Select org.example:beta');
    expect(alphaBox).toBeTruthy();
    expect(betaBox).toBeTruthy();

    fireEvent.click(alphaBox);
    expect((alphaBox as HTMLInputElement).checked).toBe(false);
    expect((betaBox as HTMLInputElement).checked).toBe(true);
  });

  it('leaves a row already at its target unselected and out of the edits', async () => {
    const satisfied = row('pom.xml#0', 'alpha');
    satisfied.site.currentVersion = '2.0.0';   // the workspace has moved on since the SBOM
    fetchBumpPlanMock.mockResolvedValue(plan([satisfied]));
    render(<BumpPage />);

    const box = await screen.findByLabelText('Select org.example:alpha') as HTMLInputElement;
    expect(box.checked).toBe(false);
    expect(screen.getByText('Already at').parentElement?.textContent).toContain('2.0.0');
    // Nothing to preview means nothing to write: no .orig backup for a change that is not one.
    expect(previewBumpMock).not.toHaveBeenCalled();
    expect(screen.getByRole('button', { name: 'Apply' }).hasAttribute('disabled')).toBe(true);
  });

  it('names every file and its edit count before writing anything', async () => {
    render(<BumpPage />);
    await screen.findByLabelText('Select org.example:alpha');
    await waitFor(() => expect(screen.getByRole('button', { name: 'Apply' }).hasAttribute('disabled'))
      .toBe(false));

    fireEvent.click(screen.getByRole('button', { name: 'Apply' }));

    const dialog = await screen.findByRole('dialog');
    expect(dialog.textContent).toContain('module-a/pom.xml');
    expect(dialog.textContent).toContain('1 edit');
    expect(dialog.textContent).toContain('C:/workspace');
    // The dialog is a question, not a notification: nothing is written until it is answered.
    expect(applyBumpMock).not.toHaveBeenCalled();
  });

  it('sends the previewed text and reports what was written', async () => {
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(false);
    render(<BumpPage />);
    await screen.findByLabelText('Select org.example:alpha');
    await waitFor(() => expect(screen.getByRole('button', { name: 'Apply' }).hasAttribute('disabled'))
      .toBe(false));
    fireEvent.click(screen.getByRole('button', { name: 'Apply' }));
    fireEvent.click(await screen.findByRole('button', { name: 'Write files' }));

    await waitFor(() => expect(applyBumpMock).toHaveBeenCalledWith('sbom-id', [{
      path: 'module-a/pom.xml',
      fingerprint: 'abc123',
      text: '<project>preview 2.0.0</project>',
    }], false));
    expect((await screen.findByRole('status')).textContent).toContain('module-a/pom.xml.orig');
    expect(screen.queryByRole('dialog')).toBeNull();
    await waitFor(() => expect(fetchBumpPlanMock).toHaveBeenCalledTimes(2));
    expect(confirm).not.toHaveBeenCalled();
  });

  it('offers the override only after git reports the workspace is not a repository', async () => {
    applyBumpMock.mockRejectedValueOnce(new ApiError(
      'This workspace is not a git repository. Applying here cannot be undone with git; '
      + 'confirm explicitly to continue.', 409));
    render(<BumpPage />);
    await screen.findByLabelText('Select org.example:alpha');
    await waitFor(() => expect(screen.getByRole('button', { name: 'Apply' }).hasAttribute('disabled'))
      .toBe(false));
    fireEvent.click(screen.getByRole('button', { name: 'Apply' }));

    // Not offered up front: an override shown before it is needed is an override people learn
    // to tick without reading.
    expect(screen.queryByLabelText(/apply anyway/i)).toBeNull();
    fireEvent.click(await screen.findByRole('button', { name: 'Write files' }));

    const write = await screen.findByRole('button', { name: 'Write files' });
    expect(write.hasAttribute('disabled')).toBe(false);
    const override = await screen.findByLabelText(/apply anyway/i);
    fireEvent.click(override);
    fireEvent.click(screen.getByRole('button', { name: 'Write files' }));

    await waitFor(() => expect(applyBumpMock).toHaveBeenLastCalledWith('sbom-id', expect.anything(), true));
  });

  it('keeps the dialog open and reports the reason when a gate refuses', async () => {
    applyBumpMock.mockRejectedValue(new ApiError(
      'The git working tree is not clean. Commit or stash first', 409));
    render(<BumpPage />);
    await screen.findByLabelText('Select org.example:alpha');
    await waitFor(() => expect(screen.getByRole('button', { name: 'Apply' }).hasAttribute('disabled'))
      .toBe(false));
    fireEvent.click(screen.getByRole('button', { name: 'Apply' }));
    fireEvent.click(await screen.findByRole('button', { name: 'Write files' }));

    expect((await screen.findByRole('alert')).textContent).toContain('Commit or stash first');
    expect(screen.getByRole('dialog')).toBeTruthy();
    const tryAgain = screen.getByRole('button', { name: 'Try again' });
    expect(tryAgain.hasAttribute('disabled')).toBe(false);
    // A dirty tracked tree is never overridable from here.
    expect(screen.queryByLabelText(/apply anyway/i)).toBeNull();
  });

  it('requires a reload instead of offering an impossible fingerprint retry', async () => {
    applyBumpMock.mockRejectedValue(new ApiError('module-a/pom.xml changed on disk since preview', 409));
    render(<BumpPage />);
    await screen.findByLabelText('Select org.example:alpha');
    await waitFor(() => expect(screen.getByRole('button', { name: 'Apply' }).hasAttribute('disabled'))
      .toBe(false));
    fireEvent.click(screen.getByRole('button', { name: 'Apply' }));
    fireEvent.click(await screen.findByRole('button', { name: 'Write files' }));

    expect((await screen.findByRole('alert')).textContent).toContain('changed on disk');
    expect(screen.getByText(/Reload the plan/)).toBeTruthy();
    const write = screen.getByRole('button', { name: 'Write files' });
    expect(write.hasAttribute('disabled')).toBe(true);
    expect(screen.getByRole('button', { name: 'Close' })).toBeTruthy();
  });

  it('reloads a fresh plan without asking when the default session is unchanged', async () => {
    const refreshed = row('module-a/pom.xml#1', 'beta');
    fetchBumpPlanMock.mockResolvedValueOnce(plan()).mockResolvedValueOnce(plan([refreshed]));
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(false);
    render(<BumpPage />);
    await screen.findByLabelText('Select org.example:alpha');

    fireEvent.click(screen.getByRole('button', { name: 'Reload' }));

    expect(await screen.findByLabelText('Select org.example:beta')).toBeTruthy();
    expect(screen.queryByLabelText('Select org.example:alpha')).toBeNull();
    expect(fetchBumpPlanMock).toHaveBeenCalledTimes(2);
    expect(confirm).not.toHaveBeenCalled();
  });

  it('asks before reload discards a changed selection', async () => {
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(false);
    render(<BumpPage />);
    const selection = await screen.findByLabelText('Select org.example:alpha');
    fireEvent.click(selection);

    fireEvent.click(screen.getByRole('button', { name: 'Reload' }));

    expect(confirm).toHaveBeenCalledWith('Reload the plan and discard your selections and preview edits?');
    expect(fetchBumpPlanMock).toHaveBeenCalledTimes(1);
  });

  it('asks before reload discards a typed preview edit', async () => {
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(false);
    render(<BumpPage />);
    const editor = await screen.findByLabelText('Edit module-a/pom.xml') as HTMLTextAreaElement;
    await waitFor(() => expect(editor.value).toBe('<project>preview 2.0.0</project>'));
    fireEvent.change(editor, { target: { value: '<project>typed by user</project>' } });

    fireEvent.click(screen.getByRole('button', { name: 'Reload' }));

    expect(confirm).toHaveBeenCalledWith('Reload the plan and discard your selections and preview edits?');
    expect(fetchBumpPlanMock).toHaveBeenCalledTimes(1);
  });
  it('filters the declaration table without deselecting what it hides', async () => {
    const alpha = row('pom.xml#0', 'alpha');
    const beta = row('pom.xml#1', 'beta');
    fetchBumpPlanMock.mockResolvedValue(plan([alpha, beta]));
    render(<BumpPage />);
    await screen.findByLabelText('Select org.example:alpha');

    fireEvent.change(screen.getByLabelText('Filter vulnerable declarations'),
      { target: { value: 'beta' } });

    expect(screen.queryByLabelText('Select org.example:alpha')).toBeNull();
    expect(screen.getByLabelText('Select org.example:beta')).toBeTruthy();
    expect(screen.getByText('1 of 2 declarations')).toBeTruthy();
    // The hidden row is still selected and still written — saying so is the point of the note.
    expect(screen.getByText(/Filtered rows stay selected/)).toBeTruthy();
    await waitFor(() => expect(previewBumpMock).toHaveBeenLastCalledWith('sbom-id', [
      { siteId: 'pom.xml#0', newVersion: '2.0.0', structural: false },
      { siteId: 'pom.xml#1', newVersion: '2.0.0', structural: false },
    ]));
  });

  it('shows nothing rather than everything for a pattern that will not compile', async () => {
    fetchBumpPlanMock.mockResolvedValue(plan([row('pom.xml#0', 'alpha')]));
    render(<BumpPage />);
    await screen.findByLabelText('Select org.example:alpha');

    fireEvent.click(screen.getByTitle('Match as a regular expression'));
    fireEvent.change(screen.getByLabelText(/Filter vulnerable declarations/),
      { target: { value: '[unclosed' } });

    expect(screen.queryByLabelText('Select org.example:alpha')).toBeNull();
    expect(screen.getByText('0 of 1 declarations')).toBeTruthy();
  });
});
