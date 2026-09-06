// The bump session deliberately has no persistence: an unapplied override is either written
// through the explicit apply flow or disappears with the browser session.
export type SiteKind = 'DIRECT' | 'MANAGED' | 'PROPERTY' | 'IMPORTED_BOM' | 'UNDECLARED' | 'NPM_DIRECT';

export type Ecosystem = 'MAVEN' | 'NPM';

export interface TextRange {
  start: number;
  end: number;
  line: number;
  column: number;
}

export interface DeclarationSite {
  id: string;
  file: string;
  module: string;
  kind: SiteKind;
  groupId: string;
  artifactId: string;
  type: string;
  classifier: string;
  currentVersion: string;
  propertyName: string | null;
  sharedWith: string[];
  exclusions: string[];
  versionRange: TextRange | null;
  insertionPoint: TextRange | null;
  ecosystem: Ecosystem;
  versionLiteral: string;
  rangeAdmitsFix: boolean;
}

export interface BumpRow {
  site: DeclarationSite;
  minimalTarget: string | null;
  latestTarget: string | null;
  advisories: BumpAdvisory[];
  highestSeverity: string | null;
  artifactUrl: string | null;
  currentVersionUrl: string | null;
  minimalTargetUrl: string | null;
  latestTargetUrl: string | null;
}

export interface BumpAdvisory {
  osvId: string;
  cveId: string | null;
  osvUrl: string | null;
  cveUrl: string | null;
}

export interface PomFile {
  path: string;
  fingerprint: string;
  editable: boolean;
  text: string;
}

export interface BumpPlan {
  sbomId: string;
  workspace: string;
  files: PomFile[];
  rows: BumpRow[];
  notes: string[];
  lockfileNotes: string[];
}

export type RowKey = string;

export function rowKey(site: DeclarationSite): RowKey {
  return `${site.id} ${site.groupId}:${site.artifactId}`;
}

export type Selection = Record<
  RowKey,
  { version: string; source: 'minimal' | 'latest' | 'custom' }
>;

export type FileEdits = Record<string, string>;

export interface BumpState {
  plan: BumpPlan;
  selection: Selection;
  files: FileEdits;
}

export type BumpCommand =
  | { kind: 'select'; row: RowKey; version: string; source: 'minimal' | 'latest' | 'custom' }
  | { kind: 'deselect'; row: RowKey }
  | { kind: 'setVersion'; row: RowKey; version: string; source: 'minimal' | 'latest' | 'custom' }
  | {
      kind: 'selectMany';
      selections: Array<{
        row: RowKey;
        version: string;
        source: 'minimal' | 'latest' | 'custom';
      }>;
    }
  | { kind: 'deselectAll' }
  | { kind: 'editFile'; path: string; text: string };

export interface Session {
  state: BumpState;
  canUndo: boolean;
  canRedo: boolean;
  undoLabel: string | null;
  redoLabel: string | null;
}

interface HistoryEntry {
  state: BumpState;
  label: string;
}

interface SessionWithHistory extends Session {
  past: HistoryEntry[];
  future: HistoryEntry[];
}

type VersionSource = 'minimal' | 'latest' | 'custom';

function sessionWith(
  state: BumpState,
  past: HistoryEntry[],
  future: HistoryEntry[],
): SessionWithHistory {
  return {
    state,
    canUndo: past.length > 0,
    canRedo: future.length > 0,
    undoLabel: past.at(-1)?.label ?? null,
    redoLabel: future[0]?.label ?? null,
    past,
    future,
  };
}

function historyOf(session: Session): SessionWithHistory {
  const candidate = session as Partial<SessionWithHistory>;
  return sessionWith(session.state, candidate.past ?? [], candidate.future ?? []);
}

function rowFor(plan: BumpPlan, key: RowKey): BumpRow {
  const row = plan.rows.find((candidate) => rowKey(candidate.site) === key);
  if (!row) {
    throw new Error(`Unknown bump row: ${key}`);
  }
  return row;
}

function parseVersion(version: string): { release: bigint[]; preRelease: string | null } {
  let value = version.trim();
  const build = value.indexOf('+');
  if (build >= 0) value = value.slice(0, build);

  const dash = value.indexOf('-');
  const numeric = dash >= 0 ? value.slice(0, dash) : value;
  const preRelease = dash >= 0 ? value.slice(dash + 1) : null;
  return {
    release: numeric.split('.').map((part) => {
      const digits = /^\d+/.exec(part)?.[0];
      if (!digits) return 0n;
      const value = BigInt(digits);
      return value <= 9223372036854775807n ? value : 0n;
    }),
    preRelease,
  };
}

/**
 * Mirrors the intentionally small VersionOrder comparator used by the backend.
 *
 * Exported because the table needs the same ordering to decide whether a row is already at or
 * above its target — and a second comparator written for that would be the one that disagrees.
 */
export function compareVersions(left: string, right: string): number {
  const a = parseVersion(left);
  const b = parseVersion(right);
  const releases = Math.max(a.release.length, b.release.length);
  for (let index = 0; index < releases; index++) {
    const difference = (a.release[index] ?? 0n) > (b.release[index] ?? 0n)
      ? 1
      : (a.release[index] ?? 0n) < (b.release[index] ?? 0n)
        ? -1
        : 0;
    if (difference !== 0) return difference;
  }
  if (a.preRelease === null && b.preRelease === null) return 0;
  if (a.preRelease === null) return 1;
  if (b.preRelease === null) return -1;
  return a.preRelease < b.preRelease ? -1 : a.preRelease > b.preRelease ? 1 : 0;
}

/** Semver ordering for npm declarations; Maven's permissive version ordering is not equivalent. */
export function compareSemver(left: string, right: string): number {
  const parse = (version: string) => {
    const withoutBuild = version.trim().split('+', 1)[0] ?? '';
    const releaseAndPreRelease = withoutBuild.split('-', 2);
    const release = releaseAndPreRelease[0] ?? '';
    const preRelease = releaseAndPreRelease[1];
    return {
      release: release.split('.').map((part) => BigInt(/^\d+$/.test(part) ? part : '0')),
      preRelease: preRelease?.split('.') ?? [],
    };
  };
  const a = parse(left);
  const b = parse(right);
  for (let index = 0; index < 3; index++) {
    const difference = (a.release[index] ?? 0n) > (b.release[index] ?? 0n)
      ? 1 : (a.release[index] ?? 0n) < (b.release[index] ?? 0n) ? -1 : 0;
    if (difference !== 0) return difference;
  }
  if (a.preRelease.length === 0 || b.preRelease.length === 0) {
    return a.preRelease.length === b.preRelease.length ? 0 : a.preRelease.length === 0 ? 1 : -1;
  }
  const identifiers = Math.max(a.preRelease.length, b.preRelease.length);
  for (let index = 0; index < identifiers; index++) {
    const aIdentifier = a.preRelease[index];
    const bIdentifier = b.preRelease[index];
    if (aIdentifier === undefined || bIdentifier === undefined) {
      return aIdentifier === bIdentifier ? 0 : aIdentifier === undefined ? -1 : 1;
    }
    const aNumeric = /^\d+$/.test(aIdentifier);
    const bNumeric = /^\d+$/.test(bIdentifier);
    if (aNumeric && bNumeric) {
      const difference = BigInt(aIdentifier) > BigInt(bIdentifier) ? 1 : BigInt(aIdentifier) < BigInt(bIdentifier) ? -1 : 0;
      if (difference !== 0) return difference;
    } else if (aNumeric !== bNumeric) {
      return aNumeric ? -1 : 1;
    } else if (aIdentifier !== bIdentifier) {
      return aIdentifier < bIdentifier ? -1 : 1;
    }
  }
  return 0;
}

export function siteVersion(state: BumpState, siteId: string): string | null {
  let highest: string | null = null;
  for (const row of state.plan.rows) {
    if (row.site.id !== siteId) continue;
    const asked = state.selection[rowKey(row.site)];
    const compare = row.site.ecosystem === 'NPM' ? compareSemver : compareVersions;
    if (asked && (highest === null || compare(asked.version, highest) > 0)) {
      highest = asked.version;
    }
  }
  return highest;
}

function selectionChange(
  state: BumpState,
  row: RowKey,
  version: string,
  source: VersionSource,
): BumpState {
  const existing = state.selection[row];
  if (existing?.version === version && existing.source === source) return state;
  return { ...state, selection: { ...state.selection, [row]: { version, source } } };
}

function commandLabel(command: BumpCommand, plan: BumpPlan): string {
  switch (command.kind) {
    case 'select':
    case 'setVersion': {
      const row = rowFor(plan, command.row);
      return `Bump ${row.site.artifactId} to ${command.version}`;
    }
    case 'deselect':
      return `Deselect ${rowFor(plan, command.row).site.artifactId}`;
    case 'selectMany':
      return `Select ${command.selections.length} rows`;
    case 'deselectAll':
      return 'Deselect all rows';
    case 'editFile':
      return `Edit ${command.path}`;
  }
}

function applyToState(state: BumpState, command: BumpCommand): BumpState {
  switch (command.kind) {
    case 'select':
    case 'setVersion':
      rowFor(state.plan, command.row);
      return selectionChange(state, command.row, command.version, command.source);
    case 'deselect': {
      rowFor(state.plan, command.row);
      if (!(command.row in state.selection)) return state;
      const { [command.row]: _removed, ...selection } = state.selection;
      return { ...state, selection };
    }
    case 'selectMany': {
      for (const selection of command.selections) rowFor(state.plan, selection.row);
      let next = state;
      for (const selection of command.selections) {
        next = selectionChange(next, selection.row, selection.version, selection.source);
      }
      return next;
    }
    case 'deselectAll':
      return Object.keys(state.selection).length === 0 ? state : { ...state, selection: {} };
    case 'editFile': {
      const file = state.plan.files.find((candidate) => candidate.path === command.path);
      if (!file) throw new Error(`Unknown pom file: ${command.path}`);
      if (command.text === file.text) {
        if (!(command.path in state.files)) return state;
        const { [command.path]: _removed, ...files } = state.files;
        return { ...state, files };
      }
      if (state.files[command.path] === command.text) return state;
      return { ...state, files: { ...state.files, [command.path]: command.text } };
    }
  }
}

export function startSession(plan: BumpPlan): Session {
  return sessionWith({ plan, selection: {}, files: {} }, [], []);
}

export function apply(session: Session, command: BumpCommand): Session {
  const current = historyOf(session);
  const nextState = applyToState(current.state, command);
  if (nextState === current.state) return current;
  return sessionWith(
    nextState,
    [...current.past, { state: current.state, label: commandLabel(command, current.state.plan) }],
    [],
  );
}

export function undo(session: Session): Session {
  const current = historyOf(session);
  const entry = current.past.at(-1);
  if (!entry) return current;
  return sessionWith(
    entry.state,
    current.past.slice(0, -1),
    [{ state: current.state, label: entry.label }, ...current.future],
  );
}

export function redo(session: Session): Session {
  const current = historyOf(session);
  const [entry, ...future] = current.future;
  if (!entry) return current;
  return sessionWith(
    entry.state,
    [...current.past, { state: current.state, label: entry.label }],
    future,
  );
}

/** Collapses selections to the one file write each declaration site can receive. */
export function editsFor(state: BumpState): Array<{
  siteId: string;
  newVersion: string;
  structural: boolean;
}> {
  const edits: Array<{ siteId: string; newVersion: string; structural: boolean }> = [];
  const seen = new Set<string>();
  for (const row of state.plan.rows) {
    const { site } = row;
    if (seen.has(site.id)) continue;
    if (site.rangeAdmitsFix || (site.versionRange === null && site.insertionPoint === null)) continue;
    const version = siteVersion(state, site.id);
    if (version === null) continue;
    seen.add(site.id);
    edits.push({
      siteId: site.id,
      newVersion: version,
      structural: site.kind === 'IMPORTED_BOM' || site.kind === 'UNDECLARED',
    });
  }
  return edits;
}

export function sharedImpact(state: BumpState, siteId: string): string[] {
  const impact = new Set<string>();
  for (const row of state.plan.rows) {
    const { site } = row;
    if (site.id !== siteId || site.kind !== 'PROPERTY') continue;
    impact.add(`${site.groupId}:${site.artifactId}`);
    for (const coordinate of site.sharedWith) impact.add(coordinate);
  }
  return [...impact];
}
