/**
 * Thin fetch wrapper. Kept deliberately small — there is no client-side data
 * library, because the backend is the source of truth and every call is a plain
 * request against our own origin.
 */

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

/** Shape the backend's ApiExceptionHandler returns for every failure. */
interface ApiErrorBody {
  message?: string;
}

async function failureFor(response: Response, path: string): Promise<ApiError> {
  // Prefer the backend's own message: it is written for users and explains what
  // was wrong with their file, which a generic status text cannot.
  try {
    const body = (await response.json()) as ApiErrorBody;
    if (body?.message) {
      return new ApiError(body.message, response.status);
    }
  } catch {
    // Non-JSON error body; fall through to the generic message.
  }
  return new ApiError(`Request to ${path} failed (${response.status})`, response.status);
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`/api${path}`, {
    headers: { Accept: 'application/json' },
    ...init,
  });

  if (!response.ok) {
    throw await failureFor(response, path);
  }

  if (response.status === 204) {
    return undefined as T;
  }

  return (await response.json()) as T;
}

export interface ServerStatus {
  application: string;
  version: string;
  /** ISO-8601 instant reported by the backend. */
  startedAt: string;
}

export function fetchServerStatus(): Promise<ServerStatus> {
  return request<ServerStatus>('/status');
}

export interface Sbom {
  id: string;
  filename: string;
  /** ISO-8601 instant. */
  uploadedAt: string;
  /** Absent when the SBOM was uploaded without a source tree. */
  workspacePath?: string;
  specVersion: string;
  componentCount: number;
  /**
   * How many of its components carry a scan record. Zero means the scanner has never
   * reached this SBOM, and `severityCounts` then describes nothing — read it first, or a
   * card will report an unexamined document as having no critical vulnerabilities.
   */
  scannedComponents: number;
  /** Rows per band across the whole SBOM, unfiltered. Same numbers as the findings page. */
  severityCounts: Partial<Record<SeverityBand, number>>;
}

/**
 * Where a component sits relative to your own code.
 *
 * APPLICATION is your own modules — a finding there is yours to fix, not to upgrade.
 * DIRECT is declared in your pom.xml or package.json. TRANSITIVE was pulled in for you.
 */
export type DependencyScope = 'APPLICATION' | 'DIRECT' | 'TRANSITIVE';

export const SCOPE_LABELS: Record<DependencyScope, string> = {
  APPLICATION: 'application',
  DIRECT: 'direct',
  TRANSITIVE: 'transitive',
};

export interface SbomComponent {
  id: string;
  /** group:name for Maven, plain name otherwise. */
  coordinates: string;
  group?: string;
  name: string;
  version?: string;
  purl?: string;
  type?: string;
  root: boolean;
  scope: DependencyScope;
  /** Public registry page, or null for ecosystems we cannot link. */
  registryUrl: string | null;
}

export function fetchSboms(): Promise<Sbom[]> {
  return request<Sbom[]>('/sboms');
}

export function fetchComponents(sbomId: string): Promise<SbomComponent[]> {
  return request<SbomComponent[]>(`/sboms/${sbomId}/components`);
}

/** Everything the Component Inspector knows about one component. */
export interface ComponentDetail {
  component: SbomComponent;
  /**
   * ISO-8601 instant, or null when this component's purl has never been checked. Read it
   * before `findings`: an empty list from an unscanned component looks exactly like a clean
   * bill of health, and is not one.
   */
  scannedAt: string | null;
  /**
   * The same rows the findings table shows for this component, from the same query. A
   * single row with `osvId` null means checked, nothing found.
   */
  findings: FindingRow[];
}

/**
 * Keyed by purl, matching the findings table's own unit — its query collapses a library
 * listed twice in one document into one row, so a row identifies a purl rather than a
 * component record. Sent as a query parameter because a purl contains slashes, and an
 * encoded slash in a path segment is rejected outright by some servlet containers.
 */
export function fetchComponentDetail(sbomId: string, purl: string): Promise<ComponentDetail> {
  return request<ComponentDetail>(
    `/sboms/${sbomId}/component?purl=${encodeURIComponent(purl)}`,
  );
}

/** A component as the dependency graph refers to it — enough to render and open a step. */
export interface GraphNode {
  bomRef: string;
  coordinates: string;
  version: string | null;
  purl: string | null;
  root: boolean;
  scope: DependencyScope;
  /** Has at least one known vulnerability, so a chain shows where else the problem sits. */
  vulnerable: boolean;
}

/** How one of your own modules reaches the component. */
export interface ModuleRoutes {
  module: GraphNode;
  /** The shortest few, each running module → … → component inclusive. */
  routes: GraphNode[][];
  totalRoutes: number;
  /** Enumeration hit its limit, so totalRoutes is a floor rather than a count. */
  truncated: boolean;
}

export interface GraphTreeNode {
  node: GraphNode;
  children: GraphTreeNode[];
  /** Expanded elsewhere in the tree; shown here but not rebuilt. */
  repeated: boolean;
  /** Already on the path above this point — a real cycle, not a rendering artefact. */
  cyclic: boolean;
}

export interface ComponentGraph {
  /** Every module that pulls this in. Never abbreviated. */
  reachedFrom: ModuleRoutes[];
  /**
   * The denominator, so reachedFrom reads as "3 of your 4 modules". Excludes the root of an
   * aggregate build: the parent pom aggregates rather than depends, so no route tops out at
   * it and counting it would understate every ratio.
   */
  ownModuleCount: number;
  /** The component is one of your own modules: nothing above it, nothing to upgrade. */
  targetIsOwnCode: boolean;
  tree: GraphTreeNode | null;
}

export function fetchComponentGraph(sbomId: string, purl: string): Promise<ComponentGraph> {
  return request<ComponentGraph>(
    `/sboms/${sbomId}/component/graph?purl=${encodeURIComponent(purl)}`,
  );
}

export function uploadSbom(file: File, workspacePath?: string): Promise<Sbom> {
  const form = new FormData();
  form.append('file', file);
  if (workspacePath && workspacePath.trim()) {
    form.append('workspacePath', workspacePath.trim());
  }

  // No Content-Type header: the browser must set the multipart boundary itself.
  return request<Sbom>('/sboms', { method: 'POST', body: form });
}

export function deleteSbom(sbomId: string): Promise<void> {
  return request<void>(`/sboms/${sbomId}`, { method: 'DELETE' });
}

// --- vulnerability scanning ------------------------------------------------

export interface ScannerSettings {
  /** When false, SBOMscope runs as an inventory and reports vulnerabilities as unanalysed. */
  enabled: boolean;
  /** Path to the osv-scanner binary. SBOMscope never downloads it. */
  executablePath: string | null;
  databaseDirectory: string;
}

export interface DatabaseStatus {
  ecosystem: string;
  present: boolean;
  sizeBytes: number;
  lastModified: string | null;
  /** Absolute path of the archive on disk. */
  path: string;
  /** Exactly what gets fetched. */
  sourceUrl: string;
}

export type DownloadState = 'IDLE' | 'RUNNING' | 'COMPLETED' | 'FAILED';

export interface DownloadProgress {
  ecosystem: string | null;
  state: DownloadState;
  bytesDownloaded: number;
  /** -1 when the server sent no Content-Length. */
  totalBytes: number;
  message: string | null;
  startedAt: string | null;
}

export interface ScannerStatus {
  settings: ScannerSettings;
  database: DatabaseStatus[];
  download: DownloadProgress;
}

export interface ScannerTestResult {
  ok: boolean;
  version: string | null;
  error: string | null;
}

export function fetchScannerStatus(): Promise<ScannerStatus> {
  return request<ScannerStatus>('/settings/scanner');
}

export function saveScannerSettings(settings: ScannerSettings): Promise<ScannerStatus> {
  return request<ScannerStatus>('/settings/scanner', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(settings),
  });
}

export function testScanner(): Promise<ScannerTestResult> {
  return request<ScannerTestResult>('/settings/scanner/test', { method: 'POST' });
}

// --- findings --------------------------------------------------------------

/**
 * One row of the view: a component, plus one vulnerability affecting it — or none.
 *
 * A component with three advisories yields three rows; a component with nothing known
 * against it yields one row with `osvId` null.
 */
export interface FindingRow {
  purl: string;
  coordinates: string;
  version: string | null;
  root: boolean;
  scope: DependencyScope;
  /** Null when this component has no known vulnerability. */
  osvId: string | null;
  /** Null for advisories with no CVE counterpart. */
  cveId: string | null;
  summary: string | null;
  /** Null for an unscored advisory *and* for a clean component — check osvId to tell. */
  severityScore: number | null;
  /**
   * GitHub's own qualitative label (LOW/MODERATE/HIGH/CRITICAL), not the CVSS band for
   * severityScore. A different scale from a different source, so shown in its own column.
   */
  severityRating: string | null;
  /** CVSS_V3 or CVSS_V4 — the two are not directly comparable. */
  cvssVersion: string | null;
  /** Null when the advisory group disagreed and no vector could be attributed. */
  cvssVector: string | null;
  fixedVersion: string | null;
  publishedAt: string | null;
  /** The advisory's own record on osv.dev; null with no finding. */
  osvUrl: string | null;
  /** NVD; null when the advisory has no CVE counterpart. */
  cveUrl: string | null;
  /** Public registry page for the component, or null when we cannot link it. */
  registryUrl: string | null;
}

export type SortField = 'COMPONENT' | 'SEVERITY';

/**
 * NONE and CLEAN are deliberately distinct: NONE is a real vulnerability whose advisory
 * carries no CVSS score, CLEAN is a component with no vulnerability at all. Merging them
 * would let "unknown severity" read as "nothing wrong".
 */
export type SeverityBand = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE' | 'CLEAN';

export const SEVERITY_BANDS: SeverityBand[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE', 'CLEAN'];

/** Everything except CLEAN — the default, so the view opens on what needs attention. */
export const VULNERABLE_BANDS: SeverityBand[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE'];

export const SEVERITY_LABELS: Record<SeverityBand, string> = {
  CRITICAL: 'Critical',
  HIGH: 'High',
  MEDIUM: 'Medium',
  LOW: 'Low',
  NONE: 'Unscored',
  CLEAN: 'No vulnerabilities',
};

export interface FindingQuery {
  sort: SortField;
  ascending: boolean;
  filter: string;
  /** Empty means every band; the backend treats it the same way. */
  severities: SeverityBand[];
  pageSize: number;
  page: number;
}

/**
 * Why a scan cannot run, or READY when it can.
 *
 * Checked per SBOM: the databases required depend on which ecosystems the document
 * actually contains, so a Maven-only SBOM is never blocked on the npm archive.
 */
export type ScanBlocker =
  | 'READY'
  | 'SCANNING_DISABLED'
  | 'NO_EXECUTABLE'
  | 'EXECUTABLE_MISSING'
  | 'NO_DATABASE';

export interface ScanReadiness {
  ready: boolean;
  reason: ScanBlocker;
  /** Which path, or which ecosystems — the specifics behind the reason code. */
  detail: string | null;
}

export interface ScanStatus {
  lastScannedAt: string | null;
  scannedComponents: number;
  totalComponents: number;
  /** True when results are old, and also when nothing has ever been scanned. */
  stale: boolean;
  staleAfterDays: number;
  /** The settings toggle alone. `readiness` is the stronger "would it actually work". */
  scanningEnabled: boolean;
  readiness: ScanReadiness;
  /** Vulnerabilities across the whole SBOM, ignoring every filter. */
  findingCount: number;
  /**
   * Rows per band, unfiltered. The five vulnerable bands sum to findingCount; CLEAN is
   * also present and counts components with nothing against them, so it is not part of
   * that sum.
   */
  severityCounts: Partial<Record<SeverityBand, number>>;
  /** Rows matching the current filter — the size an unpaged export would have. */
  filteredCount: number;
  /** The current page only. */
  rows: FindingRow[];
}

function queryParams(query: FindingQuery): URLSearchParams {
  const params = new URLSearchParams({
    sort: query.sort,
    direction: query.ascending ? 'asc' : 'desc',
  });
  if (query.filter.trim()) {
    params.set('filter', query.filter.trim());
  }
  // Always sent explicitly. Omitting them would make the backend fall back to its
  // default of vulnerabilities-only, silently dropping clean components for a user who
  // had deliberately selected every band.
  query.severities.forEach((band) => params.append('severity', band));
  return params;
}

export interface ScanRunResult {
  componentsScanned: number;
  findings: number;
  scannedAt: string;
  scannerVersion: string;
}

export function fetchFindings(sbomId: string, query: FindingQuery): Promise<ScanStatus> {
  const params = queryParams(query);
  params.set('limit', String(query.pageSize));
  params.set('offset', String(query.page * query.pageSize));
  return request<ScanStatus>(`/sboms/${sbomId}/findings?${params}`);
}

/**
 * Download URL for the export. Built as a plain link rather than a fetch so the browser
 * handles the download itself, filename and all.
 *
 * @param scope 'visible' reproduces the current page, filter and sort; 'all' keeps only
 *              the sort and exports every finding.
 */
export function exportUrl(
  sbomId: string,
  query: FindingQuery,
  scope: 'visible' | 'all',
  visibleColumns?: string[],
): string {
  const params = queryParams(query);
  params.set('scope', scope);
  if (scope === 'visible') {
    params.set('limit', String(query.pageSize));
    params.set('offset', String(query.page * query.pageSize));
  }
  // Sent always. Whether they narrow the workbook is a server-side setting, so the decision
  // is made in one place rather than the browser and the backend each having an opinion.
  visibleColumns?.forEach((column) => params.append('column', column));
  return `/api/sboms/${sbomId}/export.xlsx?${params}`;
}

export interface ExportSettings {
  /** False (the default) writes every column SBOMscope holds, whatever the screen shows. */
  visibleColumnsOnly: boolean;
}

export function fetchExportSettings(): Promise<ExportSettings> {
  return request<ExportSettings>('/settings/export');
}

export function saveExportSettings(settings: ExportSettings): Promise<ExportSettings> {
  return request<ExportSettings>('/settings/export', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(settings),
  });
}

// --- maintenance -----------------------------------------------------------

export type PurgeTarget = 'SBOMS' | 'FINDINGS' | 'SETTINGS' | 'OSV_DATABASE';

export interface PurgeResult {
  /** Target name to a sentence describing what went, so the confirmation states facts. */
  removed: Record<string, string>;
}

/** Irreversible. The backend rejects anything but PURGE or DELETE as confirmation. */
export function purge(confirmation: string, targets: PurgeTarget[]): Promise<PurgeResult> {
  return request<PurgeResult>('/maintenance/purge', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ confirmation, targets }),
  });
}

export function runScan(sbomId: string): Promise<ScanRunResult> {
  return request<ScanRunResult>(`/sboms/${sbomId}/scan`, { method: 'POST' });
}

/** Starts the download and returns immediately; poll fetchDownloadProgress for the rest. */
export function startDatabaseDownload(ecosystem: string): Promise<DownloadProgress> {
  return request<DownloadProgress>(
    `/settings/scanner/database/download?ecosystem=${encodeURIComponent(ecosystem)}`,
    { method: 'POST' },
  );
}

export function fetchDownloadProgress(): Promise<DownloadProgress> {
  return request<DownloadProgress>('/settings/scanner/database/progress');
}
