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
  /**
   * An automatic scan is queued or running for this SBOM. The counts above are whatever
   * was known before it started, so a card showing this is showing an answer in progress.
   */
  scanning: boolean;
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

/** Ranked as the backend ranks them: your own code, then what you declare, then the rest. */
export const SCOPES: DependencyScope[] = ['APPLICATION', 'DIRECT', 'TRANSITIVE'];

/** Sentence-case, for a filter list — the badges in the table use SCOPE_LABELS. */
export const SCOPE_FILTER_LABELS: Record<DependencyScope, string> = {
  APPLICATION: 'Your own code',
  DIRECT: 'Direct',
  TRANSITIVE: 'Transitive',
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
  /**
   * The worst band standing against this component, or **null for never scanned**.
   *
   * Null is not `CLEAN` and must not render as it: `CLEAN` means checked and nothing found,
   * null means nobody has looked. Collapsing the two would let an unscanned SBOM read as a
   * clean one — the single ambiguity this application is most careful about.
   */
  severity: SeverityBand | null;
  /** The artifact's own registry page, or null where we have nothing safe to link. */
  registryArtifactUrl: string | null;
  /** This exact version's page, or null where that version has none. */
  registryVersionUrl: string | null;
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
  /** Defensive compatibility flag; exact enumeration normally leaves this false. */
  truncated: boolean;
  /** Exact direct routes, computed independently of the route display cap. */
  directRoutes: number;
  /** Exact transitive route count through every declaration in this module. */
  declarations: DeclarationRoutes[];
}

export interface DeclarationRoutes {
  declaration: GraphNode;
  routes: number;
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

/** Change the version you declare, force one you don't, move the parent, or drop it. */
export type RemedyKind = 'UPGRADE' | 'PIN' | 'BUMP_ANCESTOR' | 'EXCLUDE';

export const REMEDY_LABELS: Record<RemedyKind, string> = {
  UPGRADE: 'Upgrade it',
  PIN: 'Pin the version',
  BUMP_ANCESTOR: 'Bump what pulls it in',
  EXCLUDE: 'Exclude it',
};

export interface Remedy {
  kind: RemedyKind;
  /** False when it cannot be offered here — `note` says why, which beats omitting it. */
  available: boolean;
  target: string | null;
  /** Ready to paste, or null when this ecosystem has no known way to do it. */
  snippet: string | null;
  /** Advisories whose own fix version this reaches. */
  clears: string[];
  /** Advisories it cannot address, because they name no fix at all. */
  leaves: string[];
  note: string | null;
  moduleImpacts: ModuleImpact[];
}

export type RemedyCoverage = 'COMPLETE' | 'PARTIAL' | 'UNAFFECTED';

export interface ModuleImpact {
  module: string;
  /** The declaration changed by a bump; null for upgrade and pin. */
  through: string | null;
  coverage: RemedyCoverage;
  routesCovered: number;
  routesTotal: number;
  note: string | null;
}

export interface AdvisoryFix {
  osvId: string;
  cveId: string | null;
  severityScore: number | null;
  /** Null when the advisory offers no fix on this component's branch. */
  fixedVersion: string | null;
}

export interface UpgradeAdvice {
  currentVersion: string | null;
  scope: DependencyScope;
  /** Highest fix version the advisories name, so one pin addresses all of them. */
  pinTarget: string | null;
  advisories: AdvisoryFix[];
  /** The dependencies your own code declares that lead here. */
  declaredBy: string[];
  remedies: Remedy[];
  /** Null when nothing can honestly be suggested. */
  suggested: RemedyKind | null;
  /**
   * The target was checked against the local OSV archives. **Read this before
   * `targetAdvisories`**: an empty list means "clean" only when this is true, and "nobody
   * looked" otherwise.
   */
  targetEvaluated: boolean;
  /** What the target version itself carries. GHSA ratings, not CVSS scores — see below. */
  targetAdvisories: AdvisoryHit[];
}

/**
 * An advisory affecting a version you do not have.
 *
 * `rating` is the advisory's own GHSA scale (LOW/MODERATE/HIGH/CRITICAL), never a CVSS
 * score: OSV stores severity as vector strings, and the numbers elsewhere in SBOMscope were
 * computed by the scanner, which only ran against what is installed.
 */
export interface AdvisoryHit {
  osvId: string;
  cveId: string | null;
  rating: string | null;
}

export function fetchUpgradeAdvice(sbomId: string, purl: string): Promise<UpgradeAdvice> {
  return request<UpgradeAdvice>(
    `/sboms/${sbomId}/component/upgrade?purl=${encodeURIComponent(purl)}`,
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

/**
 * Download URL for the stored document, exactly as it was uploaded.
 *
 * A plain link rather than a fetch, so the browser handles the download and takes the filename
 * from `Content-Disposition` — the name it arrived under, not the `<uuid>.cdx.json` it is
 * stored as.
 */
export function sbomDocumentUrl(sbomId: string): string {
  return `/api/sboms/${sbomId}/document`;
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
  /**
   * Parsed into the upgrade-path index. Separate from `present`: an archive copied across by
   * hand is on disk and fully scannable but cannot answer "would this version be clean".
   * **Scanning never needs this** — osv-scanner reads the archive itself.
   */
  indexed: boolean;
}

export type DownloadState = 'IDLE' | 'RUNNING' | 'COMPLETED' | 'FAILED';

/** Fetching the archive and making it answerable are separate jobs with separate progress. */
export type DownloadPhase = 'DOWNLOAD' | 'INDEX';

export interface DownloadProgress {
  ecosystem: string | null;
  state: DownloadState;
  phase: DownloadPhase;
  bytesDownloaded: number;
  /** -1 when the server sent no Content-Length. */
  totalBytes: number;
  /** Advisories read while indexing. Counts up with no ceiling — the archive states no total. */
  advisoriesIndexed: number;
  message: string | null;
  startedAt: string | null;
}

/** Indexes an archive already on disk, without re-downloading it. */
export function startDatabaseIndexing(ecosystem: string): Promise<DownloadProgress> {
  return request<DownloadProgress>(
    `/settings/scanner/database/index?ecosystem=${encodeURIComponent(ecosystem)}`,
    { method: 'POST' },
  );
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

// --- Maven probe (Phase 8 Tier 2) -------------------------------------------

export interface MavenSettings {
  /** Slow enough (a real external process, sometimes several) to stay opt-in on its own. */
  enabled: boolean;
  executablePath: string | null;
  /**
   * Ceiling on `mvn dependency:tree` invocations one bump probe may spend, shared across
   * ranking every major line. The only sound lever for trading completeness for cost —
   * narrowing the search itself (a range standing in for several minor lines) answers for one
   * version and silently drops the rest.
   */
  maxProbes: number;
  /** Wall-clock ceiling for the same run — the binding constraint in practice: a cold probe
   *  repository can spend minutes on probes that take seconds once warm. */
  runBudgetMinutes: number;
  /** Comma-separated profile IDs passed to every probe as `-P<profiles>`, e.g. `"prod,internal-repo"`.
   *  Null or blank activates no profiles, Maven's own default. */
  profiles: string | null;
  /**
   * Versions of the two plugins the probe drives. Pinned rather than resolved by prefix — which
   * avoids a metadata round-trip and keeps the probe reproducible — but configurable, because
   * which version exists is a fact about the user's repository: a curated mirror proxying an
   * approved subset of Central may carry a different one. Blank resets to the shipped default.
   */
  dependencyPluginVersion: string;
  helpPluginVersion: string;
}

export interface MavenTestResult {
  ok: boolean;
  version: string | null;
  /**
   * What the plugin check verified, or null when it failed or was never reached. Reported
   * separately from `version` because they fail separately: `mvn --version` succeeds on a
   * machine where every probe will fail for want of the plugins it drives, and a green tick
   * there would send you looking for the problem everywhere except where it is.
   */
  plugins: string | null;
  error: string | null;
}

export function fetchMavenSettings(): Promise<MavenSettings> {
  return request<MavenSettings>('/settings/maven');
}

export function saveMavenSettings(settings: MavenSettings): Promise<MavenSettings> {
  return request<MavenSettings>('/settings/maven', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(settings),
  });
}

export function testMaven(): Promise<MavenTestResult> {
  return request<MavenTestResult>('/settings/maven/test', { method: 'POST' });
}

/**
 * QUEUED is distinct from RUNNING: the backend serialises every probe on a single background
 * thread (the isolated Maven repository cannot safely take concurrent writes), so a probe
 * started while another component's is in flight waits rather than running alongside it.
 * Reporting that as RUNNING would claim Maven is being probed right now for something that
 * has not started yet.
 */
export type BumpState = 'IDLE' | 'QUEUED' | 'RUNNING' | 'COMPLETED' | 'FAILED';

/**
 * One major line's answer to "what's the best version here, and what does it still carry" —
 * Tier 1's own "candidates, not a recommendation" shape, extended to the Maven probe. One row
 * per major from the currently-declared one up to the latest that exists: a later major being
 * affected does not prove an earlier one is not clean, so every major is looked at rather than
 * the search stopping at the first one that works.
 */
export interface BumpCandidate {
  /** e.g. "Stay on 2.x", "Move to 3.x", "Move to 4.x (latest)". */
  label: string;
  ancestorCoordinates: string;
  major: number;
  /** Null when {@code probed} is false. */
  version: string | null;
  targetVersion: string | null;
  /** False when the run budget was exhausted before this major was reached. */
  probed: boolean;
  clean: boolean;
  clearsCriticalAndHigh: boolean;
  /** Advisories remaining at {@code targetVersion} — never a count. */
  stillCarries: AdvisoryHit[];
  snippet: string | null;
  /**
   * The run budget ran out partway through this major, so higher releases within it were never
   * checked. Distinguishes "the highest 2.x still carries this" from "we got as far as 2.7.18
   * and stopped" — the first is a verdict on the whole major, the second says nothing about
   * what sits above it.
   */
  higherReleasesUnchecked: boolean;
}

/**
 * Progress of one component's bump probe. {@code candidates} is the ranked list for the
 * primary declaring ancestor; {@code remedy} reuses the exact {@link Remedy} shape Tier 1's
 * remedies already use, but only for the failure/unavailable paths and the multi-ancestor
 * combination result — it is null whenever the ranked list is the whole answer.
 */
/**
 * One attempt the search made, and what came of it.
 *
 * `major` is the grouping key — null for the steps that belong to no single line: calibration,
 * the opening feasibility probe, and the combination fallback. That is a real answer, not
 * missing data: those precede the per-major search.
 *
 * `text` is the line as it has always read, so the log wording is the backend's, not a second
 * rendering of the same facts assembled here.
 */
export interface ProbeStep {
  major: number | null;
  kind: 'CALIBRATION' | 'FEASIBILITY' | 'CANDIDATE' | 'COMBINATION';
  requested: string | null;
  /** `NOT_CHECKED` is deliberately not `AFFECTED` — "we did not find out" is not "we found a problem". */
  outcome: 'CLEAN' | 'AFFECTED' | 'NOT_CHECKED' | 'FAILED' | 'INFO';
  text: string;
}

export interface BumpProgress {
  state: BumpState;
  /** One entry per probe as it completes, e.g. "[4.2.0] → jackson-databind 3.1.6 → clean". */
  verdicts: ProbeStep[];
  candidates: BumpCandidate[];
  remedy: Remedy | null;
  message: string | null;
  /** Null until calibration has run — the deciding ancestor is read from that probe's tree. */
  scope: BumpScope | null;
}

/** Starts the probe if one is not already running or cached, and returns current progress. */
export function startBump(sbomId: string, purl: string): Promise<BumpProgress> {
  return request<BumpProgress>(`/sboms/${sbomId}/component/bump?purl=${encodeURIComponent(purl)}`, {
    method: 'POST',
  });
}

/**
 * Extends a finished run the budget cut short, keeping the rows it already settled and
 * spending a fresh budget only on the majors still unfinished. `startBump` deliberately
 * refuses to re-run a completed probe, so this is the way to ask for more of the same search.
 */
export function continueBump(sbomId: string, purl: string): Promise<BumpProgress> {
  return request<BumpProgress>(
    `/sboms/${sbomId}/component/bump/continue?purl=${encodeURIComponent(purl)}`,
    { method: 'POST' },
  );
}

export function fetchBumpProgress(sbomId: string, purl: string): Promise<BumpProgress> {
  return request<BumpProgress>(`/sboms/${sbomId}/component/bump?purl=${encodeURIComponent(purl)}`);
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
  /** `group:name`, still sent because several views want the whole coordinate. */
  coordinates: string;
  /**
   * The two halves, supplied separately so the table can stack them.
   *
   * `group` is null for an npm package with no scope (`lodash`). The cell reserves its line
   * regardless, so rows keep one height — which matters more than usual for the column that
   * stays put while the table scrolls sideways.
   */
  group: string | null;
  name: string;
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
  /** The artifact's own registry page, or null where we have nothing safe to link. */
  registryArtifactUrl: string | null;
  /**
   * This exact version's page. Null where that version has none — a vendor-patched
   * a.b.c.d build has no page on Central — so the version renders unlinked while the
   * component name still reaches the artifact page.
   */
  registryVersionUrl: string | null;
  /**
   * The date CISA added this CVE to the Known Exploited Vulnerabilities catalogue.
   *
   * Null is **not** a clearance. It covers two states, which the cell tells apart using what it
   * already has: a row with no `cveId` cannot be looked up in a CVE-keyed catalogue at all, and
   * a row with one simply is not listed. The third state — nobody downloaded the catalogue — is
   * identical on every row at once and arrives as `exploitFeedsLoaded` on the status instead.
   */
  kevListedOn: string | null;
  /** CISA has confirmed ransomware use. A positive signal only: false is not a denial. */
  kevRansomware: boolean;
  /** Probability of exploitation in the next 30 days, or null where EPSS does not score it. */
  epssScore: number | null;
  /** Where that score sits among all scored CVEs — what makes 0.033 mean something. */
  epssPercentile: number | null;
  /** CISA's page for this CVE. Present only when listed, so no cell links to an empty search. */
  kevUrl: string | null;
}

/**
 * FIXED_VERSION orders by the version an advisory names as the fix, as a version rather than
 * as a string. Rows with no fix sort last in both directions — "no fix" is not a version.
 */
/**
 * `PUBLISHED` is the only honest way to order these rows by age — sorting by CVE id was
 * considered and rejected, because the sequence number is not zero-padded and `CVE-2020-9547`
 * lexically follows `CVE-2020-10001`. `GHSA_RATING` is GitHub's own word, not the CVSS band,
 * and the two disagree often enough that both are worth sorting by.
 */
/**
 * `KEV` orders by the date CISA listed the CVE, not by a flag — descending then opens on the
 * most recently listed rather than on an arbitrary member of one group. It is deliberately the
 * whole KEV interaction: a filter was considered and refused, because with a handful of listed
 * rows one header click is the same outcome with no state to persist. `EPSS` orders by the
 * probability. Both put rows with nothing to say last in either direction.
 */
export type SortField =
  | 'COMPONENT'
  | 'SEVERITY'
  | 'FIXED_VERSION'
  | 'SCOPE'
  | 'PUBLISHED'
  | 'GHSA_RATING'
  | 'KEV'
  | 'EPSS';

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
  /**
   * Whether `filter` is a regular expression rather than a literal substring.
   *
   * Off by default, and deliberately a mode rather than a guess: a purl is made almost
   * entirely of dots, so reading every filter as a regex would silently widen `spring.core`
   * to also match `springXcore`, and would start rejecting literals containing `(` or `[`.
   */
  regex: boolean;
  /**
   * Show the rows the filter does *not* match.
   *
   * Independent of `regex`: "hide everything from org.springframework" and "hide everything
   * matching `(ABC|DEF)`" are the same question at two levels of precision, so tying exclusion
   * to regex would make the simpler one unavailable.
   */
  negate: boolean;
  /** Empty means every band; the backend treats it the same way. */
  severities: SeverityBand[];
  /**
   * Which dependency scopes to show. Empty means all three, as the backend also reads it.
   * Unlike severity, the default is everything: there is no scope a reader is normally not
   * interested in, so this narrows rather than opening pre-narrowed.
   */
  scopes: DependencyScope[];
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
  /**
   * Which of two different things makes it stale. `ARCHIVE_REFRESHED` means a newer OSV
   * archive is on disk than these results were produced against — a fact about this machine,
   * and actionable now; `AGED` is only the staleAfterDays clock.
   */
  staleReason: 'NONE' | 'AGED' | 'ARCHIVE_REFRESHED';
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
  /**
   * Which exploitation feeds have data behind them, e.g. `['KEV', 'EPSS']`.
   *
   * Carried here rather than fetched separately so the notice above the table and the cells
   * below it cannot describe different states. A feed missing from this list means its column
   * is empty on *every* row for one reason — nobody downloaded it — which is a fact about the
   * installation and belongs stated once, not stamped into three hundred cells.
   */
  exploitFeedsLoaded: string[];
  /** The current page only. */
  rows: FindingRow[];
}

/**
 * @param scopeParam what to call the dependency-scope filter. The export endpoint already
 *   uses `scope` for its visible/all selector, so there it is sent as `scope_filter` — two
 *   meanings on one parameter name is exactly how an export stops matching its screen.
 */
function queryParams(query: FindingQuery, scopeParam = 'scope'): URLSearchParams {
  const params = new URLSearchParams({
    sort: query.sort,
    direction: query.ascending ? 'asc' : 'desc',
  });
  // A regex is sent verbatim; a literal is trimmed. Leading and trailing whitespace is
  // meaningful in a pattern and is a typing artefact in a substring, so trimming both would
  // quietly rewrite one of them. The backend reads the same rule from the same flag.
  const filter = query.regex ? query.filter : query.filter.trim();
  if (filter) {
    params.set('filter', filter);
    if (query.regex) {
      params.set('regex', 'true');
    }
    // Only meaningful with a filter to negate — sent alone it would ask the backend to exclude
    // nothing, which is what it already does.
    if (query.negate) {
      params.set('negate', 'true');
    }
  }
  // Always sent explicitly. Omitting them would make the backend fall back to its
  // default of vulnerabilities-only, silently dropping clean components for a user who
  // had deliberately selected every band.
  query.severities.forEach((band) => params.append('severity', band));
  query.scopes.forEach((scope) => params.append(scopeParam, scope));
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
  const params = queryParams(query, 'scope_filter');
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

export type PurgeTarget =
  | 'SBOMS'
  | 'FINDINGS'
  | 'SETTINGS'
  | 'OSV_DATABASE'
  | 'ROLLED_LOGS'
  | 'MAVEN_PROBE_CACHE';

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

// --- exploitation signals ----------------------------------------------------

/**
 * One feed's state.
 *
 * `present` and `loaded` are separate on purpose: a file copied across on a USB stick is
 * present and not loaded, and re-downloading it to fix that would be pointless on a connected
 * machine and impossible on a disconnected one.
 */
export interface ExploitFeedStatus {
  /** `KEV` or `EPSS`. */
  feed: string;
  label: string;
  /** Shown verbatim, so nothing is ever downloaded from an address the reader cannot see. */
  sourceUrl: string;
  path: string;
  present: boolean;
  sizeBytes: number;
  /**
   * There are rows for this feed, whatever is on disk now — the question the *cells* answer,
   * and therefore the one the findings notice asks. Data loaded from a catalogue survives that
   * catalogue being moved or deleted.
   */
  hasData: boolean;
  /**
   * Rows exist **and** were built from the file currently on disk. The stricter claim, and the
   * right one here: it is what decides whether the Load button is worth offering.
   */
  loaded: boolean;
  /**
   * The feed's **own** claim about when its data is from — `dateReleased` for KEV,
   * `score_date` for EPSS — never a download timestamp. That is what makes it equally true
   * of a file carried across by hand.
   */
  asOf: string | null;
  /** `catalogVersion` for KEV, `model_version` for EPSS. */
  version: string | null;
  rows: number;
}

export type FeedState = 'IDLE' | 'RUNNING' | 'COMPLETED' | 'FAILED';
export type FeedPhase = 'DOWNLOAD' | 'LOAD';

export interface FeedProgress {
  feed: string | null;
  state: FeedState;
  phase: FeedPhase;
  bytesDownloaded: number;
  /** -1 when the server sent no Content-Length. */
  totalBytes: number;
  /** Rows written so far while loading. Counts up with no ceiling. */
  rowsLoaded: number;
  message: string | null;
  startedAt: string | null;
}

export interface ExploitFeedsResponse {
  feeds: ExploitFeedStatus[];
  progress: FeedProgress;
}

export function fetchExploitFeeds(): Promise<ExploitFeedsResponse> {
  return request<ExploitFeedsResponse>('/exploit-feeds');
}

export function fetchFeedProgress(): Promise<FeedProgress> {
  return request<FeedProgress>('/exploit-feeds/progress');
}

/** Downloads and loads. The one action here that touches the network. */
export function refreshExploitFeed(feed: string): Promise<FeedProgress> {
  return request<FeedProgress>(`/exploit-feeds/${encodeURIComponent(feed)}/refresh`, {
    method: 'POST',
  });
}

/** Loads a file already on disk — the air-gapped path. */
export function loadExploitFeed(feed: string): Promise<FeedProgress> {
  return request<FeedProgress>(`/exploit-feeds/${encodeURIComponent(feed)}/load`, {
    method: 'POST',
  });
}

// --- logging -----------------------------------------------------------------

export interface LogStatus {
  /** Absolute path to the directory holding sbomscope.log and activity.jsonl. */
  path: string;
  /** False in headless environments — the caller falls back to the copyable path alone. */
  canOpenFolder: boolean;
}

export type ActivityCategory = 'NETWORK' | 'PROCESS' | 'DATA';

/**
 * One notable event: anything touching the network, running an external process, or
 * changing stored data.
 */
export interface ActivityEvent {
  /** ISO-8601 instant. */
  timestamp: string;
  category: ActivityCategory;
  event: string;
  /** Absent for events that describe a change rather than a result. */
  outcome: 'STARTED' | 'SUCCESS' | 'FAILURE' | null;
  detail: string | null;
}

export function fetchLogStatus(): Promise<LogStatus> {
  return request<LogStatus>('/logs/status');
}

/** Only meaningful because the backend runs on the user's own machine. */
export function openLogFolder(): Promise<LogStatus> {
  return request<LogStatus>('/logs/open-folder', { method: 'POST' });
}

/**
 * @param filter matched against the columns the panel shows, not the stored JSON
 * @param regex  read `filter` as a Java regular expression rather than as literal text
 */
export function fetchActivity(limit = 200, filter = '', regex = false, negate = false): Promise<ActivityEvent[]> {
  return request<ActivityEvent[]>(`/logs/activity?${logParams(limit, filter, regex, negate)}`);
}

/**
 * The filter reaches the backend rather than being applied to what arrived, because the
 * backend can look further back than the limit. Filtering here would search only the last
 * page and report an entry that plainly happened as absent.
 */
function logParams(limit: number, filter: string, regex: boolean, negate: boolean): URLSearchParams {
  const params = new URLSearchParams({ limit: String(limit) });
  // A regex goes verbatim; a literal is trimmed. Whitespace means something in a pattern.
  const value = regex ? filter : filter.trim();
  if (value) {
    params.set('filter', value);
    if (regex) params.set('regex', 'true');
    if (negate) params.set('negate', 'true');
  }
  return params;
}

/**
 * The verbose log, oldest line first — every `mvn` command and everything Maven said back.
 * A transcript rather than a record of events, so it is read top to bottom.
 */
export function fetchLogText(limit = 500, filter = '', regex = false, negate = false): Promise<string[]> {
  return request<string[]>(`/logs/text?${logParams(limit, filter, regex, negate)}`);
}

// --- the probe queue ---------------------------------------------------------

/**
 * One probe the backend is running or holding.
 *
 * Addressed globally rather than per component, because the reader who needs this is the one
 * who no longer knows which component started it — `sbomId` and `purl` are what get them back.
 */
export interface ProbeTask {
  id: string;
  sbomId: string;
  purl: string | null;
  component: string;
  /** The owning module the probe is answering for; null when the graph named none. */
  module: string | null;
  /**
   * Finished probes are kept for the session, most recent first, after the live ones —
   * "did that thing I started actually do anything" is asked right after it stops. STOPPED is
   * distinct from COMPLETED because a run cut short and one that reached the end of its budget
   * are different claims about how much of the search happened.
   */
  state: 'QUEUED' | 'RUNNING' | 'COMPLETED' | 'STOPPED' | 'FAILED';
  /** ISO-8601 instant. */
  submittedAt: string;
  /** ISO-8601 instant, or null while still queued. Elapsed time is derived from these. */
  startedAt: string | null;
  /** ISO-8601 instant, or null while queued or running. */
  finishedAt: string | null;
}

export const PROBE_FINISHED: readonly ProbeTask['state'][] = ['COMPLETED', 'STOPPED', 'FAILED'];

/**
 * What the ranked candidates are an answer *about* — two diamonds, one level apart.
 *
 * Across modules, several may own the component and only the most-affected one is probed.
 * Within that module, several direct dependencies may pull it in and only one is the
 * declaration Maven honours. A version with neither stated does not say what to bump, nor
 * where the answer holds.
 */
export interface BumpScope {
  module: string | null;
  /** Owning modules that were not probed; their direct sets differ, so their answer may too. */
  otherModules: string[];
  /** The direct dependency being bumped. */
  ancestor: string;
  ancestorVersion: string | null;
  /** Also reach the component, but Maven does not resolve through them, so bumping them alone
   *  cannot move it. Listed, never ranked. */
  otherAncestors: string[];
  /** False when the tree could not be read and the ancestor fell back to the shortest route. */
  decidedByMaven: boolean;
  /** Exact route coverage, independent of the graph panel's display cap. */
  routesCovered: number;
  routesTotal: number;
}

/** Running, queued, and recently finished — live rows first, then this session's history. */
export function fetchProbeQueue(): Promise<ProbeTask[]> {
  return request<ProbeTask[]>('/probes');
}

/** Stops a probe, running or queued. Settled rows survive; Continue resumes the search. */
export function cancelProbe(id: string): Promise<void> {
  return request<void>(`/probes/${encodeURIComponent(id)}`, { method: 'DELETE' });
}
