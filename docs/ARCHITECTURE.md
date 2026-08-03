# SBOMscope — Architecture

Reference for how the pieces fit together. Read alongside [AGENTS.md](../AGENTS.md)
(constraints and conventions) and [IMPLEMENTATION-PLAN.md](IMPLEMENTATION-PLAN.md)
(what is built, what is next, and why decisions were made).

---

## One artifact, two halves

`mvn clean package` produces a single runnable jar at `backend/target/sbomscope.jar`
containing both the API and the UI.

The `frontend` module builds with Vite, writing its output directly to
`target/classes/META-INF/resources`. Packaged as a jar, that path is classpath static
content, which Spring Boot serves automatically. The `backend` module depends on the
frontend jar at runtime scope, so the UI travels inside the application.

`SpaResourceConfig` serves that content and forwards unknown non-API paths to
`index.html`, so a deep link like `/settings` survives a browser refresh. Requests
beginning `api/` deliberately still 404 — a mistyped fetch URL should fail as a missing
endpoint, not as an HTML parse error.

During development the Vite dev server on :5173 proxies `/api` to :8080, so the UI can
hot-reload against a running backend.

The backend binds to `127.0.0.1` by default. Its HTTP API is intentionally unauthenticated and is
therefore a single-user local boundary: changing settings, supplying workspace paths, starting
processes, downloading stored SBOMs and erasing local data must not be exposed to another host by
default. Spring external configuration can deliberately override `server.address`, but an
operator doing so must supply the authentication/network boundary that SBOMscope does not have.
CORS is only a browser-origin policy and is not such a boundary.

---

## Data model

All created by Flyway migrations under `backend/src/main/resources/db/migration`.

```
sbom                     an uploaded document
  id, filename, uploaded_at, workspace_path, spec_version, component_count

component                one library within one SBOM
  id, sbom_id → sbom, bom_ref, group_name, name, version, purl,
  component_type, is_root, dependency_scope
  UNIQUE (sbom_id, bom_ref)

component_dependency     the dependency graph
  sbom_id, from_bom_ref, to_bom_ref

app_setting              user-editable settings
  setting_key, setting_value, updated_at

vulnerability_scan       "this purl was checked, at this time"
  purl, scanned_at, scanner_version

vulnerability_finding    one vulnerability affecting one purl
  id, purl → vulnerability_scan, osv_id, cve_id, summary,
  severity_score, severity_rating, cvss_vector, cvss_version,
  fixed_version, fixed_version_sort, published_at
  UNIQUE (purl, osv_id)

osv_index                the OSV archives, parsed for candidate-version evaluation
  ecosystem, package_name, osv_id, cve_id, rating, affected
  PRIMARY KEY (ecosystem, package_name, osv_id)

osv_index_source         which archive produced it, so a refresh invalidates it
  ecosystem, identity, advisories, packages, built_at

kev_entry                CISA's Known Exploited Vulnerabilities catalogue (V4)
  cve_id, vendor_project, product, vulnerability_name, date_added,
  short_description, required_action, due_date, known_ransomware, notes, cwes

kev_source               which download produced it — one row, enforced
  catalog_version, date_released, entry_count, loaded_entries, identity, loaded_at

epss_score               FIRST's daily exploitation probabilities (V5)
  cve_id, score, percentile

epss_source              which file produced it — one row, enforced
  model_version, score_date, loaded_scores, identity, loaded_at

workspace_analysis_run   one fingerprinted analysis of an attached workspace
  id, sbom_id → sbom, input_fingerprint, status, engine, algorithm, blockers,
  error_message, requested_at, started_at, finished_at

workspace_reachability_evidence
  id, analysis_run_id → workspace_analysis_run, purl, module_path, status,
  method_paths, detail
```

`osv_index` (V2) is **derived data**: rebuildable from the archive at any time, and erasing
the archives takes it and `osv_index_source` with them. It exists because the archives name
their entries by advisory id rather than by package, so finding one library's advisories means
parsing all of them — 5.2 s and ~152 MB retained for npm, measured. Parsed once into a table
instead, a lookup is an indexed `SELECT` and nothing is held in memory.

`osv_index_source.identity` is the archive's path, size and modification time. It is compared
rather than trusted, so replacing a download invalidates the index by itself, and it is
written **last** so an interrupted build leaves rows nothing considers usable — the same
reasoning as `all.zip.partial`.

Everything above `osv_index` is created by a single `V1__baseline.sql` — the original V1–V4,
squashed once while SBOMscope was pre-release. The repository went public on 2026-07-29, so
that exception is closed: see constraint 8 in [AGENTS.md](../AGENTS.md) — every migration from
here on is additive, `V1__baseline.sql` included. `V2__osv_index.sql` is additive rather than folded in: the
baseline is now installed with real data behind it, and folding would cost a database nobody
needs to lose for a table nothing supersedes.

`kev_entry` and `epss_score` (V4, V5) are **derived data** on the same terms as `osv_index`:
rebuildable from a downloaded file at any time, and erased with it. Each has its own source row
recording the feed's own identity — `catalogVersion`/`dateReleased` for KEV,
`model_version`/`score_date` for EPSS — because those are the feeds' claims about themselves and
are what the UI states as an as-of date. Both source rows are **written last**, so a load
interrupted halfway leaves rows nothing considers usable. That matters more for KEV than
anywhere else in this schema: every entry missing from a half-loaded catalogue renders as *"not
known to be exploited"*.

Two migrations rather than one, because KEV and EPSS are independent feeds with different
shapes, cadences and licences, and additive-only means a later split would not be available.

### Local-data purge boundaries

Purge empties owned tables and files; it never removes the live H2 database file or Flyway's
schema history. The **Offline vulnerability data** target is one recovery unit: OSV archives,
`osv_index`, `osv_index_source`, and the KEV and EPSS files and rows all go together because
each store is derived and restored by its source's existing load/index action.

Log history is a separate, exact-name target. It writes the purge activity event first, then
best-effort deletes only `sbomscope.log.1`–`.5` and `activity.jsonl.1`–`.3`, reporting removed,
absent and failed names. The active `sbomscope.log` and `activity.jsonl` stay open and are never
claimed as removed; the configured log directory is never traversed recursively.

The Maven probe cache is also separate. It owns only the configured
`sbomscope.probe-repository` (by default `~/.sbomscope/probe-repo`), validates that the resolved
leaf remains `probe-repo`, and never touches `~/.m2`. `BumpProbeService` gives cache maintenance
and probe submission one shared gate: cleanup is rejected while work is queued or running, and
new work cannot enter while deletion is in progress. Rebuilding the cache may need repository
access, which the warning states before deletion.

### Dependency scope

`dependency_scope` is `APPLICATION`, `DIRECT` or `TRANSITIVE`, and replaced an `is_direct`
boolean that could only say "depended on by the root".

That boolean was wrong for multi-module builds, not merely coarse. In an aggregate Maven
BOM the root is the **parent pom**, and the only things it depends on are the project's own
modules — so every genuinely declared dependency was reported as transitive, and the only
rows reported as direct were ones the user cannot upgrade because they wrote them.

`ScopeClassifier` works in two steps: establish which components are *the application* — the
root plus sibling modules — then anything that set depends on and which is not itself in it
is `DIRECT`, and the rest is `TRANSITIVE`. For npm and single-module Maven the application is
just the root, so the rule reduces to the old behaviour, which was already correct there.

**Recognising a module is the one heuristic in this codebase.** CycloneDX marks a reactor
module no differently from a third-party artifact — in a real aggregate BOM they are all
`type: library` with no scope and no properties. A module is therefore inferred: reachable
from the root, group equal to or beneath the root's, **and** version exactly the root's. Both
conditions, because either alone is too loose — an organisation routinely consumes its own
published libraries under the same group, and those are real upgradable dependencies. A blank
root group switches detection off entirely, which is what keeps npm safe.

### Two decisions worth understanding before changing anything here

**Findings are keyed by `purl`, not by component row.** The same library at the same
version appearing in five SBOMs is scanned once and every SBOM sees the result. The view
joins `component` to `vulnerability_finding` on `purl` at query time. Scanning one
project therefore benefits the next.

**`vulnerability_scan` records every component that was checked, including clean ones.**
Without it, "no findings" and "never checked" would be indistinguishable — which in a
security tool is a dangerous ambiguity, not a cosmetic one. Anything reporting on
findings must be able to tell the two apart.

---

## The view model

The vulnerability view is a **LEFT JOIN from `component` to `vulnerability_finding`**,
producing `FindingRow`:

- a component with three advisories → three rows, each self-contained and actionable
- a component with nothing known against it → one row with the advisory fields null

This is why the findings list and the component inventory are one table rather than two
screens. `FindingRow.hasFinding()` distinguishes them.

### Severity bands

`FindingQuery.SeverityBand` has six values, and two of them are not severities:

| Band | Meaning |
|---|---|
| `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` | Standard CVSS bands, by numeric score |
| `NONE` | A **real vulnerability** whose advisory carries no CVSS score |
| `CLEAN` | A component with **no known vulnerability** |

`NONE` and `CLEAN` must never be merged. Doing so would let *"we don't know how bad this
is"* render identically to *"this is fine"*. The default filter is every band except
`CLEAN`, so the view opens on what needs attention.

Ordering has to cope with all three kinds of row. `VulnerabilityRepository.orderBy`
ranks scored findings first, then unscored findings, then clean components, so findings
are never buried regardless of sort direction.

### One query object

`FindingQuery` carries sort, direction, text filter, **whether that filter is a regular
expression**, **whether it excludes rather than selects**, severity bands, **dependency
scopes**, limit and offset. The view, the row counts and the export all pass through the same
object into the same SQL, which is what guarantees an exported spreadsheet matches the screen it
came from. Do not add a second code path that sorts or filters independently.

`SortField` has six values, and three of them needed something the schema did not have.
`FIXED_VERSION` orders by `fixed_version_sort` (V3), a lexically-sortable encoding of the
version — see below. `SCOPE` orders by an explicit `CASE` ranking APPLICATION, DIRECT,
TRANSITIVE, stated rather than left to alphabetical coincidence. `GHSA_RATING` orders by another
`CASE` over GitHub's own words — note the middle band is `MODERATE`, not `MEDIUM` — and is not a
duplicate of `SEVERITY`, which orders by the numeric CVSS score; the two genuinely disagree,
which is why both columns exist. All of them put the chosen field first and the
scored/unscored/clean rank second, as `COMPONENT` does: leading with the rank would sort by
whether a finding carries a CVSS score before the column the reader clicked.

**The two `CASE` ranks are deliberately opposite shapes.** `SCOPE_RANK` is a position, so
ascending means "your own code first". `RATING_RANK` is a *value*, higher for worse, so
descending means "worst first" exactly as the numeric score does. Ranking the rating 0-for-worst
was tried and caught by verification: descending opened on LOW while the Severity column beside
it opened on CRITICAL, which is two badness columns on one table disagreeing about which way a
click points.

`KEV` and `EPSS` (Phase 3) join `kev_entry` and `epss_score` into the shared `ROW_SOURCE` on
`f.cve_id` and order by `kev_date_added` and `epss_score`, nulls last in both directions. **KEV
orders by the date CISA listed it, not by a flag** — descending then opens on the most recently
listed rather than on an arbitrary member of one group, and four-years-ago against last-week is a
real difference in how far behind you are. Both are aliased in the projection rather than ordered
by the underlying column, because `SELECT DISTINCT` requires every `ORDER BY` expression to be in
the result — the trap `FIXED_VERSION` hit first. **KEV has no filter at all**, deliberately: with
a handful of listed rows one header click is the same outcome with no state to persist, revive or
record on the About sheet. The cost is that *"exploited, worst first"* needs two criteria and
waits for B10.

`PUBLISHED` orders by `published_at`, nulls last in both directions. **Sorting by CVE id was
considered for the same purpose and rejected**: the year in `CVE-2020-9547` orders correctly
across years, but the sequence number is not zero-padded, so within a year that id sorts *after*
`CVE-2020-10001`. Half-right ordering presented as chronological is worse than none.

### Filtering, in four combinations

The text filter is literal or a regular expression, and selects or excludes — two independent
booleans, assembled by one `VulnerabilityRepository.textMatch`. H2's `REGEXP_LIKE` is
`java.util.regex`, verified against the pinned version rather than taken from the documentation:
lookbehind, named backreferences, possessive quantifiers and atomic groups all evaluate, and an
invalid pattern arrives with `PatternSyntaxException` as its root cause. That is what lets
filtering stay in SQL — matching in Java would need a second query path and would break the
property above. `ScanService.validated` compiles the pattern before it reaches the database, so a
half-typed one is a 400 carrying Java's own message rather than a data-access failure.

**Negation is of the row, not of each column.** The positive form shows a row when *any* searched
column matches, so the negative form hides it on the same condition; negating column by column
would let one pattern both show and hide the same row. Every column is `COALESCE`d for this
reason: `NOT (NULL OR …)` is NULL, so without it a component with no purl would vanish from a
search for everything *not* containing a term it plainly does not contain.

**A user-supplied pattern is bounded, on its own connection.** A regex filter runs through
`VulnerabilityRepository.bounded`, which applies a query timeout and resets it in a `finally`.
The reset is not defensive tidiness: **H2 scopes a query timeout to the session**, since
`setQueryTimeout` issues `SET QUERY_TIMEOUT`, so a pooled connection that ran one bounded query
would carry that ceiling back into the pool and silently bound whatever borrowed it next. Doing
it all inside one `ConnectionCallback` is what makes the reset land on the connection that was
actually changed. Measured, and the folklore is out of date: on JDK 21 and 25 alike the textbook
exponential patterns are linear, but `(x+x+)+y` is 30 seconds against 2000 characters and
`(a|a)+$` throws `StackOverflowError`. Since a purl is ~100 characters, the row count is what
hurts, which is what a query timeout bounds.

The log tails bound the same risk differently — that loop is ours, so `LogService.LineMatcher`
checks a deadline between lines and **reports** exhaustion rather than returning "no matches",
which would be read as evidence the log does not contain the thing being searched for.

**The scope filter is `scope` on the findings endpoint and `scope_filter` on the export**,
because the export has used `scope` for its own visible/all selector since Phase 5. Both are
emitted by one builder with the name passed in; giving them one name would let `exportUrl`
overwrite the filter and produce a workbook wider than the screen it claims to reproduce.

### Sorting by a version

H2 orders `1.10.0` before `1.9.0`, because it is comparing strings. Sorting executes in SQL —
that is what stops the view and the export diverging — so the ordering has to be a stored value
rather than a comparator applied afterwards.

`VersionOrder.sortKey` produces it, from the same parse `VersionOrder.compare` uses, because two
readings of what a version is would eventually disagree and the table would then be ordered
differently from the upgrade advice describing the same versions. Trailing zero segments are
dropped so versions the comparator calls equal produce *identical* keys; each segment is padded
to 19 digits; the release part is terminated with `'!'`, which sorts below every digit, so a
shorter version sorts before one that extends it; and a release is marked `'~'` against a
pre-release's `'-'` + suffix, reproducing "a pre-release is on the way to the release".
`VersionSortKeyTest` asserts the two agree across every version string in the committed
fixtures. **NULL means no fix, and sorts last in both directions** — "no fix" is not a version
and must not answer "which fix is furthest away".

`FixedVersionSortBackfill` fills the key in once after startup for findings written before V3.
A null key would otherwise sort as though the advisory named no fix, which is a false statement
about an advisory rather than a cosmetic mis-ordering.

---

## External tool contract: osv-scanner

SBOMscope shells out to osv-scanner. It is **never downloaded by us** — the user places
the binary and sets the path in Settings. Verified against **v2.4.0**.

```
osv-scanner scan --lockfile <file> --offline --format json
```

with `OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY` pointing at the database directory.

Four things that cost real debugging time and are easy to get wrong again:

1. **Exit code 1 means "vulnerabilities found", not failure.** Only 0 and 1 are success.
   Treating 1 as an error makes every genuinely vulnerable project look like a broken
   scan.
2. **The parser is chosen by filename.** A CycloneDX document stored as `<uuid>.json` is
   rejected with *"could not determine extractor suitable to this file"* (exit 127) no
   matter how valid its contents are. `SbomFileStore` therefore stores uploads as
   `<uuid>.cdx.json`. This suffix is load-bearing.
3. **Errors appear on the *last* line of stderr.** Progress messages such as *"Starting
   filesystem walk for root: C:\"* come first, so reporting the first line reliably
   hides the actual failure.
4. **The report identifies packages by ecosystem/name/version and carries no purl.**
   Results are tied back to stored components through `OsvReportParser.PackageKey`, which
   normalises casing on construction so both sides of the lookup agree.

### Report shape

```
results[] → packages[] → { package{name,version,ecosystem}, vulnerabilities[], groups[] }
```

Findings are built from **`groups`**, not raw `vulnerabilities`: the scanner collapses
advisories that alias one another, so a GHSA and its CVE become one finding rather than
two rows describing the same problem. `groups[].max_severity` is a **numeric** CVSS score
already computed by the scanner.

**A group's score and its vector can belong to different advisories.** `max_severity` is
the highest score across every member of the group, while the rest of the row is read from
the one advisory whose id is displayed. When members disagree about severity those two
statements come apart, and printing them together would claim a relationship that does not
hold. `OsvReportParser.attributableSeverity` therefore returns the CVSS vector only when
every member carrying one agrees; otherwise the score stands alone and the vector is
dropped. The score is never lowered — it is the worst case, which is the safe direction for
a vulnerability tool to err in.

Selecting the member whose score *is* the maximum would be the more obvious fix, but OSV
encodes severity exclusively as CVSS vector strings — only the group carries a number — so
identifying it would mean implementing CVSS scoring here. Measured against the Maven set
(2026-07): 21 of 6,860 advisories sit in a multi-member group at all, and 11 of those pairs
disagree on the vector. `osv-report-aliased-group.json` covers the case, built from two real
ClickHouse advisories that alias `CVE-2024-23689` and score it HIGH against MODERATE.

**Selecting the fix version is subtle, in two separate ways.** An advisory covers several
coordinates *and* several parallel release branches.

The Jackson advisory lists fixes for `com.fasterxml.jackson.core` (2.21.5) *and*
`tools.jackson.core` (3.1.5) — take the wrong one and you name a version that does not exist
for the library in use. `GHSA-48r7-hpm6-gfxm` lists four ranges for the single package
`@angular/common`: fixes on 22.x, 21.x and 20.x, plus a 19.x line ending in `last_affected`
with no fix at all — take the first and you tell a user on 19.2.17 to upgrade to 22.0.1.

`OsvReportParser.fixedVersionFor` therefore narrows to the entries naming the scanned
package, then picks the branch that version actually sits on: by the advisory's explicit
`versions[]` where one exists (string equality, ~90% of the Maven set), otherwise by
comparing against each range with `VersionOrder`. A branch offering only `last_affected` has
no fix, and null says so. Where no branch can be placed, null again — a confident wrong
upgrade target is worse than none.

**The report's package identity is name-based, and scoped npm packages have two spellings.**
Results are tied back through `OsvReportParser.PackageKey` (ecosystem, name, version), which
normalises casing on construction. A component is registered under every spelling a scanner
might use: `npm sbom` emits `@angular/common` as the name with no group, while other
generators split it into group `@angular` and name `common`, which renders as
`@angular:common` — Maven's separator — and would otherwise never match. A miss here does not
degrade the finding, it discards it.

---

## External tool contract: the Maven probe (Phase 8 Tier 2)

For a transitive finding, the offline advisory data (Tier 1) can pin the affected component
directly but cannot say whether a newer version of what *pulls it in* already ships the fix —
that needs resolving a dependency tree at a version nobody has installed yet, which no SBOM or
advisory database records. `BumpProbeService` answers this by driving the user's own `mvn` as
an external process, never downloaded by SBOMscope, exactly like osv-scanner above. Configured
by `MavenToolSettings` (`enabled`, `executablePath`, `maxProbes`, `runBudgetMinutes`,
`profiles`) in Settings.

**Isolated repository, never `~/.m2`.** Every probe resolves through
`sbomscope.probe-repository`, which defaults under the data directory to
`~/.sbomscope/probe-repo`. A failed probe's
`.lastUpdated` markers must not be able to make a later real build refuse to retry a download,
so the user's own local repository is never touched.

> **Known, accepted limitation — this cannot work fully air-gapped.** `-Dmaven.repo.local` *overrides* the
> local repository, so a correctly configured Maven gives the probe the user's mirrors and
> credentials from `settings.xml` but **not** the contents of their `~/.m2`. With a reachable
> mirror the plugin simply downloads into `probe-repo`, which is why this works on an ordinary
> machine. With no reachable repository there is nowhere for it to come from, so every probe
> fails at plugin resolution (`ProbeFailureReason.PLUGIN_UNAVAILABLE`) while a full `~/.m2` sits
> unused. Pinning the plugin versions below makes the required set finite and knowable, so
> seeding is possible in principle, but it still would not provide unseen candidate artifacts.
> A measured `maven.repo.local.tail` read-through likewise helps only for artifacts already
> cached. The design question was closed on 2026-08-02: keep the isolation and report the probe
> unavailable when neither the isolated repository nor a configured mirror can supply what it
> needs. See the plan's decision log.

**Every `mvn` invocation goes through `MavenInvocation`**, which captures the command line and
the complete output into `sbomscope.log`: the command at INFO so it can be pasted into a
terminal and reproduced, the full output at WARN on failure and at DEBUG on success. Raise
`logging.level.dev.sbomscope.probe` to DEBUG for successful runs too.

Two things there are load-bearing rather than incidental. **stderr is merged into stdout**: the
earlier shape read stdout to EOF, then stderr, then called `waitFor`, and a child that fills the
stderr pipe buffer (4–64 KB) blocks writing to it, never closes stdout, and so hangs the read
with the timeout unreachable — fatal here, because probes are serialised on one thread and one
hang stalls every later probe for the life of the process. **The timeout is enforced by a
watchdog that destroys the process**, not by a bounded read, because killing the child is what
actually closes the stream and unblocks the read.

**Plugin goals are fully qualified and version-pinned**, never the `dependency:tree` prefix. A
prefix costs a `maven-metadata.xml` lookup to resolve which artifact `dependency` means — the
source of `NoPluginFoundForPrefixException` — and then takes the plugin's *latest* version, so a
probe could behave differently month to month with nothing changed locally. Pinning also makes
the probe's plugin requirements a finite, knowable set, which is what makes pre-seeding a
repository possible at all. The versions are user-configurable
(`MavenToolSettings.dependencyTreeGoal()` / `effectivePomGoal()`) because which version exists is
a fact about the user's repository, not about SBOMscope: a curated mirror proxying an approved
subset of Central may carry a different one. Blank resets to the shipped default, and the value
is validated against `VERSION_PATTERN` because it is interpolated into a colon-separated goal
coordinate where a stray colon would change which goal runs.

**The ancestor that is ranked is the one Maven resolves through, read from the tree.**
`dependency:tree` writes its text output to a file the resolver already reads, and the
indentation is the parent chain — so `MavenDependencyResolver.declaringDependencyOf` names the
winning declaration at no extra invocation, where `findVersion` scans the same file and discards
it. This matters because Maven picks by depth in the *resolved* tree while the SBOM graph orders
routes by length: where they differ, bumping the shortest-route ancestor moves nothing, and that
result reads as "upstream has not fixed this" unless the panel can say otherwise. The other
declaring ancestors are listed with that reason and never ranked — ranking them splits one budget
N ways for versions that cannot change the outcome. `BumpScope` carries all of it, plus which
module the answer was verified against and which owning modules were not probed.

**Route accounting is exact even though route presentation is capped.** For each
`(component, module)` pair, `DependencyGraphService` enumerates every simple route with a
per-path cycle guard, counts direct routes and groups transitive routes by their first declared
dependency. Only the ten shortest paths are retained for the dependency-graph UI.
`UpgradeAdvice.ModuleImpact` therefore reports `COMPLETE`, `PARTIAL` or `UNAFFECTED` from the
uncapped counts: a direct upgrade is complete only in modules declaring the target, a parent
`dependencyManagement` pin is complete across modules by construction, and an ancestor bump
names the exact routes it covers. A component classified globally as `DIRECT` may still be
probed when another module owns it transitively; the probe selects that transitive owner rather
than refusing from the aggregate scope.

Exact simple-path enumeration can be exponential in a graph with many diamonds. The per-path
cycle guard guarantees termination on cyclic SBOMs, but it does not make that work polynomial;
retaining only ten paths bounds the response size, not the traversal cost. This is a deliberate
correctness trade: remedy coverage may not be inferred from a truncated walk. If a real SBOM
makes the cost unacceptable, the replacement must either compute the same exact counts by a
different representation or expose coverage as unavailable. Reintroducing a cap and presenting
its floor as a total would recreate the false-fix failure B14 removed.

**Whole-module, not single-dependency.** A component reached by two routes appears in the SBOM
as one resolved node with two parents, and the SBOM does not record which declaration Maven
actually honoured. `MavenDependencyResolver.generatePom` therefore declares the owning
module's *entire* direct dependency set — every one at its current version, except the
artifact(s) under test — so Maven's own nearest-wins resolution, not an approximation of it,
decides what the target resolves to. **Calibration** (resolving the untouched module and
comparing against the SBOM's own reported version) runs first and must match before anything
else is trusted; a mismatch means something outside SBOMscope's view overrides it — most often
a parent POM's `dependencyManagement` — and the answer is "pin it", not a guessed bump.

**Every probe past the initial feasibility check targets an exact known release, never a
numeric range.** Found live: a bounded range such as `[3.0.0,4.0.0)` resolved to `4.0.0-RC2` —
Maven compares major version before qualifier, so a pre-release of the *next* major outranks
every real release of the one being asked about and can win the range outright, silently
skipping the entire major rather than merely offering a milestone. The fix: every candidate
comes from `MavenDependencyResolver.knownVersions` (reads local `maven-metadata*.xml`,
pre-release-filtered) and is probed as an exact version (`[x.y.z]`), never a range standing in
for more than one release.

**One ranked candidate per major line, never a single winner.** A later major being affected
does not prove an earlier one is not clean — the same non-monotonicity that rules out ranges
above also rules out stopping at the first major that fails, or trusting a single
feasibility probe (`[current,)`) as proof nothing works. `rankCandidates` walks every major
from the currently-declared one up to the latest that exists, and within each major walks
minor lines ascending rather than bisecting — a version being clean or affected says nothing
about a neighbouring one, so there is no shortcut that does not risk reporting the wrong
answer. Combination testing (bumping every declaring ancestor to its own latest at once) is a
single coarse fallback, tried only when no single ancestor's ranking finds anything clean.

**The run budget is the only sound lever for trading completeness for cost.** `maxProbes` and
`runBudgetMinutes` (user-configurable in Settings) bound how much of the search completes
before a major degrades to "not probed" — narrowing the search space itself (a range standing
in for several minors, say) is the exact class of bug the paragraph above exists to prevent.

**Every probe is serialised on a single background thread**, since the isolated repository
cannot safely take concurrent writes. `BumpProgress` distinguishes `QUEUED` (submitted, waiting
behind another component's probe) from `RUNNING` (actually executing) for this reason —
reporting a queued probe as running would claim Maven is being invoked right now for something
that has not started. `BumpProbeService` tracks the executing key in an `AtomicReference`,
read only to decide what a newly-submitted probe should report about itself; the executor's own
FIFO queue is what actually decides execution order.

**An exhausted budget is reported, never disguised.** A major the run never reached is `probed:
false`; a major it walked partway is `higherReleasesUnchecked: true`, so *"the highest 2.x still
carries this"* cannot be confused with *"we got as far as 2.7.18 and stopped"* — the first is a
verdict on the whole major, the second says nothing about what sits above it. That is the same
unproven-versus-disproven distinction the feasibility short-circuit was removed for, one level
down. It is never set where the walk stopped on finding its earliest clean release, since
ascending order makes that a complete answer.

**`continueRun` extends a cut-short run rather than repeating it.** It needed no new search
logic: `rankMajor` already takes a `startAfterMinor`, which is exactly a resume point, so a
cut-short major picks up above the version it stopped at and an unreached one starts from
scratch. Settled rows cost nothing, and calibration and feasibility are not repeated — the model
was validated on the first run, settings cannot have changed without clearing this cache, and
the existing rows already enumerate every major. Each call takes a fresh budget. A run that
ranked *nothing* has nothing to preserve, so continuing it discards the cached entry and starts
over — which is also what keeps a cached failure from being a permanent dead end.

**`profiles` is passed through verbatim as `-P<profiles>`** to every `mvn` invocation the probe
makes (`dependency:tree` and, when a workspace path is attached, `help:effective-pom`) — not to
the plain `--version` check, which needs no build context. A profile that adds a repository or
changes a property the real build depends on has to be active here too, or the probe resolves
against a build the user does not actually have.

**Workspace lift-in, when a workspace path is attached.** `EffectivePomCache` runs
`mvn help:effective-pom` once per (workspace path, profiles) pair per process lifetime and
lifts `<dependencyManagement>` and `<repositories>` verbatim into the generated POM — the
actual fix for probes failing on supplier artifacts, since a project's own `pom.xml` routinely
declares a supplier's Nexus that no `settings.xml` mirror covers. Without a workspace, or when
the lift fails, the probe stays isolated rather than guessing.

**"Test Maven" checks the plugins, not just the binary.** `mvn --version` proves the path points
at Maven and nothing more; it succeeds on a machine where every probe will fail. The test
therefore also runs both configured goals against a throwaway empty project, in the real
`probe-repo`, so a green result means the exact invocations a probe makes have been made once and
worked. The version is reported even when the plugin check fails, because "Maven runs but its
plugins cannot be obtained" and "that is not Maven" need different fixes.

**The queue is addressable and stoppable, from Monitoring rather than from the component.** A
probe deliberately outlives the Inspector tab that started it — the tab is a view of this state,
not its owner — and a tab can be closed by the reader or evicted by the ten-tab cap. That left a
run holding the only probe thread with no way to reach it, since `progress(component, graph)`
requires already knowing which component to ask about, which is exactly what somebody who has
lost track of it does not. `BumpProbeService.probes()` lists running, queued and recently
finished runs (`GET /api/probes`); `cancel(id)` stops one (`DELETE /api/probes/{id}`).

**Stopping is expressed as budget exhaustion, not as a state of its own.** `SearchBudget.exhausted()`
is the one checkpoint every level of the search already consults, and every level already reports
what it did not reach — `probed: false` for a major never visited, `higherReleasesUnchecked` for
one walked partway. A stopped run is a cut-short run, so it inherits all of that, and `continueRun`
resumes it with no new logic. Two things follow that are easy to get wrong. Killing the `mvn` in
flight makes that invocation fail, so a run stopped during calibration would otherwise end by
reporting *its own kill* as "nothing resolves this cleanly" — `BumpProgress.stopped()` discards
that manufactured remedy and keeps the verdicts and settled candidates, which were true before the
stop and still are. And each run builds its **own** `SearchBudget` from current settings, so
Continue after a stop is a full fresh budget rather than the remainder of the one that was cut.

**Finished runs stay listed for the session**, bounded at 25, most recent first below the live
ones. "Did that thing I started actually do anything" is asked immediately after a run ends, and a
list that empties itself at that moment answers it with silence. `STOPPED` is kept distinct from
`COMPLETED` because a run the user cut short and one that reached the end of its budget are
different claims about how much of the search happened.

**Every attempt is a `ProbeStep`, not a sentence.** `BumpProgress.verdicts` was a flat
`List<String>` of prose — readable, and unusable for anything else: the panel shows each attempt
beside the result it contributed to, and sixteen lines against three ranked candidates had no key
between them. Each step now carries `major` (null for calibration, the opening feasibility probe
and the combination fallback, which belong to no single line), `kind`, `requested` and `outcome`
**around the original text**, which is still what the activity log records and what the panel
renders. `major` is threaded from `rankMajor` through `probeOne` rather than parsed back out of
the rendered string. `Outcome.NOT_CHECKED` is kept distinct from `AFFECTED` — including for a
resolution refused because it produced a pre-release, where declining to recommend a milestone is
a decision about what we will say, not a finding about the version.

**A transfer failure is not a missing artifact.** Maven prints `Could not transfer artifact` for
an untrusted certificate exactly as it does for one that does not exist, so
`ProbeFailureReason.REPOSITORY_UNREACHABLE` is decided **before** `NOT_FOUND`. Found live: a
`PKIX path building failed` on a machine with TLS-inspecting security software was reported as
*"Not found in any configured repository"* for a library sitting in Central. Its message names
the fix, including the part that catches people out — `MAVEN_OPTS` is an environment variable,
and a `-D` flag on SBOMscope's own JVM never reaches the `mvn` it starts.

**Probe progress is session-scoped, not persisted**, keyed by `moduleBomRef -> targetCoordinates`
in `BumpProbeService.progressByKey` — cleared on Maven settings change (a stale answer against
an old configuration is worse than a re-probe) and on process restart. `POST
/component/bump` starts or returns the existing run; `GET /component/bump` polls it.

---

## External tool contract: the workspace reachability worker (Phase 9)

Each worker has an independent configurable wall-clock limit (10 minutes by default) and JVM heap
limit (1 GiB by default). Exceeding either produces an incomplete failed run, never a negative
reachability conclusion; Stop terminates the same SBOMscope-owned process tree.

The first workspace-analysis slice is Maven-only and reads only artifacts that already exist on
the local machine. `WorkspaceInputDiscovery` finds production `target/classes` directories and
the exact Maven dependency JAR versions named by the SBOM in the user-configured **read-only**
Maven cache. It never runs Maven, a workspace build, a plugin or a network request. The
application-owned `~/.sbomscope/probe-repo` is deliberately never an input: that repository
belongs to the Maven upgrade probe and can contain probe-specific state.
Group, artifact and version values came from the uploaded SBOM, so discovery rejects absolute,
separator-bearing and traversal path segments and verifies the normalized JAR path remains below
the configured Maven cache before reading it. A rejected coordinate is a missing-input blocker,
never a best-effort read elsewhere or a negative reachability answer.

`WorkspaceReachabilityService` fingerprints those inputs, the module mappings, WALA
version/algorithm and relevant Settings when the reader opens the Component Inspector's Workspace
usage view. A matching completed run is reused; failed or stopped work retries implicitly, and
startup marks abandoned durable `QUEUED`/`RUNNING` rows failed so they can retry. A changed
fingerprint queues exactly one single-threaded analysis for that SBOM.

One worker is started per mapped module. Its WALA scope contains that module's production output,
supporting compiled workspace modules in its exact SBOM dependency closure, and only the external
JARs in that closure. Supporting module methods are not analysis roots. Duplicate classes supplied
by two component versions, or by a workspace output and a component JAR, make ownership ambiguous
and therefore `NEEDS_REVIEW`; one module's call can never be attributed to another module or every
matching version.

The parent starts the same SBOMscope artifact in its internal `--reachability-worker <input.json>
<output.json>` mode. Normal application startup is unchanged: this argument is parent-to-worker
protocol, not a user configuration option. The worker receives only already-approved class/JAR
paths, constructs the WALA graph internally, and writes bounded per-component coverage plus at
most ten representative paths. The full edge graph never enters the parent JVM, and the parent
rejects an output file above 16 MiB before deserializing it.

The worker's resource cap also has a bounded parent side. Reflection-marker inspection streams at
most 16 MiB from any class file and treats a larger/unreadable file as a conservative completeness
blocker. Worker stdout is discarded; stderr is continuously drained so the child cannot block but
only the first 64 KiB is retained, with an explicit truncation marker. The failure surfaced by the
API reads at most 8 KiB from that already-bounded file.

The worker process tree is owned by SBOMscope, shown through `GET /api/workspace-analyses`, and
stopped through `DELETE /api/workspace-analyses/{id}`. Stop never targets a user build, Maven
probe or the server. The parent also enforces the Settings-configurable wall-clock ceiling (10
minutes by default; 1–60 allowed). A user Stop persists `STOPPED`; a time limit or engine error
persists `FAILED`. Temporary request/output/stderr files live beneath SBOMscope's data directory
and are removed best-effort after the worker exits.

The persisted evidence is per SBOM/run/module, never attached to the shared vulnerability finding
cache. Module mappings, every evidence row and the final `COMPLETED` state commit atomically;
`COMPLETED` is written last. Cancellation and completion are serialized so a late worker cannot
overwrite `STOPPED`. Exact coverage determines `REACHABLE` independently of the bounded path
display, so a positive result remains positive even when no representative route fits the search
limits. A negative answer is withheld whenever an input, module mapping, Spring/AOP or reflection
completeness condition is not met. The Maven OSV archive currently lacks structured
vulnerable-method data, so this slice never presents a component path as proof that a particular
advisory's vulnerable function executes.

---

## The OSV database

Public OSV.dev data, downloaded per ecosystem on explicit request only:

```
https://osv-vulnerabilities.storage.googleapis.com/<ecosystem>/all.zip
        ↓
<databaseDirectory>/osv-scanner/<ecosystem>/all.zip
```

That layout is what osv-scanner expects. Downloads run on a background thread with
polled progress, written to `all.zip.partial` and atomically moved into place so an
interrupted transfer never leaves a truncated archive.

### Measured characteristics (Maven set, 2026-07)

Recorded so nobody has to re-measure them:

| | |
|---|---|
| Archive size | Maven ~10 MB, **npm ~200 MB** |
| Advisories (Maven) | 6,860 |
| Carry a CVE alias | 6,656 (97%) — the rest are GHSA-only or `MAL-*` |
| Have explicit `versions[]` | 6,146 (90%); the remainder need range logic |
| Range types | 12,328 `ECOSYSTEM`, 101 `SEMVER` |
| Severity encoding | CVSS **vector strings only**, never numeric: 5,928 v3, 863 v4 |

The archives are the standard OSV export — individual advisory JSON documents in OSV
schema 1.7.3, with no index, manifest, or scanner-specific metadata. Only the directory
layout belongs to osv-scanner; the data belongs to no tool.

### Index cost for the local matcher (2026-07-29)

Upgrade paths evaluate candidate versions against these archives, which means parsing them.
Measured on a real machine by `ArchiveIndexProbe`, which skips itself when the archives are
absent:

| | Archive | First query | Cached query | Heap retained |
|---|---|---|---|---|
| Maven | 9.4 MB | 398 ms | <1 ms | ~42 MB |
| npm | 202.9 MB | **5.2 s** | <1 ms | **~152 MB** |

The entries are named by advisory id rather than by package, so nothing can be skipped
without parsing it — the whole archive is read however little of it is wanted.

**The retained memory is the more awkward number, not the time.** It is held for the life of
the process once built, and both ecosystems together approach 200 MB in an application that
otherwise runs comfortably small. Anything that builds these eagerly pays that in every
session, including the ones where nobody asks an upgrade question.

---

## Bulk public data: the exploitation feeds

Two whole-file downloads, on request only, from one fixed URL each with no credentials —
constraint 1's category 2, for the same reason the OSV archives are: asking for *every* exploited
vulnerability discloses nothing about which libraries are held.

```
https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
https://epss.empiricalsecurity.com/epss_scores-current.csv.gz
        ↓
~/.sbomscope/exploit/
```

Beside `osv-db` rather than inside it: that directory's layout belongs to osv-scanner, which is
handed it as `OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY` and walks it. Written to `<name>.partial` and
moved into place, exactly as `all.zip` is.

**Measured 2026-08-01**, recorded so nobody re-measures them:

| | KEV | EPSS |
|---|---|---|
| Size | 1.50 MB JSON | 2.39 MB gzipped, 10.3 MB expanded |
| Contents | 1,656 entries | 354,453 scored CVEs |
| Cadence | irregular — 36 release days and 69 entries in 90 days | daily, just after 13:30 UTC |
| Licence | CC0 1.0, no attribution obligation | free, **attribution requested** |
| Intersection with the Maven OSV set | 52 of 6,675 CVEs (0.8%) | 6,610 (99.0%) |

**The JSON is taken over the CSV CISA also publishes**, and not for taste: the JSON states
`catalogVersion`, `dateReleased` and `count` at the top of the document, so the feed describes
its own freshness. A CSV has nowhere to put that, which would put us back to inferring an as-of
date from a file's modification time. (Its CSV also lives under a different path — `/files/csv/`,
not `/files/feeds/` — so swapping the extension is a 404.)

**Neither feed's lookup API is used.** EPSS publishes a per-CVE API, and asking about one CVE
would say which one is held — category 3 by shape. FIRST's own documentation independently says
the API is "designed for lookup, not bulk access" and names the daily file as the right mechanism
for keeping a local copy, so the permitted path and the recommended one are the same.

**A KEV flag appears derivable from data already on disk, and is not.** GitHub attaches a KEV
catalogue reference URL to advisories whose CVE is listed. Tested against the authoritative feed:
perfect precision, and it misses 4 of 52 Maven CVEs and 5 of 13 npm ones — including Spring Cloud
Gateway's `CVE-2022-22947`. A silently absent exploited-mark on the rows that most deserve one is
the failure class this project designs against, so the real feed is the only source. Recorded so
the shortcut is refused once rather than reconsidered.

**Present and loaded are separate states, and so are loaded and current.** `FeedStatus.present`
is the file on disk; `hasData` is rows in the database; `loaded` is rows built from *that* file,
compared by path/size/mtime exactly as `osv_index_source.identity` is. The distinction is not
academic: the notice above the findings table asks `hasData`, because that is the question the
cells answer, while Settings asks `loaded`, because that is what decides whether re-loading is
worth offering. Keying the notice on `loaded` put *"this column is empty on every row"* above six
rows that were visibly marked.

**The EPSS percentile is a global rank and is repeatedly misread as a local one.** It arrives as
column three of FIRST's file and is that CVE's position among all ~354,000 CVEs EPSS scores —
nothing computes it here, and it would be the same number on an empty SBOM. Asked in use, which
is why the tooltip now says *"not a rank within this SBOM"* and `EpssCell` has a `detailed`
variant spelling out *"of all scored CVEs"* where there is width for it. A 44% probability sits
near the 99th percentile globally, because most CVEs score far lower; that surprise is the whole
reason the percentile is worth showing beside the score.

**Freshness is the feed's own claim, never a download timestamp** — the same reasoning that made
`ARCHIVE_REFRESHED` read the archive's modification time: a file carried across on a USB stick
has to describe itself correctly. **Neither feed touches `ScanService.staleReason`.** That flag
means *the findings may be wrong*, because a refreshed OSV archive changes which advisories
apply; a newer KEV or EPSS file changes a displayed column and is applied by re-reading a table.
EPSS also ages far more slowly than "daily" suggests — measured, 0.9% of scores move day over day
and 0.01% by more than 0.01. What moves every score at once is a **model version**, roughly
annually, which is why it is stored and shown beside the date.

---

## Key flows

**Upload** — `SbomController.upload` → `SbomService.importSbom`. The document is written
to disk *first*, then parsed back off disk, so a later re-scan uses the file as uploaded
rather than one reconstructed from our own parse. Parsing failures delete the stored file.
The whole import is one transaction.

**Scan** — `ScanController.scan` → `ScanService.scan`. Checks settings, runs `--version`
to record what ran, invokes the scanner against the stored document, parses the report,
resolves packages back to purls, then writes a scan row for **every** component and
replaces that component's findings wholesale (so a withdrawn advisory disappears).

**Automatic scan** — `AutomaticScanner`, on a single daemon thread. After an upload, on
`ApplicationReadyEvent`, and on `ScannerSettingsChangedEvent` — in each case for every SBOM
holding a component with no `vulnerability_scan` row
(`VulnerabilityRepository.sbomIdsWithUnscannedComponents`). The settings trigger closes a gap the
other two could not: `scanLater` declines silently when readiness is not met, so an SBOM uploaded
before osv-scanner was configured stayed unscanned until the next restart, showing an empty table
that reads as "nothing found". It is a **`@TransactionalEventListener(AFTER_COMMIT)`**, because
the settings update is transactional and the scan runs on another thread with its own connection:
queued before the commit it would re-check readiness against the old settings and decline again.
Permitted by constraint 2 because
running the scanner against an archive already on disk sends nothing anywhere — see the
constraint for where that line is drawn. Gated on `ScanService.readiness` per SBOM and skipped
**silently** when it is not met, since a machine with no scanner has not failed at anything.
The in-flight set is surfaced as `scanning` on the SBOM list, so the sidebar can mark a card and
pick up the new counts in the same poll. The activity entry records the *trigger*, written
before the run; the counts are the scan's own entry, shared with the manual path.

**Download the stored document** — `SbomController.document`. The stored bytes, under the
filename it was uploaded with rather than the `<uuid>.cdx.json` it is stored as. 404 where the
file has been swept, which is a real state: `StoredDocumentSweeper` is deliberately
one-directional, so a row can outlive its document.

**View** — `ScanController.findings` returns a page of `FindingRow` plus totals: the
unfiltered vulnerability count for the headline, and the filtered row count for paging
and export labels.

**Staleness** — `ScanService.staleReason`, one reading that the boolean flag is derived from
rather than computed alongside. `AGED` is the seven-day clock, or never scanned.
`ARCHIVE_REFRESHED` means an archive this SBOM's ecosystems need was written **after** its last
scan, and is checked first because it is the stronger and more actionable statement: an archive
downloaded an hour ago against yesterday's scan is not "aged". Read from the archive file's own
modification time rather than a recorded download timestamp, so it is equally true of an archive
**carried across on a USB stick** — the workflow this product is built for, and one a
download-time column would have been blind to. Re-indexing deliberately does not count:
osv-scanner reads the archive, not the index. `lastScannedAt` is `MIN(scanned_at)` across the
SBOM's components, not `MAX` — findings are shared across SBOMs by purl, so `MAX` would let one
document look freshly scanned because another refreshed a component they share.

**Export** — `ScanController.export` → `FindingsExcelExporter`. Two scopes: `visible`
reproduces the current page, filter and sort; `all` keeps sort, severity and dependency-scope
selection but drops text filter and paging. Registry URLs come from `RegistryLinks`, the same
code the API sends to the browser, so view and export cannot drift.

`RegistryLinks.forPurl` returns **two** destinations, `Links(artifactUrl, versionUrl)`, from one
parse — so no call site can take one without the other, which is the mechanical reason the
component name and the version cell cannot end up linked differently in the view and the export.
The name reaches the artifact page, which resolves whenever the artifact exists; the version
cell reaches that exact version, which for a vendor-patched `a.b.c.d` build may not exist at
all. A purl's `repository_url` qualifier is honoured where the host is a public repository a
downstream reader can reach, and produces **no link on either half** otherwise — a link into a
private Artifactory is useless to that reader, and Central would be a confident 404. That is not
in tension with the 2026-07-26 "links stay public" decision: that one refuses a *setting* that
repoints everything at one mirror, while this is the document stating where one artifact lives.
Whether a link resolves is never tested, because asking a registry about a specific artifact is
constraint 1's category 3.

**Index** — `OsvDatabaseService` → `OsvArchiveMatcher.buildIndex`. Runs as a visible second
phase after a download, and on demand for an archive carried across by hand — being *present*
and being *indexed* are separately reachable states, and re-downloading 200 MB to fix the
second would be absurd on any machine and impossible on an air-gapped one.

**Candidate evaluation** — `OsvArchiveMatcher.advisoriesFor` answers "which advisories apply
to package P at version V" for versions the user does not have. **It is not a second
scanner.** What is installed is reported by osv-scanner and nothing else; if the two ever
disagree about a version actually present, the scanner is right by definition. Version-range
semantics live in `AffectedVersions`, read by both this and the report parser, because two
implementations would drift in the direction of "this upgrade is clean" against "it is not".

**Bump probe** — `SbomController.startBump` / `.bumpProgress` → `BumpProbeService.start` /
`.progress`. `start` returns immediately (`RUNNING` or `QUEUED`) and the actual probe runs on
the single background thread described above; the UI polls `GET .../component/bump` until the
state leaves `RUNNING`/`QUEUED`. See "External tool contract: the Maven probe" above for the
search strategy.

**The rows stream, and they arrive as a skeleton.** Which majors the search will walk is settled
the moment the feasibility probe returns — the labels come from the current and latest versions,
not from any verdict — so `rankCandidates` publishes every row as `BumpCandidate.notProbed`
before probing any of them (`BumpProgress.withCandidates`), then replaces each in place as it
settles. `notProbed` already means "this line exists and nothing is known about it yet", so the
skeleton is an honest state rather than a placeholder. The continue path fills in the same way.

Two consequences for anything reading this. **Candidates must not be read only in the
`COMPLETED` state** — `resuming()` deliberately carries the settled rows back into `RUNNING` so
that pressing Continue does not blank a panel mid-read, and gating on completion throws away
exactly what it preserves. And **an unprobed row means two different things**: "not reached yet"
while the run is in flight, "the budget ran out before this major" once it is not. The panel is
told which.

**Exploitation signals** — `ExploitFeedService.startRefresh` downloads then loads, on a single
background thread with polled `FeedProgress`; `startLoad` reads a file already on disk, which is
the air-gapped path and the ordinary one for anybody who copied a file across. Both replace their
feed wholesale rather than merging: CISA does remove entries, and one surviving only because
nothing deleted it would be a claim nobody is making any more — the same rule a re-scan follows.
The signals reach a row through `ExploitSignals`, joined at query time and never stored with a
finding, because what CISA and FIRST say about a CVE is the same statement whichever SBOM reached
it. `FindingRow.signals` is never null. **`getDouble` returns 0.0 for SQL NULL**, and for a
probability that is a real value meaning "will not happen", so both numbers are read through
`getObject`.

**Component severity for the finder** — `VulnerabilityRepository.worstBandByPurl`, riding on
`GET /sboms/{id}/components` rather than a call of its own, so the finder's marks and its rows
cannot describe different sets. Built from the same `BAND_EXPRESSION` the filter chips and the
severity counts read. **A purl absent from the map has never been scanned**, which is not
`CLEAN`: the map has holes rather than being a total function, so no caller can default the
missing case to "clean" without writing that down.

---

## Settings

Stored in `app_setting`, editable from the UI, so no file editing or restart is needed.
Deliberately **not** where secrets go — there are none today, and if one appears it
belongs in an environment variable or git-ignored config, never in the database.

`ScannerSettings` carries `enabled`, `executablePath` and `databaseDirectory`. With
scanning switched off SBOMscope is a working SBOM inventory, not a broken installation —
that is a supported mode, and the UI says so rather than showing an empty table that
looks like a failure. Changing any of it publishes `ScannerSettingsChangedEvent`, the counterpart
to the Maven one below and for the opposite reason: that one invalidates work computed against a
configuration that no longer applies, while this says work that was *skipped* may now be
possible — see **Automatic scan** above.

`MavenToolSettings` carries `enabled`, `executablePath`, `maxProbes`, `runBudgetMinutes`,
`profiles`, `dependencyPluginVersion` and `helpPluginVersion` for the Tier 2 bump probe above. Same shape and same reasoning as `ScannerSettings`:
a path the user supplies and never one SBOMscope downloads, off by default since probing is a
real external process that can take real wall-clock time. Changing any of it publishes
`MavenSettingsChangedEvent`, which clears both `BumpProbeService.progressByKey` (a cached
answer against an old configuration is worse than a re-probe) and `EffectivePomCache`.

`WorkspaceAnalysisSettings` carries `mavenLocalRepository`, `maxRunMinutes` and
`maxHeapMegabytes`. The former
defaults to the user's `~/.m2/repository`, is visibly **read-only**, and is separate from the
app-owned Maven probe repository. Runtime defaults to 10 minutes (1–60 allowed), and worker heap
defaults to 1 GiB (256 MiB–8 GiB allowed). Both are parent-enforced boundaries on isolated WALA
workers, not settings passed to a user build or Maven process.
