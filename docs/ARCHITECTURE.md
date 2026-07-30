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
  fixed_version, published_at
  UNIQUE (purl, osv_id)

osv_index                the OSV archives, parsed for candidate-version evaluation
  ecosystem, package_name, osv_id, cve_id, rating, affected
  PRIMARY KEY (ecosystem, package_name, osv_id)

osv_index_source         which archive produced it, so a refresh invalidates it
  ecosystem, identity, advisories, packages, built_at
```

`osv_index` (V2) is **derived data**: rebuildable from the archive at any time, and erasing
the archives should take it with them. It exists because the archives name their entries by
advisory id rather than by package, so finding one library's advisories means parsing all of
them — 5.2 s and ~152 MB retained for npm, measured. Parsed once into a table instead, a
lookup is an indexed `SELECT` and nothing is held in memory.

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

`FindingQuery` carries sort, direction, text filter, severity bands, limit and offset.
The view, the row counts and the export all pass through the same object into the same
SQL, which is what guarantees an exported spreadsheet matches the screen it came from.
Do not add a second code path that sorts or filters independently.

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

**Isolated repository, never `~/.m2`.** Every probe resolves into
`~/.sbomscope/probe-repo` (`SettingsService.defaultProbeRepository`). A failed probe's
`.lastUpdated` markers must not be able to make a later real build refuse to retry a download,
so the user's own local repository is never touched.

> **Known limitation — this cannot work fully air-gapped.** `-Dmaven.repo.local` *overrides* the
> local repository, so a correctly configured Maven gives the probe the user's mirrors and
> credentials from `settings.xml` but **not** the contents of their `~/.m2`. With a reachable
> mirror the plugin simply downloads into `probe-repo`, which is why this works on an ordinary
> machine. With no reachable repository there is nowhere for it to come from, so every probe
> fails at plugin resolution (`ProbeFailureReason.PLUGIN_UNAVAILABLE`) while a full `~/.m2` sits
> unused. Pinning the plugin versions below makes the required set finite and knowable, so
> seeding is possible in principle. **Unresolved** — see the 2026-07-30 entry in the plan's
> decision log, which records a measured candidate fix (`maven.repo.local.tail`) and why it is
> not a complete answer on its own.

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

**Probe progress is session-scoped, not persisted**, keyed by `moduleBomRef -> targetCoordinates`
in `BumpProbeService.progressByKey` — cleared on Maven settings change (a stale answer against
an old configuration is worse than a re-probe) and on process restart. `POST
/component/bump` starts or returns the existing run; `GET /component/bump` polls it.

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

## Key flows

**Upload** — `SbomController.upload` → `SbomService.importSbom`. The document is written
to disk *first*, then parsed back off disk, so a later re-scan uses the file as uploaded
rather than one reconstructed from our own parse. Parsing failures delete the stored file.
The whole import is one transaction.

**Scan** — `ScanController.scan` → `ScanService.scan`. Checks settings, runs `--version`
to record what ran, invokes the scanner against the stored document, parses the report,
resolves packages back to purls, then writes a scan row for **every** component and
replaces that component's findings wholesale (so a withdrawn advisory disappears).

**View** — `ScanController.findings` returns a page of `FindingRow` plus totals: the
unfiltered vulnerability count for the headline, and the filtered row count for paging
and export labels.

**Export** — `ScanController.export` → `FindingsExcelExporter`. Two scopes: `visible`
reproduces the current page, filter and sort; `all` keeps sort and severity selection but
drops text filter and paging. Registry URLs come from `RegistryLinks`, the same code the
API sends to the browser, so view and export cannot drift.

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

---

## Settings

Stored in `app_setting`, editable from the UI, so no file editing or restart is needed.
Deliberately **not** where secrets go — there are none today, and if one appears it
belongs in an environment variable or git-ignored config, never in the database.

`ScannerSettings` carries `enabled`, `executablePath` and `databaseDirectory`. With
scanning switched off SBOMscope is a working SBOM inventory, not a broken installation —
that is a supported mode, and the UI says so rather than showing an empty table that
looks like a failure.

`MavenToolSettings` carries `enabled`, `executablePath`, `maxProbes`, `runBudgetMinutes`,
`profiles`, `dependencyPluginVersion` and `helpPluginVersion` for the Tier 2 bump probe above. Same shape and same reasoning as `ScannerSettings`:
a path the user supplies and never one SBOMscope downloads, off by default since probing is a
real external process that can take real wall-clock time. Changing any of it publishes
`MavenSettingsChangedEvent`, which clears both `BumpProbeService.progressByKey` (a cached
answer against an old configuration is worse than a re-probe) and `EffectivePomCache`.
