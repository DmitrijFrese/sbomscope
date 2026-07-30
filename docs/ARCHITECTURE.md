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

---

## Settings

Stored in `app_setting`, editable from the UI, so no file editing or restart is needed.
Deliberately **not** where secrets go — there are none today, and if one appears it
belongs in an environment variable or git-ignored config, never in the database.

`ScannerSettings` carries `enabled`, `executablePath` and `databaseDirectory`. With
scanning switched off SBOMscope is a working SBOM inventory, not a broken installation —
that is a supported mode, and the UI says so rather than showing an empty table that
looks like a failure.
