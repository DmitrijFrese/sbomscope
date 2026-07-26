# SBOMscope — Implementation Plan

Working document. Iterated across implementation sessions.

**How to use this file**: work top-down through the phases. Check items off as they
land. Add newly-discovered work as you go. Record design decisions in the decision log
at the bottom — including reversals, with the reasoning.

Last updated: 2026-07-26 · Status: **Phase 0 not started**

---

## Milestones

| Phase | Goal | Status |
|---|---|---|
| 0 | Project scaffolding runs end to end | Not started |
| 1 | Upload an SBOM and see its components | Not started |
| 2 | Offline vulnerability matching works | Not started |
| 3 | Findings enriched with NVD / KEV / EPSS | Not started |
| 4 | Vulnerability table complete | Not started |
| 5 | Excel export | Not started |
| 6 | Dependency tree | Not started |
| 7 | Workspace usage detection | Not started |
| 8 | Upgrade path analysis | Not started |
| 9 | Packaging and distribution | Not started |

---

## Phase 0 — Scaffolding

Goal: `run` the project and get a React page served by Spring Boot, with storage wired
up and nothing else.

- [ ] Decide build tool (Maven vs Gradle) — see open questions
- [ ] Spring Boot backend skeleton with health endpoint
- [ ] React frontend skeleton, built and served by the backend as static assets
- [ ] Choose and wire embedded storage (H2 vs SQLite) — see open questions
- [ ] Local config pattern: `application.yml` committed, `application-local.yml`
      git-ignored, NVD API key read from env var or local config
- [ ] `.gitignore` covering secrets, build outputs, IDE files, local data
- [ ] Document the actual repo layout in `AGENTS.md`
- [ ] Document how to build and run in `README.md`

**Done when**: a single documented command starts the app and serves a page in the
browser.

## Phase 1 — SBOM ingestion

Goal: upload a CycloneDX JSON file, persist it, browse its components.

- [ ] CycloneDX JSON parsing (consider the official `cyclonedx-core-java` library
      rather than hand-rolling)
- [ ] Validate/reject non-CycloneDX and unsupported-version uploads with a clear error
- [ ] Data model: SBOM record (filename, upload date, optional workspace path) +
      components (purl, group/name, version, direct vs transitive) + the dependency
      graph edges
- [ ] Determine direct vs transitive from the SBOM's `dependencies` graph relative to
      the root component
- [ ] Upload endpoint + persistence
- [ ] Left sidebar: list uploaded SBOMs with filename, date, metadata
- [ ] Select an SBOM → see its component list
- [ ] Delete an uploaded SBOM

**Done when**: a Maven-generated and an npm-generated SBOM both upload cleanly, persist
across a restart, and list their components.

**Test fixtures**: generate real SBOMs from a small Maven project and a small npm
project and commit them as test resources.

## Phase 2 — Offline vulnerability matching

Goal: know which components have known vulnerabilities, with no internet access.

- [ ] Decide how OSV-Scanner is obtained and located — bundled, or user-supplied path
      in config (see open questions)
- [ ] Local OSV database management: where the per-ecosystem zips live, how the path is
      configured, how the user refreshes them
- [ ] Invoke OSV-Scanner in `--offline` mode against an uploaded SBOM; parse its output
- [ ] Component-level vulnerability cache keyed by purl, shared across SBOMs
- [ ] Cache entries carry `lastRefreshed`; staleness threshold configurable, default 7
      days
- [ ] Force-refresh: per component and globally
- [ ] Surface "data may be outdated" state to the API
- [ ] Handle the no-database-present case with an actionable error, not a crash

**Done when**: uploading an SBOM on a machine with no internet produces a list of
findings, and the same library across two SBOMs is only looked up once.

## Phase 3 — Enrichment

Goal: each finding carries severity, exploitation signals, and canonical links.

- [ ] NVD feed client: single authenticated channel, internal rate limiter safely under
      50 req/30s, API key from env/local config
- [ ] Handle NVD 403/throttling with backoff and a clear user-facing message
- [ ] Local NVD metadata cache (CVSS score + rating, description, published date)
- [ ] CISA KEV catalog ingest → boolean actively-exploited flag per CVE
- [ ] EPSS ingest → probability score per CVE
- [ ] Cache refresh flow for all three feeds, user-triggered only, showing per-feed last
      refresh time
- [ ] Reconcile conflicting severity between sources — define precedence and make it
      visible

**Done when**: findings show CVSS, EPSS, and KEV status, and the whole enrichment set
can be refreshed on demand from a connected machine and then used offline.

## Phase 4 — Vulnerability view

Goal: the main table, complete and usable.

- [ ] Table with all 9 columns, shown by default (no expandable detail row)
- [ ] CVE cells link to NVD; component cells link to Maven Central / npmjs.com
- [ ] Sorting and filtering (at minimum by severity, KEV, direct/transitive)
- [ ] Handle SBOMs with thousands of components without freezing the browser
      (virtualized rows or pagination)
- [ ] Top menu with icon+text, collapsible to icons only
- [ ] Empty/loading/stale-data states

**Done when**: a real project's SBOM renders a sortable, filterable findings table with
working links.

## Phase 5 — Excel export

Goal: the differentiator. A spreadsheet people actually want.

- [ ] Apache POI export of the current findings table
- [ ] CVE cells as real hyperlinks to NVD
- [ ] Component cells as real hyperlinks to Maven Central / npmjs.com (correct URL
      construction per ecosystem from the purl)
- [ ] Header row formatting, frozen header, sensible column widths, autofilter
- [ ] Include export metadata (SBOM filename, export date, data freshness per feed)
- [ ] Export respects current filters/sort, or explicitly exports everything — decide
      and document

**Done when**: the exported file opens cleanly in Excel with working links and needs no
manual cleanup.

## Phase 6 — Dependency tree

Goal: understand where a vulnerable library comes from.

- [ ] Build the in-memory graph from the SBOM `dependencies` array
- [ ] For a selected component: ancestors (who pulls this in) and descendants,
      recursively
- [ ] Handle cycles and diamond dependencies without infinite recursion
- [ ] Tree or graph rendering — decide which (see open questions)
- [ ] Navigate from a vulnerability row into the tree view

**Done when**: selecting a transitive vulnerable library shows the full chain from the
root project down to it.

## Phase 7 — Workspace usage detection

Goal: is this vulnerable library actually used in my source?

- [ ] Attach an optional workspace path to an SBOM (validate it exists and is readable)
- [ ] Map a component to the source-level identifiers it would appear as — Java package
      names for Maven coordinates, module specifiers for npm packages. **This mapping is
      the crux of the feature and needs design work; see risks.**
- [ ] Source scanning honouring ignore rules (`.gitignore`, `node_modules`, `target`,
      `build`, `dist`)
- [ ] Per-component result: total hit count + affected files with fully-qualified paths
- [ ] Hit preview: ±5 lines around each hit
- [ ] Syntax highlighting in the preview, language chosen by file extension
- [ ] Library selector with live search, scoped to the current SBOM
- [ ] Feed usage status back into the vulnerability table's Workspace usage column
      (Used / Not found / Not analyzed)
- [ ] Scan performance on a large repository — keep the UI responsive, allow cancelling

**Done when**: pointing at a real repository correctly distinguishes a library that is
imported in source from one that is only present transitively.

## Phase 8 — Upgrade path analysis

Goal: what's the smallest version bump that fixes this?

- [ ] **Resolve the manifest dependency first — see risks.** OSV-Scanner's guided
      remediation operates on `pom.xml` / `package-lock.json`, not on an SBOM.
- [ ] Invoke guided remediation (or the fallback approach) per project
- [ ] Present results in the patch → minor → major escalation model: for each step,
      the best available version and how many vulnerabilities it clears
- [ ] Populate the Recommended upgrade column
- [ ] Make clear when no upgrade resolves the finding

**Done when**: a vulnerable library shows concrete target versions with the vulnerability
counts they would leave behind.

## Phase 9 — Packaging

- [ ] Single-artifact build (backend + frontend bundled)
- [ ] Documented first-run setup: where to put the OSV database, how to set the NVD key
- [ ] Documented offline workflow: how to populate caches on a connected machine and
      move them to a restricted one
- [ ] Sample SBOMs and a quickstart

---

## Risks and design gaps

Live list of things known to need resolution before or during the phase they affect.

### R1 — Upgrade path analysis may require manifest files, not just an SBOM

**Phase 8.** OSV-Scanner's guided remediation works against `pom.xml` and npm lockfiles.
It does not take an SBOM as input. That means upgrade path analysis, as specified,
likely cannot run from an uploaded SBOM alone — it needs the workspace path, which the
spec currently treats as *optional*.

Options:
- **(a)** Require a workspace path for upgrade analysis; degrade gracefully with a
  clear "workspace needed for this" message when absent. Simplest, honest.
- **(b)** Let the user upload the manifest file alongside the SBOM.
- **(c)** Implement upgrade analysis ourselves: enumerate available versions of the
  library, check each against the local OSV database, report which candidates are
  clean. Needs a version-list source (registry metadata), which is another network
  dependency to cache offline.

Not yet decided. Affects how central the workspace path is to the product.

### R2 — Component-to-source-identifier mapping

**Phase 7.** A Maven coordinate (`com.fasterxml.jackson.core:jackson-databind`) is not
the same as the Java package imported in source (`com.fasterxml.jackson.databind`), and
npm package names don't always match their import specifiers either. Naive matching
will produce both false positives and false negatives. Needs a deliberate strategy —
possibly reading package names from the artifact itself, or a heuristic with a visible
confidence signal.

### R3 — OSV-Scanner distribution in restricted environments

**Phase 2.** "Single static binary" is only an advantage if the user can actually get it
onto the machine. Downloading an unsigned binary may itself be blocked. Decide whether
we bundle it, or document obtaining it, and what happens when it's absent.

---

## Open questions

- [ ] **Build tool** — Maven or Gradle for the backend?
- [ ] **Embedded storage** — H2 or SQLite? (H2 is the natural JVM fit; note
      Dependency-Track users have reported H2 corruption over time, though at a very
      different scale of use.)
- [ ] **OSV-Scanner acquisition** — bundle the binary, or require the user to supply a
      path? (See R3.)
- [ ] **Upgrade path approach** — resolve R1.
- [ ] **Dependency view rendering** — collapsible tree, or a graph visualization?
- [ ] **License** — not yet chosen.
- [ ] **Multi-module Maven projects** — one SBOM per module or an aggregate? Affects the
      dependency graph root and workspace mapping.

---

## Decision log

Append new decisions here with date and reasoning. Reversals stay in the record.

- 2026-07-26 — **Engine strategy**: orchestrate existing OSS engines (OSV-Scanner, NVD
  feed, CISA KEV, EPSS) rather than building CVE-matching and upgrade-path logic from
  scratch. Constrained to tools that work fully offline, because SBOMscope targets
  restricted environments: no internet access on the analysis machine, no admin rights
  to install engines.
- 2026-07-26 — **Workspace usage v1**: simple import/symbol detection. Deep call-graph
  reachability (Eclipse Steady / OWASP dep-scan + atom) explicitly deferred; those need
  separate vetting for restricted environments (JVM/Python toolchains, own vuln feeds).
- 2026-07-26 — **Persistence**: backend-local storage (files / embedded DB) as the
  source of truth, not browser IndexedDB. A local backend is required anyway for
  filesystem access during workspace scanning, so routing state through the browser
  would only duplicate what the backend can already persist.
- 2026-07-26 — **CVE sources**: blend NVD + GitHub Advisories + OSV rather than NVD
  alone, for freshness and coverage.
- 2026-07-26 — **Export links**: library cells link to the public registry (Maven
  Central / npmjs.com), not a configurable internal repository URL — exports stay
  meaningful for any reader.
- 2026-07-26 — **Exploit data**: both CISA KEV (binary actively-exploited flag) and EPSS
  (probability score).
- 2026-07-26 — **Project name**: SBOMscope.
- 2026-07-26 — **Tech stack**: Spring Boot (Java) backend, React frontend. Java is the
  maintainer's primary language; Apache POI gives native Excel-with-hyperlinks support,
  which is a core deliverable; OSV-Scanner runs as an external binary either way, so it
  didn't constrain the choice; and the JVM keeps the door open to embedding a JVM-based
  reachability engine directly in a later version.
- 2026-07-26 — **Table columns**: "Mitigated by firewall or other" and "Comments" were
  added, then **reverted**. Scope limited to columns SBOMscope can populate from a real
  data source; manual judgment fields belong in Excel post-export. This also removed the
  need for an annotation-persistence layer and a stable finding-identity design across
  re-scans, and with it the "group SBOMs into projects" question raised to support it.
  That grouping question may return if a genuinely separate need appears (e.g. trend
  analysis over time).
- 2026-07-26 — **One SBOM at a time** in the vulnerability view; no multi-SBOM
  aggregation in v1. A shared cross-SBOM component-level cache is still required, with
  staleness flagging (default 7 days) and manual force-refresh — never automatic.
- 2026-07-26 — **Library search scope**: current SBOM/workspace only, not global across
  all uploads.
- 2026-07-26 — **NVD access**: single authenticated channel with an internal rate
  limiter safely under 50 req/30s. A dual keyed+unkeyed concurrent design was proposed
  and **rejected** — NVD's terms allow blocking access for apparent circumvention of
  rate limits, and the throughput gain would have been roughly 10%. The API key is never
  committed: env var or git-ignored local config, with only a template in the repo.
- 2026-07-26 — **Table density**: all 9 columns visible by default, no expandable detail
  row in v1.
- 2026-07-26 — **Documentation split**: `README.md` (public-facing product
  documentation), `AGENTS.md` (agent conventions and constraints), and this file
  (roadmap, risks, decisions). All documentation is written for a general audience.
