# SBOMscope — Implementation Plan

Working document. Iterated across implementation sessions.

**How to use this file**: work top-down through the phases. Check items off as they
land. Add newly-discovered work as you go. Record design decisions in the decision log
at the bottom — including reversals, with the reasoning.

Last updated: 2026-07-30 · Status: **Phases 0–2, 4–7 complete. Phase 8 Tier 1 complete; Tier 2
passes A, B and C built and verified against a real `mvn`, plus the configurable probe budget,
Maven profiles, configurable plugin versions, queued-vs-running status, full `mvn` command and
output logging, continuable searches, and honest reporting of a budget-truncated major. One
open question carried forward: the isolated probe repository cannot work on a fully air-gapped
machine — see the decision log. B-items started: **B1 (session-scoped per-SBOM component tabs)
is built and verified live**, and B1a (Monitoring: the probe queue, stopping it, and the full log)
with it; B2 onward next — then Phase 3 and Phase 9**

---

## Milestones

| Phase | Goal | Status |
|---|---|---|
| 0 | Project scaffolding runs end to end | **Done** |
| 1 | Upload an SBOM and see its components | **Done** |
| 2 | Offline vulnerability matching works | **Done** |
| 3 | Findings enriched with KEV / EPSS | Not started |
| 4 | Vulnerability table complete | **Done** |
| 5 | Excel export | **Done** |
| 6 | Component Inspector: the shell | **Done** |
| 7 | Dependency graph | **Done** |
| 8 | Upgrade paths | **Tier 1 done; Tier 2 works, second pass planned** |
| 9 | Workspace usage detection | Not started |
| 10 | Packaging and distribution | Not started |
| 11 | VEX — read a supplier's "not affected" | Not started |

Phases 6–9 are one screen, described under [The Component Inspector](#the-component-inspector).
Nothing was dropped in that regrouping: the dependency tree, upgrade analysis and workspace
usage all survive with their scope intact, re-homed and reordered.

---

## Phase 0 — Scaffolding

Goal: `run` the project and get a React page served by Spring Boot, with storage wired
up and nothing else.

- [x] Verify the toolchain (Java 21 LTS, Maven 3.9) builds and runs
- [x] Maven multi-module skeleton: parent + `frontend` + `backend`
- [x] Spring Boot backend skeleton with a status endpoint
- [x] React (Vite) frontend skeleton, built into the backend jar and served from it
- [x] SPA fallback, so client-side routes survive a browser refresh
- [x] Vite dev proxy for `/api`, so hot reload works during development
- [x] Embedded H2 datasource
- [x] Flyway wired up with the initial baseline migration
- [x] Light/dark theming with a Settings → UI theme switcher
- [x] `.gitignore` covering secrets, build outputs, IDE files, local data
- [x] Document the actual repo layout in `AGENTS.md`
- [x] Document how to build and run in `README.md`, including a troubleshooting note
      for TLS-inspecting security software
- [x] Local config pattern — no longer needed for a credential, since the NVD API was
      dropped and nothing else requires one. Revisit if a feature ever introduces a secret
- [x] Commit `package-lock.json` and switch the frontend build to `npm ci` for
      reproducible dependency resolution (28 packages total)
- [x] Review the artifact's own dependency weight — dropping Spring Data JPA for plain
      JDBC took the jar from 53 MB to 26 MB. Apache POI then added ~18 MB (`poi-ooxml-lite`
      5.7 MB, `poi` 2.9 MB, and `commons-math3` 2.1 MB pulled in transitively), leaving it
      at 44 MB. POI earns that: a real .xlsx with working hyperlinks is the feature, and
      hand-rolling OOXML would be far worse
- [x] Erase local data from Settings, behind a typed confirmation, choosing independently
      between uploaded SBOMs, the vulnerability cache, settings and the OSV archives
- [ ] Trim POI's transitive weight if it becomes a problem — `commons-math3` is pulled in
      for chart support we never use, and may be excludable

**Done when**: a single documented command starts the app and serves a themed page in
the browser, backed by a migrated H2 schema.

## Phase 1 — SBOM ingestion

Goal: upload a CycloneDX JSON file, persist it, browse its components.

- [x] CycloneDX JSON parsing — hand-written Jackson mapping rather than
      `cyclonedx-core-java`, which would add seven runtime dependencies including XML
      support for a document we only read two sections of, in JSON only
- [x] Validate/reject non-CycloneDX uploads with a clear, user-facing error
- [x] Data model: SBOM record (filename, upload date, optional workspace path) +
      components (purl, group/name, version, direct vs transitive) + dependency edges
- [x] Determine scope from the `dependencies` graph — application, direct or transitive,
      relative to the application rather than to the root alone (see decision log)
- [x] Upload endpoint + persistence, in a single transaction
- [x] Left sidebar: list uploaded SBOMs with filename, date, metadata
- [x] Select an SBOM → see its component list
- [x] Delete an uploaded SBOM
- [x] Drag-and-drop upload. Replaced the native file input, whose own "Choose file" label the
      browser sizes and refuses to ellipsize — inside the 280px sidebar it was cut off
- [x] Progress while a scan runs: indeterminate, with the component count and elapsed time.
      Deliberately not a percentage — osv-scanner reports once, at the end
- [ ] Component list is currently unpaginated; revisit in Phase 4 alongside the findings
      table, where the thousands-of-rows requirement actually bites

**Done when**: a Maven-generated and an npm-generated SBOM both upload cleanly, persist
across a restart, and list their components. — **Met.**

**Test fixtures**: real SBOMs, generated by the actual tools rather than hand-written —
`maven-sbomscope.cdx.json` (CycloneDX Maven plugin, spec 1.6, 61 components) and
`npm-frontend.cdx.json` (`npm sbom`, spec 1.5, 29 components). Both are SBOMscope's own
dependency trees, so the fixtures stay honest as the project evolves.

## Phase 2 — Offline vulnerability matching

Goal: know which components have known vulnerabilities, with no internet access.

- [x] Decide how OSV-Scanner is obtained and located — user-supplied path, never
      downloaded by us (R3)
- [x] Scanning is a toggle. Switched off, SBOMscope is a working SBOM inventory rather
      than a broken installation
- [x] Settings persisted in the database and editable from the UI (`app_setting`, V3)
- [x] Validate the configured binary: path checks plus a `--version` round trip that
      confirms it really is osv-scanner
- [x] Local OSV database management: per-ecosystem download on explicit user action,
      into the `{dir}/osv-scanner/{ecosystem}/all.zip` layout the scanner expects.
      Downloaded individually — npm's archive is ~200 MB against Maven's ~10 MB
- [x] Handle the no-database-present case with an actionable error, not a crash
- [x] Downloads run asynchronously with polled progress. A 200 MB transfer held inside
      the HTTP request would tell the user nothing until it finished and be
      indistinguishable from a hang. Written to `all.zip.partial` and atomically moved
      into place, so a refresh never leaves the scanner pointed at a truncated archive
- [x] Settings shows the exact source URL and the absolute on-disk path per ecosystem,
      so nothing is downloaded opaquely and the files can be found, copied or deleted
- [x] Settings links to the OSV-Scanner releases page, names the platform builds and
      notes the published checksums — SBOMscope points at the binary, never fetches it
- [x] Downloads are gated on scanning being switched on, with an explicit override for
      staging onto an offline machine. The gate stands, now that the built-in matcher is
      decided against — "scanning off" means no matching engine at all, so the database
      genuinely has no reader.
- [x] Invoke OSV-Scanner in `--offline` mode — **verified against the real binary
      (v2.4.0)**. `scan --lockfile <sbom> --offline --format json` reads a CycloneDX
      document directly, loads the local archive, and exits 1 when it finds something,
      which the runner correctly treats as success rather than failure
- [x] Parse the scanner's JSON report into findings, keyed on `groups[].ids` so aliased
      GHSA/CVE pairs collapse to one finding rather than two rows for one problem
- [x] Select the fix on the component's **own** version branch. An advisory lists fixes
      across several coordinates and branches; taking the first would hand the user a
      version that does not exist for their library
- [x] Component-level vulnerability cache keyed by purl, shared across SBOMs — verified:
      a second, never-scanned SBOM inherits findings for libraries already scanned
- [x] A scan row is written for **every** component, not just vulnerable ones, so
      "checked, clean" is distinguishable from "never checked"
- [x] Staleness: `stale-after-days`, default 7. Never-scanned counts as stale
- [x] Surface staleness, scan coverage and whether scanning is switched off to the API
- [x] Trigger a scan from the vulnerability view and show the findings, with severity
      banded by score and the CVSS revision shown alongside it
- [x] Store the uploaded document so a re-scan uses the original rather than one
      reconstructed from our own parse. **The `.cdx.json` suffix is load-bearing** —
      osv-scanner picks its parser by filename and rejects `<uuid>.json` outright
- [x] Collapse findings that describe the same (component, advisory) pair. Resolving a
      reported package to a purl is many-to-one, so a scan could produce a list that
      violates the database's own uniqueness rule and failed the entire import
- [ ] Force-refresh of a single component's data, independent of its SBOM (whole-SBOM
      re-scan works today)

**Done when**: uploading an SBOM on a machine with no internet produces a list of
findings, and the same library across two SBOMs is only looked up once.

## Phase 3 — Exploitation signals

Goal: findings carry the signals that decide priority, not just existence.

Severity already arrives with the finding: osv-scanner supplies a numeric CVSS score,
and OSV carries the GHSA→CVE alias. **The NVD API is not used** (see decision log), so
this phase is only the two feeds NVD never provided anyway.

- [x] Handle findings with no CVE — 3% of the Maven set are GHSA-only, as are `MAL-*`
      malicious-package entries. The advisory ID is shown and linked to osv.dev instead
- [x] Show which CVSS revision produced a score, so a v3 7.5 is not silently compared
      with a v4 7.5
- [x] Attribute the CVSS vector honestly when a group's aliased advisories disagree about
      severity — the score is the group maximum, the rest of the row is one advisory, and
      the two must not be presented as one statement (see decision log)
- [ ] CISA KEV catalog ingest → actively-exploited flag per CVE
- [ ] EPSS ingest (FIRST.org) → exploitation probability per CVE
- [ ] Refresh flow for both feeds, user-triggered only, showing per-feed last refresh

**Done when**: findings show KEV status and EPSS alongside severity, refreshable on
demand from a connected machine and usable offline afterwards.

## Phase 4 — Vulnerability view

Goal: the main table, complete and usable.

- [x] Findings table with the columns available today — Component, Version, Advisory,
      Severity, Fixed in, Published. EPSS and Known Exploited arrive with Phase 3,
      Recommended upgrade with Phase 8, Workspace usage with Phase 7
- [x] CVE cells link to NVD; advisory cells link to osv.dev when there is no CVE
- [x] Sort by component or severity, ascending or descending, from the column headers
- [x] Severity band filter: Critical / High / Medium / Low / **Unscored** / **No
      vulnerabilities**. The last two are deliberately separate — Unscored is a real
      vulnerability whose advisory carries no CVSS score, "No vulnerabilities" is a
      component with nothing known against it. Merging them would let "we don't know how
      bad this is" read as "this is fine"
- [x] One integrated table rather than separate findings and inventory views. A row is a
      component plus one vulnerability, so a component with three advisories yields three
      self-contained rows and a clean component yields one with the advisory cells empty.
      Built on a LEFT JOIN from component to finding
- [x] Default filter is vulnerabilities only, so the view opens on what needs attention;
      ticking "No vulnerabilities" brings the whole inventory into the same table
- [x] Text filter across component, advisory ID and CVE
- [x] Pagination at 20 / 50 / 100 / 200 rows, so a large SBOM cannot freeze the browser
- [x] Sorting, filtering and paging all execute in SQL, so the view and the export cannot
      diverge from one another
- [x] Empty, loading, never-scanned and stale states
- [x] Component names are links in the view as well as the export. The URL is built by
      the backend and sent with the row, so the two cannot drift apart
- [x] The scan action sits in the page header rather than on its own row, and is gated on
      real readiness — scanner enabled, binary still on disk, and an OSV archive present for
      the ecosystems *this* SBOM actually contains — with the obstacle named next to the
      disabled button and linked to Settings
- [x] One export control instead of two: a split button whose primary action exports the
      view, with both scopes and their row counts in a click-opened menu
- [x] Rows-per-page moved below the table, beside numbered pagination that windows around
      the current page with a constant width
- [x] Top-menu collapse removed — three nav items never justified an icons-only mode
- [x] SBOM sidebar collapses to a rail, so the table can have the width
- [x] Sort, direction, severity bands, page size, text filter and sidebar state persist
      across navigation and reload; the page number deliberately does not
- [x] Advisory and CVE are separate columns, matching the export, so an advisory with no
      CVE shows an empty cell rather than an OSV id under a heading that says CVE
- [x] Every value SBOMscope holds is reachable from the table: GHSA rating, CVSS version,
      CVSS vector, Summary and Package URL joined the existing columns
- [x] Compact / Details toggle and the Columns picker, together behind one view-options menu
      on the actions side of the toolbar. Component, Version, OSV ID and Severity are locked —
      a row without them cannot be acted on
- [x] Columns are ordered so each value sits with its source: GHSA rating against the OSV
      ID it belongs to, the score leading the CVSS values that produced it
- [x] The severity cell shows the CVSS band derived from its own score. It previously
      showed the GHSA rating, which is a different scale from a different source — GitHub
      calls 6.5 MODERATE where CVSS calls it Medium — so the number appeared to be labelled
      by a word that was not describing it
- [x] Glossary page: the vocabulary, and a per-column table naming each column's source
- [x] Transient row numbers, numbered across the whole result rather than per page. Not a
      column: absent from the picker, from Details and from the export, where Excel supplies
      its own numbering
- [x] Per-band counts on the severity chips themselves — unfiltered, so they describe the
      SBOM rather than the view, and equal to the rows selecting that band produces. One SQL
      band expression serves both the filter and the counts, so a chip's number and what
      clicking it shows cannot disagree; covered by `SeverityBandTest` at every threshold

- [x] Critical, high and medium counts on every SBOM card in the sidebar, so a list of
      uploads can be triaged without opening each one. An SBOM the scanner has never
      reached says so instead of showing zeros
- [x] Advisory publication dates are the UTC date, with no time. The local zone moved the
      date across midnight, so an advisory read a day later than the record it links to

**Done when**: a real project's SBOM renders a sortable, filterable findings table with
working links.

## Phase 5 — Excel export

Goal: the differentiator. A spreadsheet people actually want.

- [x] Apache POI export of the findings table
- [x] CVE cells as real hyperlinks to NVD; advisory cells to osv.dev. Deliberately
      different destinations — two columns pointing at the same page wastes one, and the
      OSV record carries affected ranges NVD does not
- [x] Component cells as real hyperlinks to Maven Central / npmjs.com, built per
      ecosystem from the purl, with npm scopes decoded from `%40scope`
- [x] Severity written as a **number**, not text — as text, "10.0" sorts below "6.5" in
      Excel, which is exactly what makes an exported vulnerability list untrustworthy
- [x] Header row formatting, frozen header, column widths, autofilter
- [x] Provenance on its own sheet (SBOM, spec version, components, findings, last
      scanned, exported, data source) — kept off the findings sheet so it cannot break
      sorting and filtering
- [x] Two export scopes, each labelled with its row count: **Export view** reproduces the
      current page, filter and sort exactly; **Export all** keeps the sort but drops
      filter and paging. Counts are shown so nobody sends a filtered subset believing it
      is the whole picture
- [x] Both scopes carry the viewer's sort criterion through to the workbook
- [x] The workbook's columns, order and labels match the table exactly, including the
      Summary and CVSS vector the screen has no room for
- [x] Provenance records what was *selected* — scope, sort, severity bands, text filter and
      columns — so a filtered export can account for its own size instead of looking
      identical to a complete one
- [x] Filenames carry the time to the second. A date alone collided as soon as you exported
      twice in one day, which is the normal case when narrowing a filter
- [x] Settings choose whether a workbook carries every column or only those on screen,
      defaulting to every column

**Done when**: the exported file opens cleanly in Excel with working links and needs no
manual cleanup.

## The Component Inspector

Phases 6 to 9 build one screen, so they are introduced together.

The vulnerability view is **list-centred**: every finding in an SBOM, sorted and filtered,
answering *what is wrong here*. It is deliberately wide and shallow — a row is a fact, and
the table's job is to let you rank facts.

The Component Inspector is **component-centred**: one library, in depth, answering *what do
I do about this one*. Those are different questions and neither view can serve both. A
finding tells you `jackson-databind 3.1.4` has a 6.5; it cannot tell you which version to
move to, what that would cost, who dragged the library in, or whether your code touches it.

It replaces what earlier drafts called the Workspace view. **That name described an input —
a directory — that is optional, and that only one of the three panels below even uses.**
Naming the screen after its least central and last-scheduled feature had the priorities
backwards. It is also not a *viewer*: two of its three panels exist to support a decision,
not to display a record. See the decision log entry of 2026-07-29.

**Reaching it.** Two ways in, and both matter:

- From any row of the vulnerability view, a per-row action on the component. This is the
  common path — you are triaging a list, you hit something real, you want the detail.
- Directly, by picking a library from the current SBOM in a lightweight finder: type-ahead
  over the component list, no page transition. This is the path when you already know which
  library you are asking about.

**The three panels**, in the order they earn their place:

| Panel | Answers | Phase |
|---|---|---|
| Upgrade paths | Which version should I move to, and what does each option still carry? | 8 |
| Dependency graph | Who pulls this in, and what does it drag along? | 7 |
| Workspace usage | Does my own code actually touch this? | 9 |

## Phase 6 — Component Inspector: the shell

Goal: the screen exists, is reachable, and shows one component's identity. No analysis yet.

Small on purpose. It is the thing every later panel needs, and building it first means
phases 7 to 9 each land as a self-contained, shippable panel rather than as a screen that is
half-real for months.

- [x] Rename the route, page and navigation item away from "Workspace". The nav carries the
      full name rather than the noun alone, and `/workspace` redirects rather than falling
      through to the catch-all, so an open tab lands where it meant to
- [x] Per-row action in the vulnerability view opening the selected component here. Leading
      cell beside the row number, and like it not a column — absent from the picker, from
      Details and from the export
- [x] Lightweight finder: type-ahead over the current SBOM's components, keyboard-first,
      scoped to the selected SBOM rather than global (decided 2026-07-26). Filters in the
      browser against the list already fetched, caps the results and says how many it held
      back, and marks the component currently open
- [x] Component header: coordinates, version, scope, purl, registry link, and its own
      findings — from the same query and the same row shape the table uses
- [x] Deep-linkable: the component is a query parameter, so a refresh keeps it. Required
      persisting the selected SBOM too, since the URL names a component but not the document
      it belongs to
- [x] Honest empty states per panel — three states, not two: a vulnerable component, one
      checked with nothing found, and one never scanned at all
- [ ] Component-level re-scan from here. Today the Inspector can say a component has never
      been checked but can only point at the Vulnerabilities view to fix that; the
      single-component refresh in Phase 2 is the missing half

**Done when**: clicking a vulnerable row in the vulnerability view opens that component in
the Inspector, and the finder reaches any component of the selected SBOM. — **Met.**

## Phase 7 — Dependency graph

Goal: understand where a component comes from and what it brings with it.

Scheduled before upgrade paths, though both are top priority — **confirmed 2026-07-29**.
The reason is availability, not importance: **the edges are already in the database.**
`component_dependency` is populated at import, the parser already collapses repeated edges
and drops self-edges, and `ScopeClassifier` already distinguishes the application from its
dependencies. This panel needs no new external data, no network, and no unresolved design
question — where Phase 8 is blocked on R4.

**Rendering decided 2026-07-29: paths upward, a tree downward.** The two directions are
different questions and a single visualisation serves one of them badly.

- [x] Build the in-memory graph for one SBOM from the stored edges
- [x] **Ancestors as paths, grouped by owning module.** The routes from an APPLICATION
      component down to this one, one per line —
      `sbomscope-backend → spring-boot-starter-web → jackson-databind`. That is the literal
      answer to "who pulls this in", it states a diamond honestly by listing both routes
      rather than drawing one, and it pastes into a ticket
- [x] **Several owning modules is the normal case, not an edge case.** Spring is in every
      backend module; a shared library is in most of them. **Every owning module is listed,
      always** — guaranteed by finding the module set with a separate linear reachability
      pass, which no graph can defeat, rather than as a by-product of route enumeration,
      which any dense graph can
- [x] **Cap routes within a module, never the modules themselves.** The three shortest are
      shown with the total beside them, and where enumeration hit its own limit the total is
      written as a floor (`3 of 25+`) rather than as a count it did not finish making
- [x] Lead with the count — *pulled in by 1 of your 2 modules*, before a single route is read
- [x] The parent pom is never the top of a path, **and is not in the denominator either**.
      It aggregates rather than depends, so no route can top out at it; counting it as one of
      "your modules" would put something in the denominator that cannot appear in the
      numerator. Where the root is the only application component — npm, single-module Maven
      — it is the module and counts as one
- [x] **Descendants as a collapsible tree**, with explicit `+`/`−` controls rather than the
      native disclosure triangle, and no scope badge per row: everything below the component
      came in with it, and depth already says how directly
- [x] Handle cycles and diamonds without infinite recursion, and without presenting one
      route as if it were the only one. Each component is expanded once across the tree, so
      a shared subtree is marked *also above* rather than rebuilt under every parent
- [x] Mark vulnerable nodes in both directions, so a chain shows where else the problem sits
- [x] Scoped to the selected SBOM, which is what makes the answer specific to this project
      rather than to the library in general
- [x] No layout engine, and therefore no new frontend dependency: both shapes are ordinary
      lists and disclosure widgets (constraint 9)
- [ ] Verify against a genuinely large SBOM. The guards are tested against constructed
      graphs and the fixture is 61 components; the budgets they enforce have never actually
      been reached

**Done when**: selecting a transitive vulnerable library shows the full chain from the root
project down to it, and what it pulls in below. — **Met.** Against the real Maven fixture,
`jackson-databind` reports three routes from `sbomscope-backend`, shortest first, with the
parent pom absent from all of them.

## Phase 8 — Upgrade paths

Goal: **what do I change, and where** — which is not the same question as "which version".

The earlier draft of this phase answered "which version of this library should I move to",
and for the majority of findings that question has no answer, because **you cannot upgrade
what you do not declare**. `jackson-databind` is vulnerable, the advisory says 3.1.5 fixes
it, and your `pom.xml` has never mentioned jackson. Handing someone "upgrade to 3.1.5" there
is not a remedy, it is a fact they cannot act on.

So the panel is about **remedies**, and the version is one input to them.

### The four remedies

| Remedy | When it applies | What it needs |
|---|---|---|
| **Upgrade it** | You declare it — `DIRECT` scope | The fixed version. Already known |
| **Pin it** | You do not declare it, but can force a version anyway: Maven `dependencyManagement`, npm `overrides`, Gradle constraints | The fixed version. Already known |
| **Bump what pulls it in** | A newer version of the declaring ancestor already ships the fix | That ancestor's dependencies *at candidate versions* — not in the SBOM, not in OSV |
| **Exclude it** | Your code does not use it at all | Workspace usage (Phase 9). Never recommend without it |

Pinning is the quiet discovery here. It is precise, it is a copy-pasteable snippet, it works
regardless of what the ancestor does, and **it needs nothing SBOMscope does not already
hold** — the fixed version comes from the advisory and the ecosystem from the purl. For a
transitive finding it is very often the correct answer, and it was entirely absent from the
earlier design.

Bumping the ancestor is the one that genuinely needs the network. Knowing whether
`spring-boot-starter-json 4.2.0` ships a fixed jackson means reading *its* dependencies at
that version, which no SBOM of your project contains and no advisory database records.

### Version candidates

Where a version is the answer, the candidate set from the earlier draft stands: for a
component at `x.y.z`, the latest `x.y.*`, the latest `x.*.*`, the latest overall, and the
**earliest version clearing every known critical and high**. The first three minimise
disruption and report what that costs; the fourth names the goal and reports what reaching
it costs. Where they coincide, saying so is worth more than four rows of numbers.

Each candidate carries **its own known vulnerabilities, with severities — not a count**.
"Clears 3 of 4" cannot be acted on; *which* one remains decides whether to take it.

### Two tiers, because offline and online answer different amounts

Judging a version is reliable offline; **enumerating** versions is not. See R4.

- [x] **Tier 1 — offline, and unblocked today.** Needs no network and no new policy.
  - [x] Candidate versions taken from the advisories themselves: the `fixed` versions they
        name. The **highest** of them is the pin target, so one pin addresses every advisory
        as each describes itself — the lowest would leave the others in place
  - [x] Name the declaring ancestor from the dependency graph Phase 7 already builds, so a
        transitive finding says *who* to talk to rather than only that it is transitive
  - [x] Emit the pin snippet per ecosystem, ready to paste
  - [x] **State the ceiling honestly**: without a registry the newest release is unknown, so
        "latest patch / minor / overall" are unanswerable and are shown as such rather than
        silently computed from a biased list
  - [x] **Tier 1b — a local matcher over the downloaded OSV archives**: for a package and any
        version, which advisories apply. Scoped to answering hypotheticals, never to
        reporting on what is installed — that stays osv-scanner's job (see Open questions).
        Removes the caveat Tier 1a had to print: the panel now answers whether the target is
        clean instead of saying it cannot
  - [x] Range semantics live in one place. `AffectedVersions` is read by both the report
        parser and the matcher, because two statements of "is this version affected" would
        drift, and the direction they drift in is "this upgrade is clean" against "it is not"
  - [x] The target's own advisories carry the **GHSA rating, never a CVSS score**. OSV stores
        severity as vector strings; the numbers elsewhere were computed by the scanner, which
        only ran against what is installed. Producing one here would mean owning a CVSS
        implementation, refused once already
  - [x] Three states kept apart: the target carries something, the target is checked and
        clean, and no archive was there to check against. The last must never render as the
        second — `targetEvaluated` is what separates them
  - [x] **The index is persisted in H2, not held in memory.** Parsed once into `osv_index`
        (V2), after which a lookup is an indexed SELECT and nothing is retained. Survives a
        restart, which no in-memory arrangement could
  - [x] Built as a visible second step after a download — *step 2 of 2*, with an advisory
        counter rather than a bar, since the archive announces no total
  - [x] **Index** action for an archive already on disk: one carried across by hand, or
        downloaded before the index existed. Without it the only route to an index would be
        re-fetching 200 MB, which on an air-gapped machine is no route at all
  - [x] The index is keyed to the archive's size and modification time, so a refreshed
        download invalidates it by itself
  - [ ] **npm's disk cost is unmeasured.** Maven's 6,860 advisories added ~10 MB to the
        database; npm has 223,786 over 220,027 packages, so extrapolation suggests a few
        hundred MB. The trade is RAM for disk and it is the right one, but the number should
        be taken rather than guessed at
  - [ ] **Purge does not clear the index.** Erasing the OSV archives leaves `osv_index`
        behind, which is derived data pointing at files that no longer exist. It should go
        with them
### Bumping the declared dependency, properly

`root → A (direct) → B → C`, with the vulnerability in C. Telling someone to move C is
telling them to override a version they never chose; **the fix upstream intended is a newer
A that already brings a fixed C.** That remedy is currently listed and permanently
unavailable, which is the least useful state a remedy can be in.

Making it real needs A's *resolved* dependency tree at each candidate version — not its
declared dependencies, its resolved ones, after nearest-wins, `dependencyManagement`, BOM
imports and exclusions have had their say. That exists in no SBOM of your project and in no
advisory database, which is why this is Tier 2 and not a matter of trying harder offline.

**Three properties decide between remedies, and they are not one axis.**

| | What it asks | Where it comes from |
|---|---|---|
| **Route completeness** | Does it fix *every* route to C, or only the ones through A? | The Phase 7 graph |
| **Blast radius** | How much moves — a patch on one library, or a major on a widely-shared one | Version distance, resolved tree diff |
| **Durability** | Does the fix ship in a release, or is it a constraint you now own forever? | Which remedy it is |

**Route completeness is the sharp one, and it is the argument for pinning that was missing.**
Where C is reached by `A → B → C` *and* `D → E → C`, bumping A fixes one route and leaves
the other — the finding does not go away, and a panel that reported success would be wrong.
A pin is route-complete by construction: it constrains C wherever C appears. That is not a
simplicity argument, it is a correctness one, and it is why a pin can remain the right answer
even when a newer A exists.

**Naming the blocker is worth as much as naming the fix.** With resolved trees for A's
candidate versions, "no version of A resolves this" becomes answerable — and so does *why*:
the constraint is B, which has no fixed release. That tells a reader to go and open an issue
against B, which is the actual next action and something nothing else in the tool can say.

### Tier 2 — driving the user's own build tool

**Designed 2026-07-29. No external API is called; SBOMscope drives a tool the user
configures.** Maven first; Gradle and npm are the same shape with different probe scripts.

Configured exactly as the scanner is: user-supplied path, a Test button, unavailable rather
than broken when absent.

**The probe.** A generated POM in a temp directory declaring one dependency at a *version
range*, resolved with `mvn dependency:tree`. Ranges do both jobs at once — Maven picks the
version *and* reports the tree it resolves — so "which versions exist" and "what does each
pull in" stop being separate problems:

| Candidate | Range | Maven resolves to |
|---|---|---|
| Latest patch | `[4.1.0,4.2.0)` | highest 4.1.x |
| Latest minor | `[4.1.0,5.0.0)` | highest 4.x |
| Latest overall | `[4.1.0,)` | highest release |

Core Maven plugins only. **No settings parsing and no credentials**: Maven reads its own
`settings.xml`, so mirrors, authentication and proxies come along for free and SBOMscope
never learns them.

- [x] `DependencyResolver` behind an interface, per the standing convention on engine
      integrations — the Maven probe today, a Gradle or npm probe later. `MavenDependencyResolver`
- [x] **Resolve into an isolated local repository** (`~/.sbomscope/probe-repo`), never the
      user's `~/.m2`. A failed probe writes `.lastUpdated` markers that can make a later
      *real* build refuse to retry a download; perturbing someone's build environment to
      answer a question they asked idly is not a trade worth making. Nearly free, because
      `dependency:tree` needs POMs and not jars — kilobytes per artifact
- [x] **Version enumeration comes from our own repo.** Resolving a range makes Maven download
      metadata into the local repository to learn what exists; we read it from disk afterwards.
      **Not `maven-metadata.xml`** — found live, cost real debugging time: Maven caches this
      per remote repository, named after the repository id (`maven-metadata-central.xml`), and
      a plain `maven-metadata.xml` is not necessarily ever written to the local repo at all.
      `knownVersions` reads every `maven-metadata*.xml` present and merges them. No HTTP by us,
      so "we never call out, Maven does" survives
- [x] **Calibration probe.** Before trusting any candidate, probe the declaring dependency at
      its *current* version and compare the resolved C against the C the SBOM reports.
      Matching means the isolated model reproduces their build for this chain and candidate
      results can be trusted; differing means something in their project is overriding it,
      the bump remedy is unverifiable, and the pin is the answer. Converts "we cannot really
      rely on this" into a checked claim
- [x] **With a workspace, lift in the project's `dependencyManagement`** via
      `mvn help:effective-pom`, so their pins and imported BOMs are honoured. Without one the
      probe stays isolated and says so. `EffectivePomCache`, cached per workspace path for the
      process lifetime. Built and unit-covered; not yet exercised live against a real workspace
      with its own `<repositories>` — the supplier-artifact case below is the reason it exists,
      and that specific path deserves a real test project with a custom repository before it's
      trusted the way the rest of this phase now is
- [x] **Search order: tiers first, then refine.** Three probes establish whether any bump
      works and in which tier — actionable in under half a minute — then walk ascending
      inside the winning tier for the true earliest. **Not a binary search**: "brings a fixed
      C" is not monotonic in the version, since a newer release can introduce a fresh
      advisory, so an ordered search would report an earliest that is not one. Verified live
      against a real `mvn`: `spring-boot-starter-web` 2.1.0.RELEASE → 4.1.0 cleared
      `tomcat-embed-core`, correctly refined by walking eight ascending patch releases (all
      still affected) before honestly falling back to the confirmed-clean 4.1.0 rather than
      guessing further
- [x] Live progress while probing, linked to the log, with each probe's verdict recorded:
      *4.2.0 → jackson-databind 3.1.6 → clean* against *→ 3.1.4, still affected by GHSA-…*.
      `BumpProgress`, polled the same way `DownloadProgress` already is
- [x] **Probes will fail, and the likely reason is ours.** Observed in real use, twice over:
      (1) the scenario this bullet anticipated — a generated POM with no `<repositories>` —
      is handled by the workspace lift-in above; (2) a *different* real failure surfaced during
      verification: a fresh, empty `probe-repo` cannot resolve **any** plugin at all without
      network access, so on a machine where Maven itself needs
      `-Djavax.net.ssl.trustStoreType=Windows-ROOT` (TLS-inspecting security software — see the
      README), the very first probe fails with `NoPluginFoundForPrefixException` until the
      SBOMscope process inherits `MAVEN_OPTS`. Documented in the README troubleshooting section
      as the same root cause as the existing OSV-download note, since it is
- [x] **Fall back per component, never globally.** A probe that fails falls back to the Tier 1
      answer for *that component* — the pin still applies and is still correct. One
      unresolvable supplier artifact must not switch the feature off for everything else.
      Confirmed live: a `keycloak-core` probe failure (initially the plugin-resolution issue
      above, later an honest "no candidate resolves this cleanly") never affected the
      `spring-boot-starter-web` probe run moments later against a different component
- [x] **Say which failure it was.** "Not found in any configured repository" sends the reader
      to add a repository; "authentication failed" sends them to their credentials; "Maven is
      not runnable" is a settings problem. One generic failure message would waste the only
      moment the reader could act. `ProbeFailureReason`; the live `NoPluginFoundForPrefixException`
      matched none of the specific patterns and fell to `OTHER` with the raw message kept rather
      than discarded — the classification patterns are a starting set, not a closed one
- [x] **Remember failures.** A known-unresolvable artifact must not be re-probed on every view
      of the panel. Cache the negative result against the artifact and the settings that
      produced it, and clear it when the build tool configuration changes. **Session-scoped
      in-memory, deliberately not persisted** (decided 2026-07-29) — a restart is a fine time
      to re-validate against whatever Maven configuration is current, and it avoids a migration
      for data that is inherently tied to "the config as of five minutes ago"
- [x] A timeout per probe, and a budget for the run. Maven can hang on an unreachable
      repository, and the panel must be able to give up and say so. 60s per probe, 5 minutes
      per component overall, 8 ascending-refinement probes at most
- [ ] Per remedy: routes fixed of routes total, change size on the artifact *you* edit, and
      whether the fix is upstream or a constraint you maintain. **Deferred from the first pass;
      planned in the second pass below.** `DependencyGraphService` caps routes shown per module
      at 3 and reports a floor past 25 (`ComponentGraph.ModuleRoutes.truncated`), so counting
      "routes fixed" against the *shown* routes would undercount whenever a module reaches a
      component more than three ways — exactly the kind of confident-but-wrong number this
      project designs against. Needs an uncapped "routes through ancestor X" query
- [ ] Where no candidate resolves it, name the component in the chain that is holding it —
      the blocker, not just the failure. Deferred: identifying *why* a chain is stuck needs
      comparing resolved trees across candidates for provenance, which the first-pass probe
      does not retain. The whole-module probe below retains enough to make this answerable
- [ ] Suggested remedy = clears every critical and high **and** fixes every route, at the
      smallest change size; ties broken toward the upstream fix over the local override.
      Waiting on route completeness — `advice.suggested` is still Tier 1's UPGRADE/PIN choice
      only, and a successful `BUMP_ANCESTOR` is never offered as the suggestion even when it
      clears everything, because "fixes every route" cannot yet be checked
- [ ] A remedy that fixes some routes and not others is reported as partial, never as a fix.
      Same dependency — today a probed `BUMP_ANCESTOR` is either the full remedy (every
      advisory the target carries today, cleared) or absent; there is no partial state,
      because route completeness is what a partial fix would be measured against

### Tier 2, second pass — search shape, and route completeness by construction

**Planned 2026-07-29, after using the first pass against a real project.** Neither item below
is a coding defect in what was built; both are design problems only a real run could expose,
which is the argument for having shipped a first pass at all. Between them they close the four
items left open above.

#### A — the refinement search is the wrong *shape*, not too small

Observed live. Probing `spring-boot-starter-web 2.1.0.RELEASE` for a clean `tomcat-embed-core`,
the minor-tier probe resolved `[2.1.0,3.0.0)` to **2.7.18**, still affected — which proves *no
2.x release works at all* — and the refinement search then spent all eight of its probes on
2.1.1 … 2.1.8, inside the very line that result had just ruled out. It reported 4.1.0, a
three-major jump, having never tried 2.2, 3.0 or 4.0.

**Raising the probe count does not fix this.** The candidate list is every known version between
the current one and the winner, sorted ascending — roughly 200 releases for Spring Boot — walked
from the bottom. Twelve probes reach 2.1.12. The shape of the list is the problem, not its budget.

- [x] **Tier probes become elimination and bracketing, not candidates.** Their results already
      carry more than "is this one clean": an affected patch tier rules out the line, and **an
      affected highest-release-in-a-major rules out the entire major**. The first pass computed
      exactly that and then discarded it.
- [x] **`[current,)` is a feasibility probe, not an upgrade candidate.** It stays because it is
      also the *metadata primer*: `knownVersions` reads the local repository, and nothing is
      there until some range probe makes Maven fetch it. **Its short-circuit was removed in
      pass C below — see the unsoundness recorded there.** Built with the short-circuit, which
      was wrong.
- [x] **Descend major → minor**, ascending, first clean wins at each level.
      **Revised during the build: every step past feasibility probes an exact version, never a
      numeric range.** `[3.0.0,4.0.0)` resolved live to **`4.0.0-RC2`** — a pre-release of the
      *next* major. Maven ranks major-version differences above qualifier differences, so any
      `4.0.0-<qualifier>` outranks every real 3.x release and wins the range, silently skipping
      major 3 rather than merely offering a milestone. Candidates now come from
      `knownVersions` (already pre-release-filtered) and are probed as `[exact]`.
- [x] **Stop at the minor line, and report its highest patch.** Deliberate, not a budget
      compromise: nobody plans an upgrade to 3.0.7 rather than 3.0.0 — they plan to move to
      Spring Boot 3.0, and the blast-radius difference within a line is nil while 3.0 against
      4.1 is the entire question. The highest patch in the winning line is also the safest choice
      within it, carrying every other fix that landed there.
- [x] **Still not a binary search, at any level.** The non-monotonicity argument stands
      unchanged: a newer release can introduce a fresh advisory against the transitive component,
      so bisecting on "is it clean" can report an earliest that is not one. What changes is only
      the size of the set scanned linearly.
- [x] **Filter pre-release versions out of candidates.** `knownVersions` excludes anything
      carrying a `-` qualifier. **A second leak was found live and needed its own guard**: a
      *resolved* version can still be a pre-release even when the candidate list is clean, via
      the range-boundary case above, so a resolved pre-release is now rejected as an answer
      regardless of what the archive says about the target.
- [x] **Raise the probe ceiling to 16, and the run budget with it.** **The run budget is the
      binding constraint, not the probe count**: the cold-repository tomcat run spent about four
      minutes on twelve probes against about one minute warm. Both are revised again in C.
- [x] **Claim only what was checked**: the note names the exact version verified and what it was
      verified against — never "provably the earliest version".

**Verified live 2026-07-29** against `vuln-multi-module.cdx.json` with a real `mvn` 3.9.16.
`tomcat-embed-core 9.0.12` via `spring-boot-starter-web 2.1.0.RELEASE`: the first pass reported
**4.1.0**, a three-major jump; the second reports **3.5.16**, having eliminated 2.1.x and all of
2.x, then walked 3.0 → 3.5 to find the earliest clean minor line in major 3. Eleven probes,
about fifty seconds warm.

#### B — route completeness, from Maven rather than from us

Also observed live, and this one is a correctness problem rather than a quality-of-answer one.

`jackson-databind@2.9.5` appears in the fixture as **one component with two parents** —
`keycloak-core` and `spring-boot-starter-json`. That is the *resolved* graph: Maven already chose
one of those declarations by nearest-wins and discarded the other, and **the SBOM does not record
which one it honoured.** So bumping the losing ancestor changes the resolved version by exactly
nothing, and a panel reporting that bump as a fix would be stating something false.

The first pass cannot see this, because it generates a POM containing only the one ancestor: it
asks what that dependency brings *in isolation*, which is not a question anyone has.

- [x] **Probe the whole owning module.** The generated POM carries all of that module's direct
      dependencies at their current versions, with only the one under test moved to the candidate
      version. `dependency:tree` then reports what the component *actually resolves to for that
      module*, with nearest-wins, `dependencyManagement` and every competing route applied — by
      Maven, which is the authority on its own resolution rules, rather than by us approximating
      them.
- [x] **The inputs are already held.** `DependencyGraphService.directDependencies` reads the
      stored edges for the owning module's bom-ref and keeps the `DIRECT`-scoped children; no new
      data, no new table.
- [x] **Calibration becomes a whole-tree comparison** rather than a single chain: resolve the
      module's current direct set with nothing overridden and check the component against what the
      SBOM reports. That tests whether the isolated model reproduces their build, a far stronger
      claim than reproducing one path through it.
- [x] **Test combinations, and report the smallest set that works.** Each declaring ancestor
      alone first, then all of them together. Where several routes are live this is the real
      answer to "one suggestion for multiple routes": sometimes there is not one, and *"you have
      to move all of these together"* is an actionable output rather than a failure.
- [ ] **When no combination resolves it, the pin is provably correct.** `dependencyManagement`
      constrains the component at any depth regardless of which declaration would otherwise win,
      so it is route-complete by construction. That is the argument this phase has asserted since
      it was written and has never been able to demonstrate. **Still not stated in the panel** —
      the failure note says no combination resolves it, without drawing the conclusion.
- [ ] **Offline route counts become the filter; the probe becomes the decision.** An uncapped
      "how many routes reach this component, and how many pass through ancestor X" query in
      `DependencyGraphService` supplies a *necessary* condition cheaply — a bump that misses
      routes cannot be complete, so it need not be probed at all — while the probe supplies the
      *sufficient* one. This is also what the "routes fixed of routes total" figure needs, and it
      must be uncapped: the display caps routes at three per module and reports a floor past
      twenty-five, so counting against the shown routes would undercount silently.
- [ ] **Which module the answer holds for has to be stated.** A component owned by several
      modules may need a different remedy in each, because their direct sets differ. Built as
      *probe the most-affected module only* — `ComponentGraph.reachedFrom()` is already ordered
      by route count, so its first entry is used and the others are not probed. **The remedy does
      not yet say which module it was verified against**, which is the honesty half of this item
      and is still open. **Open**: whether to probe every owning module eagerly — it multiplies
      cost by the module count.

Cost per candidate is unchanged: a larger generated POM, the same number of `dependency:tree`
invocations.

**Verified live 2026-07-29.** `jackson-databind@2.9.5`, reached through both `keycloak-core` and
`spring-boot-starter-web`: bumping `spring-boot-starter-web` to its latest leaves jackson at
**2.9.5, entirely unchanged**, because Keycloak's declaration is the one Maven honours. The
single-dependency probe of the first pass would have shown jackson moving in isolation and
reported a fix the real module does not get — exactly the false statement this pass exists to
prevent.

**Order.** A first — self-contained, changes only the search, needs no new inputs. B second, as
its own pass, because it changes POM generation, calibration and the remedy model together.
**Both built 2026-07-29**; C below follows from what building them exposed.

#### C — ranked candidates per major line, and the unsoundness A left behind

**Planned 2026-07-30.** Two things drive this, and the first is a defect in A rather than an
enhancement.

**The feasibility probe must not short-circuit.** A treats "`[current,)` came back affected" as
*no version of this ancestor fixes it* and stops. That is the same non-monotonicity trap this
design keeps invoking against binary search: **the global latest being affected does not mean no
version is clean**, because a newer release can regress where an intermediate one was fine. The
fixture hits it — `keycloak-core [4.8.3.Final,)` resolved to 26.7.0 bringing jackson 2.21.2,
still affected, and the search stopped there without probing a single intermediate Keycloak. The
"no combination resolves this cleanly" verdict recorded above is, on that point, **unproven
rather than wrong**, and must not be read as evidence.

**And one verdict is the wrong output shape anyway.** Tier 1 already presents *candidates, not a
recommendation*, each carrying its own advisories — Tier 2 collapsing to a single winner was the
odd one out, and it discards work it already did: every tier probe knows what its version still
carries, and A threw that away the moment it was not perfectly clean.

**The grouping is one row per major line**, every major from the current one up to the latest.

| Row | Reports |
|---|---|
| Stay on 2.x | earliest clean in major 2 — or "highest is 2.7.18, still carries …" |
| Move to 3.x | earliest clean in major 3 → 3.5.16 |
| Move to 4.x (latest) | earliest clean in major 4 |

- [x] **One candidate per major, enumerated from `knownVersions` — never a "next major"
      shorthand.** Picking "the next major" is the same arbitrary-boundary mistake as
      `[3.0.0,4.0.0)`: at 1.x with latest 5.x it names 2.x and silently skips 3 and 4.
- [x] **Major is the axis blast radius varies along**, which is why rows split there. Spring Boot
      2 → 3 is the Jakarta namespace migration; 3.0 → 3.5 is a weekend.
- [x] **The patch tier disappears as a concept.** The current-major row *is* the patch or minor
      answer whenever the fix is nearby — if 2.1.18 were clean, "Stay on 2.x → 2.1.18". One
      fewer concept and a more accurate one.
- [x] **Every row carries what it still carries**, as advisories with their GHSA ratings and
      **not a count** — the existing rule that *"clears 3 of 4" cannot be acted on; which one
      remains decides*. A row is additionally marked when it clears every critical and high,
      since that is the bar an upgrade is usually judged against. **Revised 2026-07-30, later the
      same day, on live user feedback**: the inline list grew unusably long for a heavily-carried
      component (65 advisories on one row). `AdvisorySummary` now leads with a **count by
      severity band**, CVE-linked and clickable, with the full list behind a details toggle — the
      "not a count" rule survives as "never *only* a count", not as "never a count at all".
- [x] **This subsumes the partial-fix idea** raised the same day: a row whose highest release
      still carries two criticals against a baseline of twelve is visible and comparable without
      any separate "best candidate so far" mechanism.
- [x] **The feasibility probe keeps its other two jobs and loses the short-circuit.** It is the
      metadata primer — `knownVersions` reads the local repository and nothing is there until a
      range probe makes Maven fetch it — and it establishes the upper bound. Its verdict becomes
      one data point among the rows.
- [x] **Nearest-major-first, on one shared budget.** Ranking wants ascending majors anyway, so
      budget exhaustion lands on the far majors — precisely where precision matters least. No
      special-casing needed. Unprobed majors are reported as **not probed**, never as "no fix".
- [x] **Budgets: 20 probes, 8 minutes**, as the shipped defaults (`MavenToolSettings.DEFAULT_MAX_PROBES`
      / `DEFAULT_RUN_BUDGET_MINUTES`). **Made user-configurable 2026-07-30**, later the same day,
      per the "the run budget is the only sound lever" decision below — the UX judgement this
      bullet flagged did not need resolving centrally once the user can set it themselves, with a
      link from the Bump section straight to Settings.
- [x] **Scope: ranked candidates for the single-ancestor search only.** Combination testing stays
      the one coarse fallback probe it is now; ranking combinations as well is a combinatorial
      step up not worth taking in the same pass.
- [x] **`BumpProgress` gains `List<BumpCandidate>`** — `(label, major, version, targetVersion,
      clean, stillCarries, snippet)` — while `remedy` stays for the failure and unavailable
      paths, so none of the failure-classification work is disturbed. The panel renders the rows
      as a table, closer to how `advice.advisories` already renders than to a `RemedyCard`.
- [x] **No suggestion is emitted.** A bump cannot be *suggested* until route completeness exists,
      which is still open under B.

**Built and verified live 2026-07-30.** `jackson-databind@2.9.5` (via `keycloak-core`) ranked one
row per major from 4 through 23, each carrying its own still-affected advisories; the
`feasibilityBeingAffectedDoesNotStopTheSearchOfIntermediateMajors` regression test pins the
non-monotonicity fix directly. Same day, two follow-on items landed in the same area and are
recorded under their own dates below rather than folded in here: the probe budget became
user-configurable, and `BumpProgress` gained a `QUEUED` state distinct from `RUNNING` once the
single background thread's serialisation became something a reader could actually observe.

#### D — say which library is being bumped, and which declaration decides — **built 2026-07-30**

**Designed and built 2026-07-30**, from three observations after using pass C. None is a coding defect;
all three are the panel failing to say what it knows or is assuming.

**The diamond question exists at two levels, and the panel is silent on both.**

| Level | Question | Before this pass |
|---|---|---|
| Across **modules** | `module-a` and `module-b` both pull this in — which is this answer for? | Probes the most-affected module only, never says so |
| Within **one module** | `keycloak-core` and `spring-boot-starter-web` both pull it in — which are we bumping? | Ranks `ancestorNodes.getFirst()`, never names it, never mentions the others |

At the second level the choice was not merely unstated, it was **made by the wrong criterion**.
`distinctAncestorsInPrimaryModule` takes the ancestor on the shortest SBOM route; Maven picks by
depth in the *resolved* tree. Those usually agree and are not the same thing — and pass B already
established what follows when they differ: bumping the declaration Maven did not honour changes
the resolved version by nothing at all, so the reader sees *"Move to 26.x → jackson still 2.9.5 →
still affected"* with no way to tell that this is Keycloak's declaration losing rather than
Keycloak failing to ship a fix.

- [x] **Status carries the worst remaining severity**, not a binary. `Critical` / `High` /
      `Moderate` / `Low` replaces `still critical/high` versus `clears critical/high` — strictly
      more information *and* one fewer concept, since "Moderate" already says critical and high
      were cleared. **Stated plainly, without a "still" prefix** (revised on review, same day):
      the column is headed Status and the row is a candidate, so the word added nothing but
      hedging. Derived in the frontend from
      the same `stillCarries` array `AdvisorySummary` renders beside it, so the chip and the list
      cannot disagree. **An unrated remaining advisory renders as `still carries (unrated)`, never
      as clean** — the `NONE`-versus-`CLEAN` rule, one more level down.
      `BumpCandidate.clearsCriticalAndHigh` stays in the model; it stops being a badge.
- [x] **Name the ancestor being bumped.** Every row of one run shares it, so it belongs in a
      caption above the table rather than a repeated column: *"Bumping `org.keycloak:keycloak-core`,
      currently 4.8.3.Final"*. The **Version** column header becomes **Bump to**, which then reads
      as a sentence with the caption. Today the panel shows a version with no indication of what
      it is a version *of*.
- [x] **Read the deciding ancestor out of the tree already on disk.** `dependency:tree` is run
      with `-DoutputType=text` into `tree.txt`, and `findVersion` scans it line by line —
      **discarding the indentation, which is exactly the parent chain**. Parsing depth instead
      names the direct dependency the target actually hangs under, authoritatively, at **zero
      extra Maven invocations**. Rank that ancestor rather than the shortest-route one.
- [x] **List the other declaring ancestors with the reason they are not ranked**: *"`spring-boot-starter-web`
      also pulls this in, but Maven resolves it through `keycloak-core` (nearest wins), so bumping
      `spring-boot-starter-web` alone would not move it."* The single most useful sentence this
      panel could add, and it is currently absent. **Decided 2026-07-30: rank the decider only.**
      Ranking every ancestor splits a fixed budget N ways, so with three ancestors each ranking is
      budget-truncated — the exact failure `higherReleasesUnchecked` exists to report — and buys
      nothing, since only one of them can change the outcome. The all-ancestors combination probe
      stays as the fallback, unchanged.
- [x] **State the module the answer holds for**: *"Verified against `module-a`. `module-b` also
      pulls this in and was not probed — its direct set differs, so its answer may too."*
      **Decided 2026-07-30: state it, do not probe it** — closing the open question carried since
      pass B. Probing every owning module multiplies the whole budget by the module count, and for
      a library present in every backend module that is several full runs to answer a question
      nobody asked; the honesty costs nothing and was the half that was actually missing.

- [x] **Two sort orders, deliberately different.** Advisory *detail* lists sort worst-first —
      the first thing wanted from such a list is its worst entry — and that is applied inside
      `AdvisorySummary`, so every list in the panel inherits it. The candidate *rows* stay
      **version ascending**, because they are a ladder from where you are to where you could go
      and reordering them by severity would destroy the one axis blast radius varies along.

**What this unblocks at no extra cost.** Two items deferred above become answerable, because both
were waiting on provenance the probe was throwing away: *"name the component in the chain that is
holding it"* (deferred as needing "comparing resolved trees across candidates for provenance,
which the first-pass probe does not retain"), and the honesty half of *"which module the answer
holds for has to be stated"*.

**Verified live 2026-07-30** against `vuln-multi-module.cdx.json` with a real `mvn`.
`jackson-databind@2.9.5` is reached through both `keycloak-core` and `spring-boot-starter-web`;
the provenance read named **`keycloak-core`** as the deciding declaration with
`decidedByMaven: true`, **independently agreeing with what pass B established by probing** — that
bumping `spring-boot-starter-web` leaves jackson entirely unchanged. The panel now says so in a
sentence instead of leaving the reader to infer it from a bump that did nothing. The severity
change is equally visible: all 23 rows previously read `still critical/high` identically, and now
show `Critical` up to major 9 and `High` from 10 onward, which is real signal that the binary was
hiding.

### Logging

Not a feature of upgrade paths, but this is what made it necessary: a recommendation nobody
can check is the failure mode this project keeps designing against, and probing produces
reasoning worth showing.

- [x] **Two files** under `~/.sbomscope/logs`. `sbomscope.log` is the full verbose record in
      conventional text, rotated with a size cap, for diagnosing after the fact.
      `activity.jsonl` holds notable events only, one JSON object per line. Both rotate by
      size (`sbomscope.log`: 10 MB × 5; `activity.jsonl`: 10 MB × 3) via a custom
      `logback-spring.xml`, since Boot's own `logging.file.*` properties only ever configure
      one file. The directory is `sbomscope.logs-directory`, derived from the same
      `sbomscope.data-directory` property `SbomFileStore` uses, so the existing test override
      isolates logs too rather than needing a second one
- [x] **The UI tails `activity.jsonl`.** Structured by construction, so the viewer never
      parses prose. Polled every 3s from its own top-level Log tab (moved there from Settings
      on 2026-07-30). **Keeps no cursor** — every call seeks from the file's current end, which
      is what makes it robust to rotation where a stored byte offset would not be — but reads
      only a bounded window off the end rather than the whole file. The original "re-read it
      all, it is size-capped" reasoning did not survive contact with the cap: 10 MB read and
      parsed twenty times a minute to return 200 rows is a cost with nothing on the other side
      of it. Corrected 2026-07-30
- [x] Notable = anything touching the network, anything running an external process, anything
      changing stored data, and every probe result with its verdict. Network, process and data
      covered (OSV database download/index, osv-scanner invocations, SBOM upload/delete, purge,
      settings changes); Maven probe verdicts covered too, one `activity.jsonl` line per
      `mvn dependency:tree` invocation, verified live against a real probe run
- [x] The log directory shown in Settings as copyable text, not a link: a browser cannot open
      a native folder from an `http://` page — **and**, per B6, an "Open folder" button that
      drives `java.awt.Desktop` from the backend, hidden (not shown-and-failing) when
      unsupported
  - [ ] Real version lists per component, cached per purl with a last-fetched timestamp
  - [ ] The four candidates above, properly
  - [ ] Whether a newer declaring ancestor ships the fix — the one remedy that cannot be
        computed offline at all
  - [ ] **A configurable base URL per ecosystem, defaulting to the public registry.** The
        organisations this product is for do not let a developer machine reach Maven Central
        directly; they run a Nexus or Artifactory mirror, and that mirror already holds the
        metadata this needs. Pointing at it makes the feature work *without leaving the
        network at all* — which turns the disclosure objection off entirely and is likely
        the difference between this tier being usable in a locked-down environment and being
        switched off there permanently. Canonical metadata paths, not search APIs:
        `maven-metadata.xml` and the npm packument, both of which a mirror proxies verbatim
  - [ ] Every number traceable to the source that produced it, and to when

### The recommendation

- [ ] **Route completeness — needs no build tool, and should land first.** From the Phase 7
      graph: how many routes reach this component, and how many a given remedy would fix. A
      pin fixes all of them by construction; a bump fixes only those through the dependency
      bumped. The panel already recommends a pin but never says *why* it is the complete
      answer, and that reasoning is computable offline today
- [x] One suggested remedy, alongside the alternatives — not a bare verdict. The reasoning is
      deliberately shallow: declare it and there is a version to change, do not and a pin is
      the precise answer. Anything cleverer would be guessing at a project's appetite for
      breakage, which the tool has no way to know
- [x] It states its inputs, and degrades to "not enough information" rather than guessing.
      This project has already shipped one confident wrong upgrade target and does not intend
      to ship a second
- [x] **Never recommend an exclusion without usage data.** Listed as an option with its
      caveat until Phase 9 can say the library is genuinely unreferenced
- [x] Unavailable remedies are shown dimmed with their reason rather than hidden. "You do not
      declare this dependency" is the part that explains why the obvious remedy is the wrong
      one, and a reader who cannot see the option cannot learn it
- [x] Advisories cleared and left, per remedy — left meaning "names no fix at all", which is
      a real state rather than missing data
- [ ] The rest of the metrics: version distance (patch / minor / major, as a proxy for how
      likely it is to break something) and which data source each answer rests on. Distance
      needs Tier 1b to mean anything, since without it there is only one candidate
- [ ] Populate the Recommended upgrade column in the findings table from the same source, so
      the table and the Inspector cannot disagree
- [x] Application-scoped components are excluded: they are your own modules, and there is no
      version to upgrade to

**Done when**: a transitive vulnerable library names who pulls it in, what to pin it to, and
what that leaves behind — offline. With lookups enabled it also names the versions that
exist and whether a newer parent would do the job.

## Phase 9 — Workspace usage detection

Goal: is this vulnerable library actually used in my source?

Deliberately last of the three. It is the only panel needing an input the user may not have
given us, the only one whose correctness rests on a heuristic (R2), and the one whose answer
is advisory rather than decisive — a library you do not import today can still be reachable
tomorrow. Valuable, but not what the screen stands or falls on.

- [ ] Attach an optional workspace path to an SBOM (validate it exists and is readable)
- [ ] Map a component to the source-level identifiers it would appear as — Java package
      names for Maven coordinates, module specifiers for npm packages. **This mapping is
      the crux of the feature and needs design work; see R2.**
- [ ] Source scanning honouring ignore rules (`.gitignore`, `node_modules`, `target`,
      `build`, `dist`)
- [ ] Per-component result: total hit count + affected files with fully-qualified paths
- [ ] **A results surface, not a file browser.** Every match in the workspace listed
      together and grouped by file, each hit rendered in place with the lines around it
      (±5) and language-aware syntax highlighting, so the whole result can be read top to
      bottom without opening anything. Selecting a hit expands its context; the
      fully-qualified path stays visible and copyable, since the next step is usually to
      open it in an editor
- [ ] Feed usage status back into the vulnerability table's Workspace usage column
      (Used / Not found / Not analyzed)
- [ ] Scan performance on a large repository — keep the UI responsive, allow cancelling

**Done when**: pointing at a real repository correctly distinguishes a library that is
imported in source from one that is only present transitively.

## Phase 10 — Packaging

- [ ] Single-artifact build (backend + frontend bundled)
- [ ] Documented first-run setup: where to put the osv-scanner binary and the OSV database
- [ ] Documented offline workflow: how to populate caches on a connected machine and
      move them to a restricted one
- [ ] Sample SBOMs and a quickstart

## Phase 11 — VEX

Goal: a finding can carry **someone's assertion that it does not apply**, from a document
rather than from a text box.

Raised 2026-07-30. Scheduled after Phase 3 and after B2, for reasons given under *Order*
below. Nothing here is started.

### What VEX is, and the one fact that shapes the whole phase

VEX (Vulnerability Exploitability eXchange) is a statement about **one product** and **one
vulnerability**, carrying a status — `not_affected`, `affected`, `fixed` or
`under_investigation` — and, for `not_affected`, a justification from a closed set:
`component_not_present`, `vulnerable_code_not_present`, `vulnerable_code_not_in_execute_path`,
`vulnerable_code_cannot_be_controlled_by_adversary`, `inline_mitigations_already_exist`.

Three encodings, all live: **CSAF 2.0 VEX** (OASIS, what vendors publish), **OpenVEX**
(OpenSSF, minimal JSON-LD, what tools emit), and **CycloneDX VEX** (alongside or inside a BOM).
Read all three, emit none in the first pass.

**The fact that decides everything below: there is no OSV-shaped universal VEX archive, and
there structurally cannot be one.** OSV can be downloaded whole because an advisory is a fact
about a *package* — true for everyone who has it. A VEX statement is a supplier's assertion
about *their own build*: "our appliance ships log4j 2.14, but the vulnerable path is not
reachable in it". Upstream open-source projects almost never publish VEX about themselves, so
for an ordinary Maven or npm dependency tree there is nothing to fetch. Anyone offering "all
the VEX data" is offering a vendor's product catalogue, which is a different thing.

So the phase splits in two, and **the smaller half is the more valuable one**.

### Tier A — consume a VEX the user was handed

Needs no feed, no network, and no new policy. A VEX document arrives the way an SBOM does:
somebody produced it and gave it to you — a supplier shipping software, or your own security
team recording a triage decision once so it is not re-made every month.

- [ ] Attach one or more VEX documents to an SBOM, uploaded exactly as the SBOM is
- [ ] Parse CSAF VEX, OpenVEX and CycloneDX VEX into one internal statement shape:
      (vulnerability id, product identity, status, justification, statement author, timestamp)
- [ ] Match a statement to findings by **purl first**, falling back to the same
      `PackageKey`-style normalisation the report parser already needs. A statement that
      matches nothing is reported, never dropped — the count of unmatched statements is exactly
      the kind of silent loss recorded under *Optional enhancements* for scanner results
- [ ] Findings carry their statement in the view, the Inspector and the export
- [ ] Filter by VEX status, defaulting to showing everything

**This does not breach constraint 6, and the reason is worth stating because it looks like it
does.** Constraint 6 forbids *manual judgment fields* — a comment box, a "mitigated?" tick —
because those need an annotation store and make SBOMscope the system of record for opinions it
cannot check. Reading a VEX document is the opposite: it is a standard-format artefact from a
real source, carrying its own author and timestamp, no different in kind from an OSV advisory.
The boundary is sharp and must stay so: **SBOMscope reads VEX; it never offers a UI for
authoring one.** The moment a user can type a justification into our screen, constraint 6 has
been broken and the argument above stops being available.

### Tier B — Red Hat's CSAF VEX as a real feed

The one bulk corpus that earns its place, because it answers a question OSV structurally
cannot.

Red Hat publishes CSAF VEX for every CVE touching their portfolio, as individual documents
plus a **weekly bulk archive with a published checksum and signature** — one fixed URL, no
credentials, downloaded whole. That is constraint 1 category 2 exactly, the same shape as
`all.zip`, and it can be carried across on a USB stick.

**Why this one and not a general "VEX feed" setting.** It lands directly on **B2**. Red Hat's
Maven rebuilds are the `a.b.c.d` vendor-patched versions carrying
`?repository_url=https://maven.repository.redhat.com/...` — the ones whose registry links B2 is
fixing. For an SBOM containing those, OSV is describing the *upstream* artifact and Red Hat's
VEX is the authority on **their rebuild**, which is the artifact actually installed. That is a
real gap closed, not a second opinion.

- [ ] Download and index the archive, per the OSV archive's own pattern: explicit user action,
      exact URL shown, `.partial` then atomic move, identity by size and modification time
- [ ] Verify the published checksum. The OSV archive is unsigned and we accept that; this one
      is signed, so declining to check would be a choice rather than a limitation
- [ ] Match by Red Hat's own product identifiers and by purl where the document carries one
- [ ] **Measure before committing**: archive size, parse time, retained memory and the disk cost
      of the index — the four numbers taken for OSV under *Index cost for the local matcher*.
      This plan does not carry unmeasured numbers, and the npm index is already an open item for
      exactly that reason

### Suppression discipline — the part that decides whether this is safe

VEX **hides findings**. A security tool that conceals something because a document said so
needs the same rules this project applies everywhere else:

- [ ] **Never delete, only mark.** A suppressed finding stays in the database and stays
      exportable. The default view may hide it; nothing may lose it
- [ ] **Always show the count.** *"12 findings suppressed by VEX"* is visible wherever the
      suppression applies, and one click shows them
- [ ] **Always name the author.** `not_affected` / `vulnerable_code_not_present` is a claim with
      somebody's name on it, not a fact. The statement's source document and timestamp travel
      with it into the view and the export
- [ ] **Staleness is visible.** A statement made against version 2.14 says nothing about 2.17.
      Same reasoning as the version-list cache in R4: the absence of a safe default
- [ ] **Never suppress silently on import.** Attaching a VEX changes what a security tool shows
      and is therefore a deliberate act, like every other one here

**Done when**: a finding a supplier has declared `not_affected` shows that status, its
justification and its author, is filterable and exportable, and is never quietly absent.

### Order, and what would change it

Below Phase 3 and below B2. Phase 3 (KEV, EPSS) sharpens *every* finding; VEX sharpens the
subset somebody has written a document about. B2 comes first because Tier B's value rests on
vendor-patched artifacts being handled properly, which is B2's job. Tier A can move up on its
own the moment a real VEX document turns up to test against — it needs nothing from the rest.

---

## From using it — 2026-07-29

A day of real use. Kept together rather than distributed into phases, because several are
small and the list is more useful as a list.

Each item below is specified to be picked up cold. Where a design decision was needed it has
been taken and the reasoning recorded; **one item is deliberately left open and marked**.

### B0 — Scanning becomes automatic

Decided 2026-07-29 along with the rewording of constraint 2. Fetching stays on request;
analysing does not need asking, because it sends nothing anywhere.

- **On upload.** After `importSbom` succeeds, queue a scan for that SBOM. Asynchronous on a
  single-threaded executor — the upload response should not wait on an external process — with
  the SBOM ids currently in flight exposed so the sidebar can show the card as scanning and
  refresh its counts when it finishes.
- **At startup.** On `ApplicationReadyEvent`, **not** `@PostConstruct`: the application must
  be serving before this begins, or the cost lands on launch, which was the objection to doing
  it at all. Queue every SBOM that has at least one component with no `vulnerability_scan`
  row. One at a time, on the same executor.
- **Gated on readiness**, per SBOM, using the existing `ScanService.readiness`. Scanner off,
  binary missing or archive absent means do nothing — silently. It is not an error that a
  machine without a scanner did not scan.
- **Logged**, every run, because it starts an external process. That is what the activity log
  is for.
- **The manual re-scan stays.** Filling a gap and deliberately re-running analysis against a
  refreshed archive are different needs, and only the first is automatic.

### B1 — Component selection is global, should be per SBOM, and should be session-persistent tabs — **built 2026-07-30**

Merged 2026-07-30 from two items that turned out to be the same underlying gap approached from
different angles: component selection does not survive navigation the way it should. Originally
two problems —

1. Switching to an SBOM that does not contain the selected component renders an error. It
   should clear instead: a component that is not in this document is not a failure, it is a
   different document.
2. The inspector holds exactly one component at a time; picking another replaces it, so
   comparing two libraries — or resuming one you were reading before a detour to the Activity
   log — means re-searching every time.

— and both are solved by the same mechanism: session-scoped, per-SBOM, multi-component state
that lives above the router rather than being reconstructed from the URL alone.

**Partially built 2026-07-30, ahead of this merge.** A live bug turned out worse than problem 1
as originally described: the top-nav Component Inspector link carries no purl at all, so a trip
to the Activity log and back reset the whole panel to "No component selected", not only the
multi-SBOM case. Fixed as an immediate patch in `ComponentInspectorPage` with
`usePersistentState('inspector.lastPurl', {})` — the same localStorage-backed hook already used
for the tab selector — restoring the last purl per SBOM whenever the page is reached with no
purl in the URL. This patch is superseded by the design below, not layered under it: the tab
list becomes the thing that remembers "what was I looking at", and the single-purl map is
removed once it exists. Two gaps the patch left, both closed by the design below rather than
patched separately: it is localStorage-persisted where this item calls for session-only state,
so it outlives a restart it should not; and the SBOM-switch case — a *stale* purl still present
in the URL after switching to an SBOM that does not contain it — still 404s and shows the raw
error rather than clearing quietly.

**The design — browser-style tabs**, session-scoped, not a preference: does not need to survive
an application restart. In-memory state above the router (so it survives route navigation,
which is the actual bug every version of this item was chasing) is sufficient, and simpler than
anything backed by localStorage.

- **State shape**: `Map<sbomId, string[]>` in `SbomProvider` — an ordered list of open purls per
  SBOM — plus which one is active. Scoped per SBOM because a tab strip for a component that is
  not in the current document is meaningless: switching SBOMs shows that SBOM's own open tabs,
  empty for one never visited this session, which is problem 1 solved as a side effect of the
  data shape rather than a special case.
- **The URL still names the active tab.** `?purl=` stays the source of truth for what is
  currently shown — a refresh must keep working, and the per-row "Inspect" links elsewhere in
  the app must keep working as plain links. Opening a purl not already in the list appends it
  and makes it active; opening one already there just activates it. Opening a purl the current
  SBOM does not contain clears quietly and shows the finder, per problem 1's original spec —
  never the raw 404.
- **UI**: a tab strip between the finder and the identity panel, each tab a short label (the
  artifact name, not the full coordinates — the identity panel below already carries the full
  purl) with its own close control. Closing the active tab activates its neighbour; closing the
  last tab returns to the current "no component selected" placeholder.
- **Only the active tab's panel is mounted.** Advisories, the dependency graph and the bump
  probe are already fetched per (sbomId, purl) and the bump probe already survives being
  un-mounted and re-mounted (today's fix, and the QUEUED/RUNNING work beside it) — a probe
  started on one tab keeps running server-side while another tab is active, and hydrates
  correctly when its tab is switched back to. Rendering every open tab's content simultaneously
  is not needed and would multiply the polling for no benefit.
- **Interacts directly with the queued-probe work built the same day.** With several tabs open,
  starting a bump probe on more than one is a realistic thing to do in one sitting, not a
  hypothetical — this is the scenario QUEUED exists to describe honestly.
- Not in scope here: reordering tabs by drag, or restoring tabs after a full reload — left for
  a later pass if the plain version proves not to be enough. **A maximum tab count was also
  listed here and was brought in the same day** — see *Crowding* below.

**Crowding — added 2026-07-30**, on the question of what happens with too many tabs open.

The performance half of that worry does not apply: only the active tab's panel is mounted, so
ten tabs are ten list items and nothing else. Navigation and vertical space are the real costs,
and the established answers are the ones IDEs and browsers already converged on.

- [x] **One row that never wraps.** Wrapping was the first shape and it was wrong: a second and
      third row of tabs takes height from the panel, which is the same argument that moved the
      identity block out of this column. Tabs shrink to a 118px floor and then the strip
      scrolls, as every browser does. Measured: constant 44px whether one tab is open or ten.
- [x] **A cap of ten, evicting the least recently *active*** — IntelliJ's tab limit and VS
      Code's `workbench.editor.limit`, at their usual default. Least recently active rather
      than oldest-opened, or the tab you have been returning to all session is the one that
      goes. Display order stays the order things were opened in.
- [x] **Eviction is silent, and that is defensible here specifically.** A tab holds no state:
      advisories and the graph are re-fetched per (sbom, purl), and a probe's progress lives on
      the backend keyed by module and target, so closing a tab neither stops a probe nor
      discards its result. A dropped tab costs two keystrokes in the finder. That is why this
      does not get the "report it, never disguise it" treatment budget exhaustion gets — there,
      something genuinely was not done.
- [x] **The active tab is always revealed**, since activation arrives from four places that are
      not a click on the tab itself: a row's Inspect link, a close activating its neighbour,
      the restore after a route change, and opening a component that is not yet a tab.
- [ ] Revisit only if ten proves wrong in use. A user-configurable limit is deliberately not
      offered — the probe budget earned that because it trades completeness for cost, and this
      trades nothing.

**Built and verified live 2026-07-30**, against both fixtures in one session. `SbomProvider`
holds `Record<sbomId, {open, active}>` in plain `useState`; `ComponentInspectorPage` renders
the strip and the superseded `inspector.lastPurl` map is gone, its localStorage key removed on
mount so it does not sit orphaned in browsers that ran that build. Verified in the browser
rather than asserted:

| Behaviour | Result |
|---|---|
| Top-nav round trip (Inspector → Activity log → Inspector) | three tabs intact, active one restored into the URL |
| Switch to an SBOM not containing the URL's purl | purl dropped, finder shown, **no 404 rendered** |
| Two SBOMs, two tabs each | fully independent lists *and* active tabs, in both directions, over two round trips |
| Close active tab with a right neighbour | neighbour activated, URL follows |
| Close an inactive tab | URL and active tab untouched |
| Close the last tab | placeholder returns, purl cleared |
| Per-row "Inspect" link from the vulnerability view | still a plain link; appends a tab and activates it |
| Probe started on one tab, another tab active | kept running server-side, hydrated with its accumulated verdicts on return |
| Full page reload | tabs gone by design, the URL's purl reopens as one tab, no error |

Two things the item did not anticipate, both settled during the build:

- **The label needs the version.** "the artifact name, not the full coordinates" is right
  about the group and wrong about the version: `vuln-multi-module.cdx.json` carries
  `jackson-databind`, `keycloak-core` and `netty-all` each at two versions, and opening two of
  them produced two tabs reading `jackson-databind` with nothing to tell them apart. Found by
  a verification step picking the wrong tab. The version now follows the name, muted and
  monospaced, exactly as the finder already renders it.
- **The strip is in the main column**, not beside the finder. B1 said "between the finder and
  the identity panel", which assumed a side column ordered finder-then-identity; the shipped
  order is the reverse, deliberately. A 280px column cannot hold browser-style tabs anyway.
  In the main column the strip aligns with the top of the identity block (measured: both at
  y=155) and sits directly above the content it switches.

### B1a — Monitoring: the running queue, and stopping it — **built 2026-07-30**

Raised straight after B1, and by it: a probe outlives the tab it was started from, so closing
that tab — or having the ten-tab cap evict it — left a real `mvn` running with no way to reach
it. Not an orphan in the leaked sense (it is tracked, it finishes, its result is cached), but
invisible, holding the only probe thread, and unstoppable.

**The Activity Log tab becomes Monitoring, with three sub-tabs.** `/log` redirects, as
`/workspace` already precedents.

- [x] **Processes** — running, queued and recently finished probes, with elapsed time and a
      Stop control. Each row opens the component it was answering for; a plain link would not
      do, because the Inspector reads the purl from the URL but the SBOM from the selection, so
      it selects the SBOM on the way.
- [x] **Activity log** — the existing `activity.jsonl` tail, unchanged.
- [x] **Full log** — a tail of `sbomscope.log`, which nothing surfaced before. The last session
      made the probe diagnosable by writing every `mvn` command and its whole output there, and
      then left the only route to it an "Open folder" button — no route at all on a machine
      where the browser and the file manager are not both to hand.
- [x] **Stopping kills the process tree, not the wrapper.** The pre-existing timeout watchdog
      destroyed only the direct child; on Windows that is `mvn.cmd` and the real Maven JVM is
      its grandchild. Fixed at every kill site, since implementing Stop on top of it would have
      manufactured exactly the orphan this item is about.
- [x] **Finished runs stay listed for the session**, bounded at 25.
- [ ] **Persistence across a restart** — deliberately deferred (see the backlog). Nothing here
      survives a restart today, consistent with probe progress itself.
- [ ] Extend the list to osv-scanner runs and OSV downloads. Both already have their own
      progress surfaces, so folding all three into one honest "what is this application doing"
      is a reconciliation job rather than an addition.

### B2 — Registry links break on vendor-patched versions

`a.b.c.d`, where `.d` is a distributor's patch level, yields a Maven Central URL that 404s.
Two independent fixes, neither of them a heuristic:

- **Honour the purl's `repository_url` qualifier.** `RegistryLinks.stripQualifiers` currently
  discards the whole query string, including the one field that names where the artifact
  actually lives. A vendor build carrying
  `?repository_url=https://maven.repository.redhat.com/...` is telling us Central is the wrong
  destination, and we are throwing that away and then linking to Central anyway. Where it is
  present, link there; where the host is unrecognised, prefer no link over a wrong one.
- **Split the two links by reliability.** The component *name* links to the artifact page
  (`/artifact/{group}/{name}`), which resolves whenever the artifact exists at all; the
  *version* cell carries the version-specific link. A reader who lands on the artifact page
  can find their version; a reader who lands on a 404 cannot.

**Validating links is not an option.** Testing whether a URL resolves means asking a registry
about a specific artifact, which constraint 1 puts in category 3 — and an external 404 renders
the registry's page, not ours, so there is no error of ours to make friendly. The only
available move is choosing targets that do not fail.

### B3 — The "system" theme appears inert

The mechanism is correct: `ThemeProvider` reads `prefers-color-scheme` and tracks changes
live. With a dark OS, "System" and "Dark" are visually identical, so it reads as doing
nothing. **Label it with what it resolved to** — *System (currently dark)* — updating as the
OS changes. No mechanism change.

### B4 — Multi-file upload

Accept multiple files on the dropzone and the file input. Import sequentially, and report
**per file**: a partial failure must be visible, since one malformed document among five is
the normal case and a single "upload failed" would hide the four that worked. Select the last
successful import, as a single upload already does.

### B5 — Download the stored SBOM

`GET /api/sboms/{id}/document`, serving the stored bytes with the original filename in
`Content-Disposition`. The stored document is the one the scanner reads, so it is also the one
worth handing to somebody else. 404 where the file has been swept.

### B6 — Reaching the log directory — **built 2026-07-29**

Logs live under `~/.sbomscope/logs`. Show the absolute path as copyable text **and** offer a
button that opens the folder in the OS file manager — possible only because the backend runs
on the user's own machine, which is the same property that makes workspace scanning possible.
Use `java.awt.Desktop` where supported and fall back silently to the copyable path when
headless; a button that does nothing is worse than one that is absent.

Built as `LogService`/`LogController` (`GET /api/logs/status`, `POST /api/logs/open-folder`)
and `LoggingPanel.tsx`. `canOpenFolder` is reported once from the backend
(`Desktop.isDesktopSupported() && isSupported(Action.OPEN)`) and the button is omitted
entirely rather than shown disabled — matches the "fall back silently" instruction. Observed
`false` when launched as a backgrounded process from this shell during verification; expected
to report `true` under a normal interactive launch, worth confirming on your machine.

### B7 — Dependency graph rendering

- Vertical space between routes; they currently run together.
- **Drop the repeated root from every line.** The module heading already names it, so
  repeating it as step 1 of each route spends the widest column on the word the reader
  already read.
- Subtly emphasise the **direct dependency** on each route — the step whose version they can
  actually change. Weight or a quiet underline, not colour: colour already means severity here.

### B8 — Sort by the "fixed in" version

The only item with a real obstacle. Sorting, filtering and paging execute in SQL so the view
and the export cannot diverge, and H2 orders `1.10.0` before `1.9.0` lexically.

- Add `fixed_version_sort` to `vulnerability_finding` (**V3**, additive), written at insert
  time in `recordScan`, null when there is no fix.
- **Generate the key from `VersionOrder`'s own rules, not a second interpretation of
  versions.** Zero-pad numeric segments to a fixed width and encode pre-release suffixes so
  they sort below their release. A test must assert that ordering by the key agrees with
  `VersionOrder.compare` across the fixture set — otherwise the table and the comparator
  disagree, which is exactly the class of quiet inconsistency this project keeps designing
  against.
- `FindingQuery.SortField` gains `FIXED_VERSION`, ascending and descending, with nulls last
  in both directions: "no fix" is not a version and must not sort as one.

### B9 — Filter and sort by dependency scope

`FindingQuery` gains a scope set, defaulting to all three. The SQL clause is a plain
`dependency_scope IN (…)` built from enum constants, as the severity clause already is.
Sorting reuses the `CASE` ordering in `findComponents` (APPLICATION, DIRECT, TRANSITIVE).

**Put the filter in the view-options menu, not the toolbar.** The toolbar already wraps at
1024px with the severity chips alone, and there is a recorded decision that moving density and
columns behind one menu is what stopped it reading as a pile of unrelated widgets. A second
chip row would undo that.

### B10 — Secondary sort

`FindingQuery` gains an optional second criterion, appended to the `ORDER BY` and carried into
the export description like the first. **Shift-click a second column header** — the
established pattern, and it costs no toolbar chrome at all, which is the constraint. Show it
as a small superscript rank on the two active headers so the state is visible rather than
folklore.

### B11 — Folder and tool pickers — **the open decision**

A browser cannot return an absolute filesystem path, so a picker must come from the backend.
Two viable shapes, and **this one is not decided**:

- **A backend-rendered directory browser.** Reliable, works headless, no native dependency.
  It is a filesystem browser exposed over localhost, which is worth stating plainly even
  though the process already reads and writes that filesystem on request.
- **A native dialog** via `JFileChooser`. Feels better when it works; fails headless and can
  open behind the browser window, which is a bad failure because it looks like a hang.

File *upload* is unaffected — that is an ordinary file input.

### B12 — Purge gaps

Erasing the OSV archives should also erase `osv_index` and `osv_index_source`: an index
without its archive is derived data pointing at nothing. **Bind it to the existing archive
target rather than adding a fourth checkbox** — four targets were chosen because they differ
by orders of magnitude in what they cost to undo, and an index is rebuilt by pressing one
button. Also purge the probe repository and, separately, the logs.

### B13 — Application icon

"Scope" is in the name, and both obvious glyphs are taken by navigation: the shield is
Vulnerabilities, the cube is the Component Inspector. **A magnifier whose lens contains a
small cube** reads as "examine a package", is neither existing icon, and survives 16px if the
cube stays two or three strokes. Needed as a favicon and in the top-left brand slot, which is
currently a bare wordmark.

### Backlog

- [ ] **Diff two SBOMs, or trend several.** This reopens a closed question: the decision log
      dropped "group SBOMs into projects" and named trend analysis as what would bring it
      back. It has. A data-model question before it is a screen — findings are keyed by purl
      and shared across SBOMs, so "how did this project change" needs a notion of *this
      project* that does not currently exist
- [ ] **Persist the probe history across restarts.** Monitoring's Processes tab keeps finished
      runs for the session only, matching probe progress itself, which is deliberately
      session-scoped so a restart re-validates against whatever Maven configuration is current.
      Persisting the *history* is a different claim from persisting the *results* and could be
      done without disturbing that — a small table of (component, module, outcome, timings). Not
      needed yet; raised 2026-07-30 when the history was added
- [ ] More themes, including a high-contrast one for visually impaired readers. `tokens.css`
      already holds every colour in one place, which is what makes this cheap
- **VEX** was raised here on 2026-07-30 and promoted straight to [Phase 11](#phase-11--vex)
      rather than left as a backlog line: the interesting part is not "support VEX" but the
      constraint-6 boundary and the suppression rules, and neither fits in a bullet

---

## Risks and design gaps

Live list of things known to need resolution before or during the phase they affect.

### R1 — Guided remediation needs manifests, so it does not fit this screen

**Phase 8.** OSV-Scanner's guided remediation works against `pom.xml` and npm lockfiles,
not an SBOM. Requiring a workspace path for upgrade analysis was one option, and the
Inspector's design makes it the wrong one: **upgrade paths are the panel most likely to be
wanted for an SBOM someone was handed**, with no source tree anywhere near it. A panel that
is blank for exactly that reader is not much of a feature.

That points at option (c) of the original three — computing candidates ourselves against
the local OSV data — which turns out to be a bigger question than "which tool do we call",
so it is now **R4**. R1 stays only to record why the obvious route was not taken:

- **(a)** Require a workspace path. Rejected: it makes the most portable panel the least
  available one.
- **(b)** Upload manifests alongside the SBOM. Rejected as a *requirement* for the same
  reason, though it remains a sensible later addition — a resolved manifest would let the
  Inspector say whether a candidate version is reachable given the project's other
  constraints, which is a question SBOMs cannot answer at all.
- **(c)** Compute it ourselves. Taken, subject to R4.

### R2 — Component-to-source-identifier mapping

**Phase 9.** A Maven coordinate (`com.fasterxml.jackson.core:jackson-databind`) is not
the same as the Java package imported in source (`com.fasterxml.jackson.databind`), and
npm package names don't always match their import specifiers either. Naive matching
will produce both false positives and false negatives. Needs a deliberate strategy —
possibly reading package names from the artifact itself, or a heuristic with a visible
confidence signal.

This is the reason workspace usage is scheduled last of the three panels: it is the only one
whose answer depends on a heuristic being right, and a "not used" that is wrong is a finding
quietly dismissed.

### R3 — OSV-Scanner distribution in restricted environments — **resolved**

**Phase 2.** Resolved 2026-07-27. OSV-Scanner v2.4.0 ships as a bare, portable single
executable (~55 MB per platform; Windows `.exe`, Linux and macOS binaries), with
published `SHA256SUMS` and SLSA provenance. No installer, no admin rights, no runtime
dependencies, and nothing to extract.

SBOMscope never downloads it. The user places the binary and points SBOMscope at it from
Settings. Scanning is a toggle: turned off, the application is a working SBOM inventory
and vulnerability columns report "not analysed" rather than failing. Bundling was
rejected — three platforms would add roughly 160 MB to a 26 MB artifact, and a
supply-chain tool shipping someone else's opaque executable is the wrong default.

Pin a known-good version: v2.4.0 fixed a panic in the offline matcher when checking
version ranges, and added CycloneDX 1.7 support.

### R4 — Upgrade paths need two things the current engine does not provide

**Phase 8, and the blocker for it.** Naming candidate versions and saying what each one
carries decomposes into two separate problems, and only one of them is about tooling.

**1. Enumerating the versions that exist.** OSV knows which versions an advisory *affects*.
It has no reason to know a library's release list, and does not — a version nobody filed an
advisory against is invisible to it. So "the latest patch on this line" cannot be answered
from the data SBOMscope holds. The complete source is the registry (Maven Central's
`maven-metadata.xml`, npm's packument), which is a network dependency and therefore has to
be cached deliberately under constraint 1, per component, the way findings already are.

Worth noting what that changes: it is the first cache whose *absence* has no safe default.
A stale finding is still a real finding; a stale version list silently omits the release
that fixes the problem. Staleness has to be visible on this panel, not merely recorded.

**2. Judging a version we do not have.** osv-scanner scans a document describing what is
installed. Asking "would 3.2.0 be clean?" is not a question it takes. Two ways round it:

- **Synthesise a document per candidate and run the scanner over each.** Honest, reuses the
  engine, and costs a process launch per candidate — with the fourth candidate above needing
  a walk over the whole range rather than three probes, that is not viable.
- **Evaluate the local OSV archives ourselves**: for a package and a version, which
  advisories apply. This is version-range matching against data already on disk, offline,
  with no process launch.

The second is **the built-in matching idea recorded under Open questions as decided
against** — and it is not a reversal of that decision, because it is not the same job. That
proposal was to replace osv-scanner for real scans, and the argument against it stands:
correctness risk in the reporting path, while a maintained engine does it well. This is a
strictly smaller thing — answering hypotheticals about versions the user does not have —
where osv-scanner offers nothing to be consistent with, and where being wrong misranks a
suggestion rather than misreporting an installed component. The open question closed with
"reconsider only if a concrete need appears". This is that need, and the measured facts
recorded there (explicit `versions[]` on ~90% of the Maven set, `VersionOrder` already
written and tested for the rest) are what make it tractable.

**Resolved 2026-07-29**, and the resolution is that the two halves have different answers.

**Judging a candidate is solved, offline, and is the second option above.** A local matcher
over the downloaded archives answers "which advisories apply to package P at version V" for
any V, using data already on disk. `VersionOrder` exists and is tested; ~90% of the Maven set
carries explicit `versions[]`, so most of it is string equality. This is Tier 1 and needs no
network and no policy change.

**Enumerating candidates has no good offline answer, and saying so matters more than
working around it.** OSV knows the versions an advisory *mentions*; it has no reason to know
a library's release list and does not. Deriving one from advisories yields a set biased
toward versions near known vulnerabilities — so "the latest release" computed that way could
name 2.15.1 while 2.19.0 exists, and a version nobody has filed against is invisible
entirely. **That is not a staler answer, it is a wrong one**, which is a different thing
from the staleness this project already tolerates elsewhere: a stale finding is still a real
finding, whereas a truncated version list silently omits the release that fixes the problem.

So the offline tier does not compute "latest" at all. It offers the fix versions the
advisories name — a small, honest, useful set — and says plainly that the newest release is
unknown without a registry. The complete list requires an outbound call, which is the
subject of the outbound-calls decision in the log.

Two consequences worth carrying forward:

- **Registry data is cached per purl with a last-fetched time, and staleness is visible on
  the panel** rather than merely recorded. It is the first cache whose absence has no safe
  default.
- **A version lookup discloses your dependency list to whoever answers it.** Asking Maven
  Central which versions of an internal-sounding artifact exist tells Maven Central you use
  it. For the environments SBOMscope targets that is a real cost, not a theoretical one, and
  it is the reason the opt-in is per host with the exact URL shown.

---

## Open questions

- **Built-in matching as a second engine — decided against, 2026-07-27.** SBOMscope
  relies on osv-scanner. The idea was to read the OSV `all.zip` files directly in Java
  and match purls and versions ourselves, removing the external binary; it is recorded
  here only so it is not re-proposed.

  Facts that would matter if it is ever reconsidered: the archives are the public OSV.dev
  export in OSV schema 1.7.3 (6,860 standalone advisory documents for Maven, no index or
  scanner-specific metadata), and records carry explicit `versions[]` enumerations
  alongside `ranges[].events[]`, so much of the matching would be string equality rather
  than version-range arithmetic. That was the main argument against it, and it is weaker
  than it first appeared — but correctness risk in a security tool is not the place to
  spend effort while a maintained engine does the job.

  **Revisited 2026-07-29, and now happening — for a narrower job.** Upgrade paths need to
  answer "which advisories apply to a version the user does not have", which osv-scanner does
  not take as a question at all. That is not the scanning path and replaces nothing, so the
  argument above does not reach it. Built as Phase 8 Tier 1, scoped to hypotheticals only:
  **what is installed is still reported by osv-scanner and nothing else**, and if the two
  ever disagree about a version the user actually has, the scanner is right by definition.
  Keeping that boundary sharp is what makes the narrow matcher safe.
- **Where version lists come from, and how a candidate is judged — resolved 2026-07-29.**
  See R4: judging is offline and solved, enumerating is not and needs an opt-in lookup.
- **Dependency view rendering — resolved 2026-07-29.** Paths upward, collapsible tree
  downward. See the decision log; the question was malformed as originally written, since it
  assumed one rendering had to serve both directions.
- **License — resolved 2026-07-29.** Apache-2.0. See the decision log.
- **Multi-module Maven, for the dependency graph — resolved 2026-07-29.** An upward path tops
  out at the owning module, never the parent pom. See the decision log.
- [ ] **Multi-module Maven, for workspace mapping** — still open, and Phase 9's problem: with
      one aggregate SBOM over several module directories, which source tree does a component
      get scanned against? Recommending per-module SBOMs is not an answer, since SBOMscope
      reads documents other people generated.

---

## Optional enhancements

Things worth having that nothing currently needs. Kept here rather than in a phase so the
roadmap stays a list of commitments; each moves up only when a concrete need appears.

- **NVD as a second opinion.** NVD's own CVSS scoring and canonical descriptions, alongside
  OSV's. Deliberately not used today: tracing every column to its source showed it
  contributes to none of them (see the 2026-07-27 decision). Note that redistributing NVD
  data carries attribution obligations that merely linking does not.
- **Log to a file, and show where.** SBOMscope currently logs to the console only —
  `application.yml` sets levels but no `logging.file.name`, so there is no log file to point
  at. Doing this properly means choosing a location (`~/.sbomscope/logs` alongside the rest
  of the local data), a rotation policy and a size cap, *then* surfacing it. Note the second
  half is not a link: a browser cannot open a native folder from an `http://` page, so
  Settings would show a copyable path the way it already does for the OSV archives.

  Worth doing when something needs diagnosing after the fact — a scan that failed overnight,
  or a dropped finding noticed days later. Not before.
- **Surface scanner results that could not be matched.** A finding the scanner reports but
  which cannot be tied back to a stored component is discarded with only a log warning. That
  is how a real advisory against `@angular/common` went unnoticed. The count belongs in the
  UI, since a silently dropped finding is the failure mode this project guards against
  everywhere else.

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
- 2026-07-27 — **Java 25 LTS**. Java 24 was considered and rejected: it is a non-LTS
  release that stopped receiving updates around September 2025. Shipping a security
  tool on an unpatched JDK undermines the product and fails enterprise approval, which
  is precisely the environment SBOMscope targets. Java 25 is the current LTS with
  first-class Spring Boot 4 support. **Lowered to 21 on 2026-07-28 — see below.**
- 2026-07-28 — **Java 21, lowering the baseline from 25.** The reasoning for 25 was that
  a security tool must not ship on an unpatched JDK, and that argument is untouched: 21
  is an LTS in active support, so it satisfies the same requirement. What the earlier
  decision missed is that the requirement was only half the question.

  SBOMscope's target is a locked-down machine, and the JDK on such a machine is chosen by
  somebody other than its user. Java 21 is the release that is actually approved and
  installed in those environments; 25 is months of procurement away. A build requirement
  the target environment cannot satisfy is not a security posture, it is a product that
  does not run there — and the whole premise of this project is that it runs where the
  alternatives cannot.

  **21 is a floor, not a ceiling.** `maven.compiler.release` pins the bytecode, so
  building on a newer JDK still produces an artifact that runs on 21, and the developer
  machine is free to be ahead. The cost is that nothing may use a language or library
  feature above 21 — worth checking when a new API looks convenient, because
  `--release 21` catches it at compile time rather than as a runtime failure on someone
  else's machine.

  Verified rather than assumed: Spring Boot 4.1's own classes are Java 17 bytecode, so the
  framework never needed 25, and the codebase's newest feature is `SequencedCollection`
  (`getFirst()`), which is 21. The build was run end to end on a real JDK 21.
- 2026-07-27 — **Maven multi-module build** (parent + `frontend` + `backend`). The
  frontend is built during the Maven build and packaged into the backend jar under
  `META-INF/resources`, which Spring Boot serves automatically. One command produces
  one runnable artifact. Development keeps hot reload by running the Vite dev server
  with `/api` proxied to the backend. Maven chosen over Gradle for its dominance in the
  Spring ecosystem and simpler multi-module declarations.
- 2026-07-27 — **Storage: embedded H2**. SQLite was considered and rejected on
  environment grounds: its standard JDBC driver extracts native binaries to a temp
  directory at runtime, which restricted machines (noexec temp directories, aggressive
  endpoint protection) can block. H2 is pure Java with no such failure mode.
- 2026-07-27 — **Schema migrations: Flyway**, versioned SQL under `db/migration`.
  Hibernate auto-DDL is deliberately not used. The local database holds real user data
  — uploaded SBOMs and vulnerability caches — that must survive an application upgrade,
  so schema evolution has to be explicit and reviewable rather than inferred from
  entity mappings at startup.
- 2026-07-27 — **Lean dependency tree as a standing principle**. A generated
  full-stack scaffold was evaluated and rejected. Two reasons: SBOMscope is a
  dependency-vulnerability tool, so its own SBOM is a credibility statement and every
  transitive dependency becomes a finding somebody has to triage; and the product is
  overwhelmingly bespoke analysis logic rather than entity CRUD, so generated
  scaffolding would cover a small fraction of the work while constraining the rest.
  Recorded as constraint 9 in `AGENTS.md`.
- 2026-07-27 — **Flyway is wired through `spring-boot-starter-flyway`, not
  `flyway-core`.** Spring Boot 4 splits autoconfiguration into per-integration
  modules, so `flyway-core` alone placed Flyway on the classpath without ever
  activating it: the application started cleanly, reported healthy, and silently
  applied no migrations at all. Caught by checking the startup log rather than
  trusting a green build. Recorded as a gotcha in `AGENTS.md` because the same trap
  applies to every other integration added from here on.
- 2026-07-27 — **Persistence: Spring JDBC, not Spring Data JPA.** Flyway owns the
  schema so entity-driven DDL adds nothing, and the findings views are reporting-shaped
  reads where explicit SQL beats lazy loading and its N+1 risk. Taken while no entities
  existed, so it cost nothing then and would have been expensive later. It halved the
  artifact: 53 MB to 26 MB.
- 2026-07-27 — **CycloneDX parsed with Jackson directly**, not `cyclonedx-core-java`.
  The reference library brings seven runtime dependencies including XML support, while
  SBOMscope reads two sections of one format; the fields it needs have been stable since
  spec 1.2, and ignoring unknown properties covers version differences. Phase 1 therefore
  added no new dependency at all. Revisit if writing SBOMs or schema validation is ever
  needed — that is the point where the library starts earning its weight.
- 2026-07-28 — **One integrated table, and "unscored" is not "clean".** A brief
  two-tab design (findings vs. all components, with different table shapes) was replaced
  by a single table built on a LEFT JOIN from component to finding: one row per
  component/vulnerability pair, plus one row per component with nothing against it.

  The proposal that "Unscored" should also cover components without vulnerabilities was
  rejected. Unscored means a real vulnerability whose advisory carries no CVSS score, so
  merging the two would let "we don't know how bad this is" render identically to "this
  is fine" — the same conflation the schema already avoids by writing a scan row for
  every component. Clean components got their own band instead, off by default.
- 2026-07-27 — **The NVD API is not used.** Tracing every column to its source showed it
  contributes to none of them: osv-scanner already supplies a numeric CVSS score
  (`max_severity`), OSV `aliases` resolve GHSA→CVE for 97% of Maven advisories, EPSS
  comes from FIRST.org and the exploited flag from CISA — neither is NVD. Linking to
  nvd.nist.gov needs no API, since the URL derives from the CVE ID.

  This removes the API key, the rate-limiter design, an offline NVD mirror, and the
  "reconcile conflicting severity between sources" problem, which only existed because
  there were two sources. Superseded the earlier decisions to blend NVD into matching and
  to use a single rate-limited authenticated channel.

  Kept as a possible later enhancement, not a gap: NVD's own CVSS scoring and canonical
  descriptions would be an authoritative second opinion. Add only if a concrete need
  appears — and note that redistributing NVD data carries attribution obligations that
  merely linking does not.
- 2026-07-27 — **Database downloads are gated on scanning being enabled**, with an
  explicit "Download anyway" override. With scanning off nothing in the application can
  read the archives, so offering a 200 MB download would be a dead end. The override
  exists because staging data for an air-gapped machine is legitimate — though weakly so,
  since the source URL is public and shown in the UI, and the offline machine must have
  the scanner configured anyway. The gate is therefore a usability judgement, not a
  technical constraint, and must be reconsidered if the built-in matcher is built.
- 2026-07-27 — **The build uses the machine's Node, not a downloaded one.**
  `frontend-maven-plugin` was replaced with `exec-maven-plugin` invoking npm from the
  PATH, because the former has no system-Node mode — it always installs its own copy
  into the module directory (~105 MB) and hardcodes that path. The trade is
  reproducibility for a smaller, faster build that matches how the target environment is
  provisioned; `engines` in `package.json` pins the minimum so an unsupported Node fails
  with a clear message from npm. This also removed a build plugin, per constraint 9.
- 2026-07-28 — **Tests get their own data directory.** The test configuration isolated the
  database and said so in a comment — but only the database. `SbomFileStore` still resolved
  to `${user.home}/.sbomscope`, so uploads in tests wrote into the developer's real data
  directory. Harmless while it was only stray files, and destructive the moment
  `StoredDocumentSweeper` existed: it runs on every Spring context, finds an empty in-memory
  `sbom` table, and correctly concludes that every document in that directory is an orphan.
  **Running `mvn test` deleted real uploaded SBOMs.**

  Caught during verification, when a scan failed against documents that had been there
  minutes earlier. Tests now point at `target/sbomscope-test-data`, which `mvn clean` clears.
  The general lesson is in the comment: isolating the database is not the same as isolating
  the storage, and a component that deletes files makes the difference matter.
- 2026-07-28 — **`OsvScannerException` gets its own handler.** Every scanner problem the user
  can act on — scanning switched off, no binary configured, a missing database, an uploaded
  document no longer on disk — carries a message written to tell them what to do. All of them
  were being swallowed by the catch-all advice and reported as "Something went wrong. Check
  the application log for details.", which is the exact trap the `ResponseStatusException`
  handler already exists to avoid. Mapped to 409, since each describes a state that prevents
  the request rather than a malformed one.
- 2026-07-28 — **The fix version is chosen by branch, not by file order.** An advisory
  describes several parallel release lines, and only one says anything about the version in
  use. `fixedVersionFor` matched on package name and then took the first `fixed` event it
  found, which was right for the Jackson case that motivated it — several *coordinates*, one
  branch each — and wrong as soon as one package has several branches.

  Found while investigating a live report. `GHSA-48r7-hpm6-gfxm` lists four ranges for
  `@angular/common`: fixes on 22.x, 21.x and 20.x, and a 19.x line ending in `last_affected`
  with no fix at all. A user on 19.2.17 was told to upgrade to **22.0.1** — three majors away,
  on a branch their advisory never mentions. A confident, wrong upgrade target is worse than
  none.

  The branch is now selected first: by an advisory's explicit `versions[]` where one exists
  (string equality, ~90% of the Maven set), otherwise by comparing the version against each
  range. Where the selected branch offers only `last_affected`, null is the honest answer —
  there is no fix on that line. Where no branch can be placed, null again rather than a guess.

  This needed a version comparator, which the CVSS decision above deliberately refused to
  write. The difference is that version ordering is well defined and testable, whereas CVSS
  scoring would have been reimplementing arithmetic the scanner had already done. `VersionOrder`
  is scoped to dotted releases with pre-release suffixes — what OSV's `SEMVER` ranges are made
  of — and Maven's richer qualifier rules are covered by preferring `versions[]`.
- 2026-07-28 — **A component is indexed under every name a scanner might use for it.** The
  report carries no purl, so ecosystem/name/version is the only link back to a stored
  component, and a miss silently discards the finding. Scoped npm packages broke it:
  `npm sbom` emits `name: "@angular/common"` with no group, while other generators split it
  into `group: "@angular"` and `name: "common"` — which `coordinates()` renders as
  `@angular:common`, with Maven's separator, against the scanner's `@angular/common`.
  Registering both spellings is cheaper and more robust than trying to infer which generator
  produced the document. Collisions are harmless, since the forms only coincide when they
  denote the same package.
- 2026-07-28 — **Repeated dependency edges are collapsed at parse time.** Generators list the
  same ref twice, or repeat a target within one `dependsOn`. Both describe one relationship,
  and stored as written they violate `component_dependency`'s primary key and fail the entire
  import — reported live as an SBOM that simply would not load. Deduplicated in the parser
  rather than ignored at the database, because the duplication is meaningless rather than a
  conflict to resolve. Self-edges are dropped for the same reason, and because they would turn
  the scope walk into a loop.
- 2026-07-28 — **Dependency scope is three-valued, and the boolean it replaced was wrong
  rather than coarse.** `is_direct` could only express "depended on by the root". In an
  aggregate Maven BOM the root is the parent pom, so its direct dependencies are the
  project's own modules: every genuinely declared dependency was reported as **transitive**,
  and the only rows reported as **direct** were two artifacts the user cannot upgrade because
  they wrote them. Confirmed against the real fixture before changing anything.

  `ScopeClassifier` establishes the application — root plus sibling modules — and then treats
  what that set depends on, minus itself, as `DIRECT`. For npm and single-module Maven the
  application is just the root, so the rule reproduces the old behaviour where it was already
  correct. In the Maven fixture the backend module declares seven dependencies and the seventh
  is `sbomscope-frontend`; excluding a sibling module from "things you can upgrade" is exactly
  what the boolean could not do.

  **Module detection is a heuristic and is deliberately strict.** CycloneDX marks a reactor
  module no differently from a third-party artifact, so it is inferred from group *and* exact
  version together. Either alone is too loose: an organisation routinely consumes its own
  published libraries under the same group prefix, and those are real upgradable dependencies.
  A blank root group disables detection, which is what keeps npm safe. `ScopeClassifierTest`
  pins the refusals — same version different group, same group different version, and
  `com.acmex` not matching `com.acme`.
- 2026-07-28 — **V1–V4 squashed into one baseline.** V4 had already added a column the scope
  change would have removed, so a reader would have met `is_direct BOOLEAN` in one migration
  and had to reconstruct the history to learn it no longer exists. Squashing also avoided
  committing a migration whose job was to delete the user's data — an artifact that would have
  outlived its usefulness by years.

  The trade is a one-time break: databases created by the old migrations fail to start, and the
  fix is to delete `~/.sbomscope/db/sbomscope.mv.db` with the application stopped. Settings live
  in that database, so the scanner path has to be re-entered. Acceptable now because the only
  installations are the maintainer's; recorded as constraint 8 in `AGENTS.md` so it stops being
  acceptable the moment that changes.
- 2026-07-28 — **Orphaned stored documents are swept at startup.** Documents and rows live in
  two places no transaction spans, so they drift — a crash mid-import, or a schema reset, which
  empties tables and cannot reach the disk. The sweep is deliberately one-directional: a row
  whose document is missing is left alone, because that is a real SBOM whose re-scan fails with
  a message saying so, and deleting the user's inventory to tidy up after ourselves would be a
  far worse trade. Filenames it cannot account for are also left alone; the directory is the
  user's.
- 2026-07-28 — **Purge deletes rows, never the database file — and never the migration
  history.** H2 holds an exclusive lock on `sbomscope.mv.db` while the application runs (the
  same lock that blocks a rebuild), so removing the file from inside the running process is
  not possible. Emptying the tables achieves the same result and leaves a working schema.

  The consequence is worth stating because it is the obvious wrong assumption: **purge cannot
  rescue an installation that will not start.** A migration the application refuses to boot on
  has to be dealt with while it is stopped, by deleting the database file. `flyway_schema_history`
  is deliberately left alone — clearing it from a running process would leave a populated schema
  that Flyway believes is empty, which is worse than the problem it would be solving. The panel
  says so, and a test pins it.

  Four independent targets rather than one button, because they differ by orders of magnitude
  in what they cost to undo: re-uploading an SBOM is a drag and drop, while replacing the npm
  archive is a 200 MB download that the restricted environments SBOMscope targets may not be
  able to perform at all. Erasing SBOMs deliberately keeps the purl-keyed vulnerability cache,
  so a re-upload gets its findings back without re-running the scanner — clearing that is a
  separate intention. An unrecognised target fails the whole request rather than being skipped:
  deleting something other than what was asked for is the one outcome a purge must never produce.
- 2026-07-28 — **Export columns are a setting, defaulting to all of them.** "Export view"
  reproduces the screen's *rows* — that was always about filter, sort and paging. Whether it
  also reproduces the screen's *columns* is genuinely ambiguous, so it became a Settings
  choice rather than a decision taken on the user's behalf. The default is every column: a
  spreadsheet has no width pressure, it is usually read by someone who never saw the view it
  came from, and a recipient cannot recover a column dropped before they received it.

  The browser always sends the columns it is showing and the backend decides whether they
  narrow the workbook, so the rule lives in one place instead of both ends holding an
  opinion. Unknown or empty column ids fall back to every column: a malformed request should
  produce a complete spreadsheet, never a blank one, because silently omitting findings is
  the worse failure.
- 2026-07-28 — **The provenance sheet records what was selected, not just what was scanned.**
  A workbook holding 40 of 600 findings was indistinguishable from a complete one. It now
  carries scope, sort, severity bands, text filter and columns — the receiving-end
  counterpart to the row counts on the export buttons.
- 2026-07-28 — **Export filenames carry the time to the second.** A date alone collided the
  second time you exported in a day, which is exactly what happens while narrowing a filter,
  leaving the browser to disambiguate with "(1)" and "(2)". Colons are illegal in Windows
  filenames, so the time is written without them and still sorts chronologically.
- 2026-07-28 — **One SQL expression decides a finding's band.** The severity filter built a
  chain of OR'd range predicates while the new summary counts needed the same thresholds
  again; two statements of the same boundaries would drift, and the failure — the number
  beside "High" describing different rows than ticking High — would be silent. Both now read
  a single ordered `CASE`, which also made the filter clause shorter.

  It closed a real gap in passing. LOW required `severity_score > 0`, so a finding scored
  exactly **0.0** matched neither LOW nor NONE (which requires no score at all): the row
  existed but no filter selection could display it. The `CASE` ends in `ELSE 'LOW'`, so no
  scored finding can fall outside every band. `SeverityBandTest` pins the thresholds from
  either side, since a comparison flipped between `>=` and `>` only shows at the edge.
- 2026-07-28 — **The severity summary is unfiltered, and includes Low and Unscored.** It
  describes the SBOM, not the current view — the row count under the table already answers
  "what am I looking at". Low and Unscored are shown despite rarely being acted on first,
  because without them the counts would not sum to the total printed beside them, and an
  unexplained discrepancy in a security summary costs more than a quiet extra number. Empty
  bands are dimmed rather than hidden, keeping "none found" distinct from "not measured".
  Read-only: filtering stays with the severity chips, so two controls cannot disagree about
  what is selected.

  **Merged into the severity chips the same day, after two attempts.** As stacked cards the
  summary was the largest block above the table — 101px of 288px, leaving the table 380px of
  a 720px window. Measured, not guessed.

  The first attempt moved it into the page header as a horizontal strip and folded the
  headline count and scan date into the header's meta line. That returned 114px but still
  looked wrong, and the reason was the real problem: **the chips and the counts described the
  same six bands, so the screen said everything twice.** Any placement of a second control
  for one taxonomy was going to look like clutter.

  Each chip now carries its own count. One control instead of two, no block above the table
  at all, and the numbers became clickable. **135px returned in total: 288px down to 153px,
  with the table going from 380px to 515px.**

  Two consequences worth knowing:

  - **A chip's count is "how many rows selecting this produces"**, counted from the same LEFT
    JOIN the view is built on. That is what makes `CLEAN` countable — it counts components
    with nothing against them where the others count vulnerabilities. Different units, but the
    same question for a filter. `countsByBand` changed from counting findings to counting
    rows for this reason, and `SeverityBandTest` now checks every band, not just the vulnerable
    ones, because a number printed on a control that did not match what clicking it produced
    would be worse than no number.
  - **The count does not move with the filter.** It describes the SBOM, so the chips stay
    comparable however the view is narrowed. Unpressed chips were lightened from 0.45 to 0.62
    opacity so a switched-off band's number stays readable.

  The wider chips then pushed the controls row onto a second line, which would have given back
  the space just saved. `.toolbar__search` now flexes (`1 1 180px`, capped at 320px) and shrinks
  first — it reads perfectly well at half width, and a filter box is not worth a band of vertical
  space. At 1024px the row still wraps, since the chips alone are 518px; nothing overflows and it
  remains ahead of the original layout.
- 2026-07-28 — **GHSA rating and CVSS severity are separate columns, because they are
  separate claims.** `severity_rating` comes from the advisory's `database_specific.severity`
  — GitHub's own LOW/MODERATE/HIGH/CRITICAL scale — and is not derived from the CVSS score
  beside it. The table had been rendering it as that score's label, so a finding read
  "6.5 MODERATE" where CVSS's own word for 6.5 is "Medium". MODERATE is not a CVSS term at
  all. The severity cell now shows the band derived from its own number, and the GHSA rating
  has its own column, placed next to the OSV ID it belongs to.

  Columns are ordered by source generally: everything except the CVE identifier describes
  the OSV/GHSA record, including the published date, which is when the *advisory* appeared
  rather than when NVD published the CVE.
- 2026-07-28 — **Compact / Details, with a locked core.** All 13 columns are reachable, but
  showing them by default makes the table unreadable, so Compact is a configurable subset and
  Details is everything. Component, Version, OSV ID and Severity cannot be switched off —
  a row missing any of them cannot be acted on. The picker lives on the table toolbar rather
  than in Settings: it is wanted at the moment you are looking at the table, and the effect
  is visible as you tick. Stored sets are repaired on load — unknown ids dropped, locked ones
  forced back in, canonical order restored — rather than trusted, since a preference outlives
  the code that wrote it.

  **Revised the same day**: both controls started out inline in the toolbar, which put "how it
  looks" between "which rows" and the export button — three unrelated jobs reading as one
  strip. They now share a single view-options menu next to Export, so the row divides on what
  the controls are *for*: filtering to the left, things you do to the result to the right.
  Density moving behind a click is the cost; the toolbar no longer looking like a pile of
  unrelated widgets is the gain.
- 2026-07-28 — **Advisory links come from `AdvisoryLinks`.** The exporter built osv.dev and
  NVD URLs inline while the API sent its own `referenceUrl`, so the table and the spreadsheet
  had two implementations of the same decision. Both now call one helper, for the same reason
  `RegistryLinks` already existed. `FindingRow.referenceUrl` went with it: with OSV ID and CVE
  ID as separate columns, a single "authoritative link" no longer describes anything.
- 2026-07-28 — **A glossary, because the vocabulary is unavoidable.** CVSS, GHSA, purl and
  CycloneDX scopes are what the data is, and are opaque to anyone not already working in
  supply-chain security — who is exactly who receives the exported spreadsheet. The
  per-column table is the substantive half: it names each column's source, which is where the
  distinctions this project keeps making (GHSA rating vs CVSS band, advisory date vs CVE date,
  unscored vs clean, why a vector can be missing) are written down for the reader rather than
  only for the maintainer.
- 2026-07-28 — **Scan availability is checked, not assumed.** The scan button was disabled
  only on the settings toggle, so with scanning switched on but the binary moved or the OSV
  archive never downloaded, it stayed enabled and failed on click. `ScanService.readiness`
  now reports a reason code the UI renders beside the button. Checked **per SBOM**, because
  the archives needed depend on the document's ecosystems — telling someone with a
  Maven-only SBOM to fetch npm's 200 MB archive would be wrong as well as annoying.
  Filesystem checks only: confirming the binary really is osv-scanner means running it, which
  belongs behind the deliberate "Test scanner" action, not on every poll of the view.

  Rendered as text next to the control rather than a `title` tooltip, which is invisible on
  touch, to keyboard users, and to anyone who does not think to hover over something that
  looks broken.
- 2026-07-28 — **View preferences persist; the page number does not.** Sort, severity bands,
  page size, text filter and the sidebar's collapsed state are written to `localStorage`, so
  a trip to Settings no longer resets the table. The page number is deliberately excluded:
  restoring page 7 against whichever SBOM happens to be selected lands somewhere arbitrary.
  `localStorage` rather than the URL because SBOMscope runs on one machine for one person,
  so there is nobody to share a link with. Stored state is revived through a validating
  function rather than trusted, since it outlives the code that wrote it.
- 2026-07-28 — **One export button, with the row counts kept.** Two side-by-side buttons
  became a split button: primary action exports the view, the caret opens both scopes. Opened
  by click, not hover — a hover menu is unreachable by keyboard and does not exist on touch,
  and this is the only route to a whole-inventory export. Both entries still carry their row
  counts, because the reason those counts existed has not changed.
- 2026-07-28 — **A group's CVSS vector is shown only when its members agree on it.**
  Findings are built per group of aliased advisories. The score comes from
  `max_severity` — the highest across the whole group — while every other field is read
  from the single advisory whose id is displayed, so where members disagree the number and
  the vector described different records. Nothing surfaced this because the vector was
  never displayed; adding a CVSS vector column would have made the tool print a vector that
  does not produce the score beside it.

  Reading every field from the member whose score is the maximum was considered and is not
  implementable cheaply: OSV encodes severity as CVSS **vector strings only**, and just the
  group carries a number, so identifying that member means owning a CVSS v3.1 + v4.0
  scoring implementation — a few hundred lines of lookup tables duplicating the scanner, in
  the one place where being subtly wrong is worst. Rejected under constraint 9.

  Instead the vector is returned only when every member carrying one agrees, which makes it
  unambiguously the vector behind the score; otherwise it is dropped and the score stands.
  The score is never lowered. Measured against the Maven set: 21 of 6,860 advisories are in
  a multi-member group, and 11 of those pairs disagree on the vector — so the rule affects
  ~0.16% of advisories, and where it bites the disagreements are large
  (`C:H/I:H/A:H` against `C:L/I:L/A:L`), not rounding.
- 2026-07-28 — **One finding per (component, advisory), decided in the parser.** A scan on
  another machine failed at `recordScan`: the parsed list held two findings with the same
  purl and OSV id, which is exactly what `uq_finding_per_component` forbids. The import runs
  in one transaction, so the whole scan was lost, and the error named a constraint rather
  than anything the user could act on.

  **The lookup that produces it is not the bug**, which is why the obvious fix is the wrong
  one. Resolving a reported package back to a purl is many-to-one in two independent ways,
  both deliberate: `component` is unique on (sbom_id, bom_ref) and not on purl, so one
  document can legitimately carry the same library twice — npm installs a package at several
  paths, an aggregate BOM spans several modules — and a component is registered under every
  name a generator might use for it, which is the fix that stopped scoped npm packages being
  silently dropped. Making either one-to-one would reintroduce a discarded-findings bug to
  cure a duplicate-row one.

  So uniqueness is established where the pair is assembled. `OsvReportParser.parse` collects
  into a map keyed by `VulnerabilityFinding.Key`, which is the schema's constraint written
  once in Java. Put in the parser rather than at the call site because returning a list that
  cannot be stored is the parser's defect regardless of who consumes it — and Phase 8's
  guided remediation is a second consumer waiting to happen.

  **A MERGE in the repository was considered and rejected.** It would have made the write
  idempotent, and `vulnerability_scan` is already written that way, so it was the consistent
  choice. But it resolves collisions by last-one-wins, silently, at the point where nothing
  can see them any more. Colliding findings are normally identical; where they are not, the
  descriptive fields depend on the reported package name, and the difference is worth a log
  line rather than a coin toss. The first is kept, which is the entry described from the
  advisory's own coordinates — `keepsTheFullyDescribedFindingWhenDuplicatesDisagree` pins
  that, since the alternative silently prefers a row whose fix version could not be resolved.
- 2026-07-28 — **Severity counts on the SBOM cards, and "not scanned" is not a zero.** The
  sidebar listed filename, date and component count — nothing about risk — so choosing which
  upload to open meant opening all of them. Each card now carries critical, high and medium.

  Low and Unscored are left off deliberately: the card exists to pick the next SBOM, and five
  numbers in a 280px column is a table rather than a glance. Nothing on the card claims to be
  a total, so unlike the severity chips there is no sum for the omission to break — the
  findings page still carries every band.

  **The counts alone would have lied.** A document nobody has scanned has no critical
  vulnerabilities in precisely the way a scanned, clean one does: every component falls in
  `CLEAN`, and the card would have read 0/0/0 either way. That is the same conflation the scan
  table was introduced to prevent, one screen further out, so `scannedComponents` travels
  with the numbers and the card says *Not scanned* instead. It can be non-zero for an SBOM
  never scanned in its own right, because the purl cache is shared — that is the cache
  working, and the card is honest either way.

  Counted in one grouped query for the whole list rather than per card, from the same
  `BAND_EXPRESSION` and the same LEFT JOIN as the findings page. That is a second
  implementation of a number this project has already refused to duplicate once, so
  `SeverityBandTest` asserts the batched summary equals the per-SBOM one rather than trusting
  that they look alike. Zero bands are dimmed rather than hidden, as on the chips.
- 2026-07-28 — **Advisory dates are UTC dates; timestamps from this machine stay local.**
  The Published column rendered `2026-07-21T22:00:43Z` as "22.07.2026, 00:00" in Berlin. Both
  halves are wrong: the 00:00 reads as though no time was recorded, and the date is a day
  after the advisory the row links to on osv.dev.

  Two kinds of value were being formatted by one rule. Upload, scan and export times happened
  on the reader's own machine, where their clock is the right one. An advisory's publication
  date belongs to an external record the reader can go and check, and shifting it into their
  zone breaks that correspondence for everyone east or west of UTC — but only for advisories
  filed near midnight, so it would surface as occasional bad data rather than a formatting
  choice. The time of day is dropped with it: for triage the question is how old an advisory
  is, never what minute it was filed. The table and the export changed together, as they must.
- 2026-07-29 — **A component's name is never registered without its group.**
  `scannerNamesFor` added the bare name unconditionally, so every Maven component also
  claimed its artifactId alone: `com.foo:core` and `com.bar:core` both claimed `core`, and
  `putIfAbsent` gave it to whichever was indexed first. A finding could then be reported
  against a library that does not have it — worse than dropping one, because it looks like an
  answer.

  Dormant rather than live, since osv-scanner names Maven packages `group:artifact` and never
  emitted the bare form. Which is also why removing it cost nothing: the key could not match
  a real report, and an unscoped npm package already arrives through `coordinates()`, which
  *is* the plain name when there is no group. For a scoped npm package the bare form was
  affirmatively wrong — `common` is a real package and is not `@angular/common`.

  A residual ambiguity is now logged rather than resolved silently: two components can still
  share ecosystem, name and version while differing in purl, which Maven qualifiers such as a
  classifier can produce. The first still wins, since reporting the advisory against one of
  them beats dropping it, but the choice is no longer invisible.
- 2026-07-29 — **The Workspace view becomes the Component Inspector, and phases 6–9 become
  one screen.** No scope was dropped: the dependency tree, upgrade analysis and workspace
  usage all survive intact. What changed is what they are *for*.

  The vulnerability view is list-centred and answers "what is wrong here". Everything left in
  the roadmap answers "what do I do about this one library", which is a different question
  and needs a component-centred screen: one library, its findings, its upgrade options, its
  place in the graph, its use in your code. As three separate phases they read as three
  unrelated features; as one screen they are three panels of a single argument.

  **The old name described an input, not the screen.** A workspace is a directory, it is
  optional, and only one of the three panels uses it — the one now scheduled last. Naming
  the screen after its least central feature made the roadmap look like it was building a
  source browser that happened to know about vulnerabilities. *Viewer* was rejected in turn:
  two of the three panels exist to support a decision, and *inspector* is the established
  word for a focused detail surface on one selected object.

  **The navigation item carries the full name**, not the noun alone. Shortening it to
  *Component* was proposed for symmetry with *Vulnerabilities* and rejected: on its own the
  word names a thing rather than what the screen does with it, and with only four nav items
  there is no width pressure worth paying for that. The icon is a package rather than the
  earlier document glyph, for the same reason the name changed — the subject is one library,
  not a directory of files.

  **Reordered: shell, graph, upgrades, usage.** The shell first so each panel afterwards is
  independently shippable. The dependency graph before upgrade paths despite both being top
  priority, on availability rather than importance — its edges are already stored, parsed and
  deduplicated, so it needs no new data source and has no open question in front of it, while
  upgrade paths are blocked on R4. Workspace usage last: it is the only panel resting on a
  heuristic (R2), and a wrong "not used" is a finding quietly dismissed.
- 2026-07-29 — **The Inspector is keyed by purl, not by component row id.** The intended
  identifier was the component's row id, and it was wrong for a reason that only shows up
  where the two screens meet: `rowsForSbom` selects **DISTINCT** over the purl precisely so a
  library listed twice in one document produces one row. Putting the row id back into a row
  to link from it would have undone that collapse and reintroduced the duplicate rows the
  parser fix had just removed. The Inspector's unit has to be the table's unit, or the action
  on a row opens something the row was not describing.

  Carried in the **query string** rather than a path segment, because a purl contains
  slashes and an encoded slash inside a path is rejected outright by some servlet containers
  — a failure that would have appeared only for certain packages.

  Two consequences worth stating. `findComponentByPurl` returns the first match from an
  ordering that puts the root first and then sorts by scope, so where a purl does appear
  twice the Inspector describes the most significant of them rather than an arbitrary one.
  And **the selected SBOM is now persisted**: the URL names a component but not the document
  positioning it, so without that a refresh restored the component against whichever SBOM
  happened to be newest. That also fixes the older annoyance of the findings view silently
  switching documents on reload.
- 2026-07-29 — **`RowResponse` and the finding presentation helpers are shared, not
  reimplemented.** The Inspector shows the same component the table does, so it reads the
  same row shape from the same SQL and renders severity through the same component. Two
  descriptions of one row would have been free to drift, and the specific way they drift is
  known in advance: "unscored" starts reading as "clean" on one screen and not the other.
  `RowResponse` moved out of `ScanController` into its own file, and `bandOf`,
  `SeverityCell`, `formatTimestamp` and `formatAdvisoryDate` out of `VulnerabilitiesPage`
  into `findings/presentation`.

  The Inspector does add one thing the table cannot say: **three states rather than two.** A
  component with no advisories is either checked and clean or never examined, and the table
  answers that once for the whole SBOM while the Inspector has to answer it for one
  component. `scannedAt` is therefore per purl, and null renders as a warning rather than
  as silence.
- 2026-07-29 — **Remedies are ranked on three properties, not one — and "bump the direct
  dependency" is not automatically the best.** For `root → A → B → C` with C vulnerable, the
  fix upstream intended is a newer A that already brings a fixed C, and telling someone to
  override C is telling them to own a version they never chose. So the remedy has to become
  real rather than permanently unavailable, which is the least useful state a remedy can be
  in.

  Ranking direct bumps above overrides as a rule was proposed and **refined rather than
  taken**, because it hides the property that actually decides correctness:

  - **Route completeness.** Where C is reached by `A → B → C` *and* `D → E → C`, bumping A
    fixes one route and leaves the other — the finding does not go away. A pin constrains C
    wherever C appears, so it is route-complete by construction. That is a correctness
    argument for pinning, not a convenience one, and it means a direct bump can be the
    *worse* answer while looking like the better one.
  - **Blast radius.** A patch on A and a major on A are not the same suggestion, and neither
    is comparable to one pinned line.
  - **Durability.** An upstream release is maintained by someone else; a pin is a constraint
    you own until you remember to remove it.

  Suggested remedy is therefore: clears every critical and high **and** fixes every route, at
  the smallest change size, with ties broken toward the upstream fix. A minimal direct bump
  usually wins that — the instinct was right for the common case — but it wins by satisfying
  the criteria rather than by category.

  **Naming the blocker is worth as much as naming the fix.** With resolved trees for A's
  candidates, "no version of A resolves this" becomes answerable, and so does why: the
  constraint is B, which has no fixed release. That is the actual next action — open an issue
  against B — and nothing else in the tool can say it.

  This is unavoidably Tier 2. It needs A's *resolved* tree at each candidate version, after
  nearest-wins, `dependencyManagement`, BOM imports and exclusions have had their say. That
  appears in no SBOM of this project and no advisory database, so it is a matter of a data
  source rather than of trying harder offline.
- 2026-07-29 — **The advisory index is persisted in the database, not held in memory.**
  Measuring the in-memory version answered the question it was meant to and then raised a
  better one: npm cost 5.2 s to build and **~152 MB retained**, and almost all of that memory
  described the 220,000 packages a given project does not have.

  Three arrangements of an in-memory index were considered — build it after the download,
  scope it to the packages the uploaded SBOMs mention, or leave it lazy behind a spinner.
  All three share a defect: **the index dies with the process.** Whatever the trigger, the
  first question after every restart pays the parse again.

  Persisting it removes that, and the codebase made it far smaller than a bespoke file
  format would have been: **H2 is already here**, so the index is a table (`osv_index`, V2)
  and a lookup is an indexed SELECT. That also dissolves the two moving parts the design
  seemed to need — nothing loads at startup and nothing is augmented when an SBOM is
  uploaded, because a query *is* the selective read. Neither can be forgotten if neither
  exists.

  Measured after building it: Maven indexes in **1.6 s** through the API, evaluation is
  correct across a restart in **283 ms with no re-parse**, and retained memory is now
  whatever one query holds.

  Three consequences worth carrying:

  - **Being present and being indexed are different states.** An archive copied onto an
    air-gapped machine is fully scannable — osv-scanner reads it directly and never touches
    this index — but cannot answer "would this version be clean". Settings shows both and
    offers **Index** for the gap, because the alternative was telling someone to re-download
    200 MB they already have.
  - **The index is keyed to the archive's size and modification time.** A refreshed download
    invalidates it without anyone remembering to, which is exactly the kind of thing nobody
    remembers.
  - **The source row is written last.** A build interrupted halfway leaves rows that nothing
    considers usable, and the next attempt rebuilds — the same reasoning as downloading to
    `all.zip.partial` before moving it into place.

  The trade is RAM for disk: Maven's advisories added ~10 MB to the database. npm's will add
  considerably more and that number has not been taken.
- 2026-07-29 — **The local matcher is built, and the boundary around it is the design.** It
  answers one question osv-scanner does not take: which advisories apply to a version the
  user *does not have*. The scanner reads a document describing what is present, so
  "would 3.1.5 be clean?" has nowhere to go in it.

  **What is installed is still reported by osv-scanner and nothing else.** If the two ever
  disagree about a version actually in the SBOM, the scanner is right by definition. The open
  question that rejected a built-in matcher rejected it as a replacement for the reporting
  path, where being wrong misreports a real component; this never touches that path, and
  being wrong here misranks a suggestion. Keeping the boundary sharp is what makes the
  revival safe, and it is why the matcher lives behind a callback the advice service
  receives rather than a dependency it holds.

  Two consequences fell out of building it:

  - **Range semantics moved into one place.** `AffectedVersions` is now read by the report
    parser *and* the matcher. Two implementations of "does this version fall in this range"
    would drift, and the direction is not neutral: one says an upgrade is clean, the other
    says it is not.
  - **The result carries a GHSA rating, never a CVSS score.** OSV stores severity as vector
    strings only — the numbers on a finding were computed by the scanner — so producing one
    here would mean owning a CVSS implementation, which this project declined once already
    and for the same reason. The panel labels it as GHSA's own scale, as everywhere else.

  Measured on the real archive: **891 ms to index 6,860 Maven advisories, 81 ms cached.** The
  npm archive is 20× larger and has never been indexed, so that cost is a known unknown
  rather than a solved one.
- 2026-07-29 — **Scanning becomes automatic; fetching stays on request.** Constraint 2 said
  "no background jobs, no refresh-on-startup, no refresh-on-upload", and a day of real use
  found the gap it left: an SBOM you have just uploaded reads *Not scanned* until you press a
  button whose necessity is not obvious, and the purl cache means most of the answer was
  already sitting there.

  The constraint was reaching for something narrower than it said. **Downloading an archive
  and running a scan are not the same act.** A download leaves the machine and is somebody's
  data transfer; a scan runs a local binary against a file already on disk and sends nothing
  anywhere. Only the first needs asking. That is the same line constraint 1 draws — what
  leaves the machine, not what the CPU does — so the two constraints now agree rather than
  one being a stricter accident.

  So: a newly uploaded SBOM is scanned automatically, and at startup components with no scan
  record are scanned in the background.

  **Two costs were raised against the startup half and designed around rather than accepted.**
  It runs *after* the application is serving, so launch is never delayed; and it covers only
  components lacking a scan record, one SBOM at a time, and does nothing at all where the
  scanner is unconfigured or its archive absent. Every run is logged, because it starts an
  external process and that is precisely what the activity log is for.

  The manual re-scan survives. Findings go stale when the archive is refreshed, and re-running
  analysis deliberately is a different need from filling a gap.
- 2026-07-29 — **The network stance is framed by what traffic reveals, not by whether traffic
  happens.** "SBOMscope's own network access is exclusively user-triggered cache refreshes"
  was written a few hours earlier and reads as a strict no-calls claim, which it is not:
  the OSV archives are fetched by us, with our own HTTP client. The README version —
  *SBOMscope does not go and ask* — was worse, since it is simply false.

  Softer wording would have papered over it. The line that actually holds is **what the
  traffic discloses about the user**, and it separates three categories cleanly:

  1. **Executable code — never fetched.** The user places osv-scanner. A supply-chain tool
     that downloads and runs someone else's binary has the wrong default.
  2. **Bulk public data — fetched on request.** Requesting *every* Maven advisory says
     nothing about which libraries you have. That is why it can be an archive rather than a
     series of questions, and why it can travel on a USB stick to an air-gapped machine.
  3. **Anything about the user's own dependencies — delegated, never asked.** "Which versions
     of `com.acme:internal-billing` exist" identifies that artifact as one you use. Maven asks
     it, through their mirror, with their credentials, over a channel their build already
     uses daily — so no new disclosure is created and no credential is held here.

  This is also the principled version of the reversal below: the rejected API design was a
  category-3 question being answered by category-2 means. Stating the rule that way makes
  the same mistake harder to make again than "do not call deps.dev" would.
- 2026-07-29 — **Upgrade paths drive the user's build tool, and the outbound-API decision
  taken this morning is reversed.** Both changes came from one observation: asking Maven is
  better than asking a registry.

  The API design required knowing a mirror URL and credentials, which led me to propose
  reading `mvn help:effective-settings`. Challenged on why we would need the user's Maven
  configuration at all, the answer turned out to be that we would not — **Maven reads its own
  settings when it runs.** The requirement was manufactured by choosing to fetch metadata
  ourselves. Removing that choice removed it, and produced a better mechanism: a probe POM
  declaring a *version range*, resolved by `dependency:tree`, which returns the version Maven
  picked *and* the tree it resolves. Two problems, one invocation, core plugins only.

  **So deps.dev is dropped and constraint 1 is narrowed back to its original claim.**
  SBOMscope's own network access is again exclusively the OSV download. Delegated access —
  Maven fetching on the user's behalf, through their mirror, with their credentials — is
  declared as its own category rather than pretended away, since we cause those calls even
  though we do not make them. This is a stronger position than the one it replaces and it
  costs nothing: the tool route is *better* in a restricted environment, not merely
  acceptable.

  Decisions taken, in order, and the reasoning that is not obvious from the outcome:

  - **Isolated local repository**, never `~/.m2`. A failed probe leaves `.lastUpdated`
    markers that can make a later real build refuse to retry. Nearly free, since
    `dependency:tree` resolves POMs and not jars.
  - **Version enumeration reads `maven-metadata.xml` out of our own repo**, which Maven puts
    there while resolving a range. Keeps "we never call out" literally true.
  - **A calibration probe** at the current version, compared against the SBOM's resolved
    version, before any candidate is trusted. This is what makes the SBOM-only case honest
    rather than optimistic: matching proves the isolated model reproduces their build for
    that chain; differing proves something is overriding it and sends the reader to the pin.
  - **`dependencyManagement` lifted in when a workspace exists**, isolated when it does not.
  - **Tiers first, then refine.** And explicitly *not* a binary search: "brings a fixed C" is
    not monotonic in the version, because a newer release can carry a new advisory, so an
    ordered search would confidently report an earliest that is not one.
- 2026-07-29 — **Two logs, and the UI tails the structured one.** Probing produces reasoning
  worth showing — *4.2.0 resolves jackson-databind 3.1.6, clean* — which turns the log from
  an event feed into the audit trail behind a recommendation. That matters more here than
  usual: this project's recurring worry is advice nobody can check, and probe results are the
  working shown.

  `sbomscope.log` is the full verbose record for diagnosing; `activity.jsonl` holds notable
  events as one JSON object per line and is what the UI reads. Splitting them answers the
  objection to tailing one's own log — the viewer never parses prose, because the file it
  reads was written to be read back. Notable means anything touching the network, anything
  running an external process, anything changing stored data, and every probe verdict.
- 2026-07-29 — **Outbound lookups become possible, off by default, one host at a time.
  Superseded the same day — see the build-tool decision above.**
  Constraint 1 previously allowed the network *only* for cache refreshes. Upgrade paths need
  something no cache can hold — the list of versions a library actually has — so the
  constraint is broadened rather than worked around.

  **What is preserved is the guarantee, not the mechanism.** Offline still has to produce an
  honest answer; what changes is that "honest" is allowed to mean *narrower*. With every
  switch off the panel names the fix versions the advisories carry, names who pulls the
  library in, and says which questions it cannot answer — it does not compute a "latest
  version" from a biased set and present it as the latest. That distinction is the whole
  point: this project tolerates staleness because a stale finding is still a real finding,
  and refuses guessing because a truncated version list omits the release that fixes the
  problem.

  **Per host rather than one master switch.** Two levels of state to reason about is one too
  many, and the question a security-conscious reader actually asks is not "which feature" but
  "what leaves this machine, and to whom". Each entry shows its exact URL, matching how the
  OSV archive panel already works. The default is every switch off, which is what keeps
  "offline by default" a fact about the shipped product rather than a claim about intent.

  **A lookup is a disclosure**, and the UI has to say so. Asking Maven Central which versions
  of an artifact exist tells Maven Central that you use it — for an internal-sounding
  coordinate in a locked-down environment that is a real cost, and precisely the sort of
  thing users of this product are employed to care about.
- 2026-07-29 — **Upgrade paths are about remedies, not versions.** The phase was specified as
  "which version should I move to", and for most findings that question has no answer at all:
  **you cannot upgrade what you do not declare.** The advisory says 3.1.5 fixes
  `jackson-databind`, and your `pom.xml` has never mentioned jackson. "Upgrade to 3.1.5" is
  then a true statement and a useless one.

  Four remedies instead, of which a version bump is only the first: upgrade it (if you
  declare it), **pin it** (Maven `dependencyManagement`, npm `overrides`), bump whatever
  pulls it in, or exclude it.

  **Pinning is the discovery.** It is precise, it is a snippet you can paste, it works
  whatever the ancestor does — and it needs nothing SBOMscope does not already hold, since
  the fixed version comes from the advisory and the ecosystem from the purl. For a transitive
  finding it is very often the right answer, and the earlier design had no concept of it.
  Naming the declaring ancestor is free too, now that Phase 7 computes the routes.

  Bumping the ancestor is the remedy that genuinely requires the network: whether
  `spring-boot-starter-json 4.2.0` ships a fixed jackson means reading *its* dependencies at
  that version, which appears in no SBOM of your project and no advisory database.

  Excluding is the remedy that requires **Phase 9**, and is not to be recommended without it.
  A recommendation to delete a dependency the code turns out to use is worse than no
  recommendation, so until usage detection exists it is listed as an option with its caveat
  and never as the suggestion. That dependency runs the other way from how the phases were
  ordered, and is the first argument for moving workspace usage up.

  A single suggested remedy is offered with its reasoning and its inputs beside the
  alternatives — not a bare verdict. Constraint 6 is untouched: this is derived from data,
  not a judgment field a user types into.
- 2026-07-29 — **The Inspector's panels are tabs, and the finder is a fixed column beside
  them.** Stacked, four panels made the page a scroll where only one of them is ever the
  reason you came. Tabs hold the component's identity and the finder still while the answer
  changes — which is what makes the finder worth a column rather than a control you use once:
  pick the next library and the question you were already asking is on screen for it. The tab
  choice is persisted and deliberately *not* reset when the component changes, because
  comparing the same panel across several libraries is the workflow.

  **The first tab is "Advisories", not "Vulnerabilities".** The top-level view already owns
  that word, and two different things under one name in one application is how a reader stops
  trusting either. It is also the more accurate label: the panel lists advisory records, and
  a component can legitimately have none.

  Below 900px the columns stop fighting for width and the side column goes full-width above
  the panel, which is the arrangement it reads fine in and the table never did.

  **Revised the same day: the component's identity moved into the side column too**, above
  the finder. It had been sitting in the main column above the tab strip, which pushed every
  panel down by its own height — about 160px, on the one screen whose main content is a
  dependency tree several hundred rows long. What you are looking at and how to change it
  belong together, and the tab strip now top-aligns with the identity block beside it.

  With nothing selected the block becomes a dashed placeholder with a **floor on its height
  and no animation**. A shimmering skeleton was the obvious thing and is wrong here: nothing
  is loading and nothing is on its way, so animating it would promise something that is not
  coming — the same reason "never scanned" is a sentence rather than an empty list. The floor
  is a floor rather than a match: a real identity varies with how long the coordinates are,
  so the first selection still shifts the finder down somewhat, while switching between
  components of similar name length does not.
- 2026-07-29 — **"n of your m modules" excludes the aggregate root from m.** The first
  version counted every APPLICATION component, so the maven fixture reported "1 of your 3"
  where the honest answer is "1 of your 2". The parent pom depends only on the project's own
  modules, so no route can ever top out at it — it was a denominator term that could never
  appear in the numerator, quietly understating every ratio. Where the root is the only
  application component, as in npm and single-module Maven, it *is* the module and counts as
  one, which is the same reduction that makes the scope classification safe there.

  Caught by reading the number the panel actually printed rather than the code that made it.
- 2026-07-29 — **The tree shows structure, not repeated labels.** Every row carried a
  direct/transitive badge, which on a tree is a word repeated down the whole left edge to say
  something the indentation already says — and it competed with the two markers that do carry
  information, *also above* and *cycle*. Removed. The native disclosure triangle went with it
  in favour of explicit `+`/`−` controls: bigger, identical in every browser, and a tree is
  read by scanning its left edge for what can still be opened. Leaves carry a matching spacer
  so the controls form a column rather than ragged indentation. The open
  question asked whether to use a collapsible tree or a graph visualisation, and it was
  malformed: it assumed one rendering had to serve both directions, when the directions are
  different questions.

  Upward the question is *why is this here*, and the answer is a route: the distinct paths
  from a root down to the component, shortest first, one per line. A diamond is stated
  honestly by listing both routes rather than drawing them, the shortest is usually the only
  one that matters, and a line of arrows pastes into a ticket — which is where this answer
  tends to end up.

  Downward the question is *what does this drag in*, and the answer is a set. A collapsible
  tree shows its shape at a glance where a path list would repeat a long shared prefix on
  every line.

  **A node-link graph was rejected** despite being the only structurally truthful option —
  one node per library however many edges reach it. It needs a layout algorithm, so either a
  frontend dependency to justify under constraint 9 or one hand-rolled; and on a real project
  SBOM of a few thousand components an unfiltered drawing is unreadable without a filtering
  design nobody has done. Neither shape chosen here needs a layout pass at all, so Phase 7
  adds no dependency.

  One consequence to honour: with many routes to a root, the panel shows the shortest few and
  **says how many it held back**. A quietly shortened list of causes is a wrong answer to
  "why is this here", not a tidier one.
- 2026-07-29 — **An upward path tops out at the owning module, not the document root.** In an
  aggregate Maven BOM the root is the parent pom, so a faithful walk reads
  `sbomscope-parent → sbomscope-backend → spring-boot-starter-web → jackson-databind`, where
  the first hop is bookkeeping. The parent aggregates; it does not depend on anything the
  reader can act on, and it would lead every path in every aggregate SBOM with the same
  uninformative name.

  Stopping at the nearest APPLICATION component instead makes the top of the path say
  **which of your modules is responsible** — the first thing you need before fixing anything,
  and something the old `is_direct` boolean could not express at all. `ScopeClassifier`
  already computes that set, so this costs nothing new. For npm and single-module Maven the
  application is just the root and the rule reduces to the obvious behaviour, which is the
  same property that made the scope classification safe to introduce.

  This resolves the dependency-graph half of the multi-module open question. The workspace
  half is untouched and stays open for Phase 9: an aggregate SBOM spans several source
  directories, and which one a component should be scanned against has no answer yet.

  **Amended the same day, and the amendment matters more than the decision.** As first
  written this said "the owning module", singular, and paired it with a rule capping long
  path lists to the shortest few. Both were wrong for the ordinary case: a library is
  routinely reached from *many* modules — Spring is in every backend module — and capping by
  shortest route would then have silently dropped most of the modules affected. That inverts
  the value of the panel. The number of your own modules carrying a vulnerable library is the
  scope of the problem, and scope is what decides whether it is a morning's work or a
  quarter's.

  So: every owning module is always listed. Capping applies only *within* a module, where
  several routes reach the same component and only the shortest is usually interesting, and
  even then the count of what was withheld is shown. Hiding a route is a tidier answer;
  hiding a module is a wrong one — the same distinction the severity chips already make
  between a number that is smaller and a number that is false.
- 2026-07-29 — **Apache-2.0.** Chosen on the same reasoning as most of this project: the
  target is a locked-down corporate machine, so the licence has to survive somebody else's
  procurement review. Apache-2.0 passes without discussion. AGPL was considered and rejected
  for precisely the audience it would otherwise protect against — corporate policy at the
  kind of organisation SBOMscope is for frequently bans it outright, and the risk it guards
  against (someone running this as a competing hosted service) is small for a local-first
  single-user tool that explicitly does not run as a shared service.

  MIT was the close alternative and would have been fine. Apache-2.0 wins on two details:
  §8 states the limitation of liability in specific terms rather than one sentence, and §9
  has no MIT equivalent — anyone redistributing SBOMscope with their own support or warranty
  does so on their own behalf and indemnifies us for it. For a tool likely to be repackaged
  inside a company, that is the difference worth having.

  Two things the licence does **not** do, recorded so they are not assumed: German law limits
  how far liability can be disclaimed in advance regardless of what the text says, and the
  EU Cyber Resilience Act's obligations for a security product attach from December 2027
  independently of licensing. Neither is a licence question, and both need real advice before
  this is commercialised.

  The `LICENSE` file is the verbatim Apache text, and the licence is declared in the parent
  POM so it reaches SBOMscope's own generated SBOM.
- 2026-07-29 — **Upgrade paths present candidates, not a recommendation.** For a component at
  `x.y.z`: the latest patch on its line, the latest within its major, the latest overall, and
  the earliest version clearing every known critical and high. The first three minimise
  disruption and report what that costs; the fourth names the goal and reports what reaching
  it costs. Where they coincide, saying so is worth more than four rows of numbers.

  **Each candidate carries its own vulnerabilities, not a count of what it clears.** "Clears
  3 of 4" cannot be acted on — which one remains is the whole question, and a candidate that
  leaves a critical behind is not an upgrade path. This is also the design constraint that
  makes R4 unavoidable: a per-candidate advisory list means evaluating versions the user does
  not have, which nothing in the current pipeline can do.
- 2026-07-27 — **`-parameters` is configured explicitly in the parent POM.** Because
  this project imports the Spring Boot BOM instead of inheriting from
  `spring-boot-starter-parent`, none of that parent's build configuration comes along.
  Without the flag, `@PathVariable`/`@RequestParam` cannot recover their own names and
  every such endpoint fails at runtime with a 400 — while parameter-free endpoints keep
  working, which makes it look like a routing problem rather than a compiler setting.
- 2026-07-29 — **The repository went public.** Constraint 8's exception (rewriting
  `V1__baseline.sql` instead of extending it, because the only installations were the
  maintainer's) closes as of this date. Every migration from here on is strictly additive;
  the baseline is not touched again. Recorded in `AGENTS.md` and `docs/ARCHITECTURE.md`.

  It also changes what belongs in the repository at all. Adversarial test fixtures —
  deliberately old, vulnerable dependency versions, built for Phase 8/9 testing — must never
  be committed as a live `pom.xml` or `package.json`: GitHub's dependency scanning reads any
  manifest it finds in a public repo, including test fixtures, and would raise Dependabot
  alerts against SBOMscope's own repository for libraries it does not ship. The generated
  `.cdx.json` this project already commits as test fixtures is not itself a manifest format
  Dependabot parses, so the rule is: build the vulnerable project outside the repository,
  commit only the CycloneDX output it produces.
- 2026-07-29 — **Phase 8 Tier 2 (the Maven probe) built and verified against a real `mvn`,
  not just fakes.** `vuln-multi-module.cdx.json` — a two-module aggregate with old Spring
  Boot, Keycloak at two versions, Netty at two versions, PDFBox and POI — gave 288 real
  findings across 62 components, including `jackson-databind` reached by two independent
  routes (via `keycloak-core` and via `spring-boot-starter-web`) and `keycloak-core`/
  `netty-all` each present at two versions in the one document.

  Live testing found two real bugs the unit tests (fake resolver, no real Maven) could not
  have caught, both fixed the same session: the `maven-metadata.xml` filename gotcha
  recorded above, and a `String.formatted()` operator-precedence bug (`"a %s" + "b".formatted(x)`
  binds the call to `"b"` alone, not the concatenation, leaving a literal `%s` in the
  rendered note). Also confirmed live: the ascending-refinement search correctly exhausts
  its budget and falls back to the already-confirmed candidate rather than guessing past it
  (`spring-boot-starter-web` 2.1.0.RELEASE → 4.1.0 clearing `tomcat-embed-core`, after eight
  ascending patch probes all came back still-affected); a real probe failure
  (`NoPluginFoundForPrefixException`, see the `MAVEN_OPTS` gotcha above) correctly fell back
  to an honest unavailable remedy for that one component without affecting any other.

  Deliberately not built this pass, and not silently dropped: route completeness (routes
  fixed of routes total), naming the blocking component when nothing resolves, and route
  completeness feeding into which remedy gets suggested — all three need an uncapped
  "routes through ancestor X" query `DependencyGraphService` does not yet have, recorded
  as open items in the Tier 2 checklist above rather than attempted approximately.
- 2026-07-29 — **Two Tier 2 designs revised after using it, before building anything further.**
  Both supersede choices made in the first pass earlier the same day; the reasoning is in
  "Tier 2, second pass" above and only the reversals are recorded here.

  **The ascending refinement search is replaced by hierarchical major → minor descent.** The
  first pass walked every known version between the current one and the winning candidate,
  ascending from the bottom — around 200 releases for Spring Boot — so its eight probes never
  left the 2.1.x line that the minor-tier probe had already disproved. Raising the probe count
  was considered and **rejected as a fix**: twelve probes reach 2.1.12, because the candidate
  list is the wrong shape rather than the wrong length. The tier probes' elimination value
  (an affected minor tier rules out the whole major, since the range resolved that major's
  highest release) was being computed and discarded, and now brackets the search instead. The
  descent deliberately stops at the minor line rather than hunting the exact earliest patch:
  the blast-radius difference inside a line is nil, and nobody plans an upgrade to 3.0.7 over
  3.0.0. `[current,)` is kept, reframed as a feasibility probe rather than a candidate — it is
  what made the Keycloak "nothing fixes this" answer cost one probe instead of six.

  **Single-ancestor probing is replaced by whole-module probing.** A generated POM containing
  only the ancestor under test asks what that dependency brings *in isolation*, which is not
  the question. A component reached by two routes appears in the SBOM as one resolved node with
  two parents, and **the SBOM does not record which declaration Maven honoured** — so bumping
  the ancestor that lost nearest-wins changes nothing, and reporting it as a fix would be
  false. Probing the owning module's full direct set, with one dependency moved, makes Maven
  compute route completeness itself rather than having us approximate its resolution rules.
  It also makes the pin's route-completeness demonstrable instead of merely asserted, and
  turns "no single bump works, move both or pin it" into an answer the panel can give.
- 2026-07-29 — **A version range is not a safe way to ask for "the highest release in a major".**
  Found by reading the live verdicts rather than by a failing test. `[3.0.0,4.0.0)` resolved to
  **`4.0.0-RC2`**: Maven compares major versions before qualifiers, so every `4.0.0-<qualifier>`
  outranks every real 3.x release and satisfies the exclusive upper bound. The damage is not that
  a milestone might be recommended — it is that **major 3 was skipped entirely**, which is the
  same defect class as the ascending-walk bug this pass was written to fix, one level down.

  Rejecting pre-release *resolutions* was the first fix and is insufficient on its own: it
  prevents the wrong answer without restoring the missed one. Every tier probe past feasibility
  now takes its candidate from `knownVersions` — which already excludes pre-releases — and probes
  it as an exact `[version]`. The pre-release rejection is kept as a second guard, since the
  feasibility probe is still a range. Measured effect on the fixture: `tomcat-embed-core`'s
  recommendation moved from 4.1.0 (three majors) to **3.5.16** (one).

  `[current,)` survives as the one remaining range because it is open at the top, so nothing can
  leak in from above it, and because it is the only probe that populates the local metadata
  `knownVersions` reads.
- 2026-07-30 — **Tier 2 reports ranked candidates per major line, and the feasibility probe stops
  short-circuiting.** Planned as pass C above; recorded here for the reversal it contains.

  **The short-circuit was unsound.** Treating "the global latest is still affected" as "no version
  fixes this" assumes monotonicity — the exact assumption this design refuses elsewhere when
  rejecting binary search. A newer release can regress where an intermediate one was clean, and
  the fixture demonstrates the shape: `keycloak-core` at 26.7.0 still carries an affected jackson,
  and the search stopped without probing anything between 4.8 and 26.7. The recorded verdict "no
  single ancestor, and no combination, resolves this cleanly" is therefore **unproven, not wrong**,
  and the note above it says so rather than leaving it to be read as evidence.

  **One verdict was also the wrong output shape.** Tier 1 has presented candidates rather than a
  recommendation since it was designed, each carrying its own advisories; Tier 2 collapsing to a
  single winner was inconsistent with that and discarded information it had already paid for —
  every tier probe knows what its version still carries, and the search threw that away as soon
  as it was not perfectly clean.

  **Grouping by major line was chosen over "patch / this major / next major / latest".** "Next
  major" is an arbitrary boundary: at 1.x with a 5.x latest it names 2.x and skips 3 and 4, which
  is the same class of error as the range bug above. Enumerating every major between current and
  latest has no such gap, splits rows along the axis blast radius actually varies on, and makes
  the patch tier disappear as a separate concept — the current-major row *is* the patch answer
  when the fix is nearby. It also subsumes the partial-fix idea raised the same day: with each row
  carrying its remaining advisories, "fewer criticals and highs" is visible and comparable without
  a separate best-so-far mechanism.

- 2026-07-30 — **The probe run budget (max probes, run budget minutes) is user-configurable in
  Settings, not a constant.** The only sound lever for trading completeness for cost — narrowing
  the search space itself (a range standing in for several minor lines) was already rejected above
  as the exact class of bug this design keeps finding. A binary-search-shaped optimisation for the
  minor-line walk was proposed and rejected on the same grounds during this work: a range always
  resolves to its own top, telling you nothing about the minors below it, one level down from the
  major-line version of the same mistake. `MavenToolSettings.maxProbes`/`runBudgetMinutes` replace
  the former hardcoded constants; the Bump section in the UI links to where they live.
- 2026-07-30 — **A Maven profiles setting**, comma-separated, passed to every probe invocation
  exactly as `-P<profiles>` — the same syntax `mvn` itself accepts. Threaded through both the
  `dependency:tree` probe command and the `help:effective-pom` workspace lift-in, not the plain
  `--version` check, which does not depend on profiles. A profile that changes what a dependency
  resolves to (an added repository, a property the resolution depends on) has to be active in the
  probe too, or it answers for a build the user does not actually have.
- 2026-07-30 — **Advisory lists collapsed to a count-by-band with an expandable, CVE-linked
  detail view**, replacing inline GHSA-id lists that ran to dozens of entries for a heavily
  vulnerable library (`AdvisorySummary` in `UpgradePathsPanel.tsx`). Applied uniformly to
  everywhere a remedy names what it clears or still carries — the bump candidate table, both
  remedy cards, and the target's own advisory notice. "Never only a count" still holds: the
  detail view is one click away, never removed, only collapsed by default.
- 2026-07-30 — **A real bug in the Component Inspector, found live and worse than the B1 item
  already described**: navigating away and back — even just to the Activity log via the top nav,
  which carries no purl — reset the whole panel to blank, not only the multi-SBOM case B1 named.
  Two fixes, both session-scoped: `ComponentInspectorPage` remembers the last purl per SBOM
  (`usePersistentState`, restored when the page is reached with no purl in the URL), and the bump
  probe card hydrates from the backend's already-cached progress on mount instead of discarding it.
  The backend was already keeping probe progress correctly (session-scoped, keyed by module and
  target) — the bug was entirely that the frontend never asked. Superseded, not just noted, by
  B1's session-tabs redesign the same day — see B1 for what this patch does not yet cover.
- 2026-07-30 — **Bump probe progress distinguishes QUEUED from RUNNING.** The single background
  thread that runs every probe (deliberate — the isolated Maven repository cannot safely take
  concurrent writes) means a second component's probe started while another is in flight does not
  run alongside it, it waits. Reporting that as RUNNING claimed Maven was being probed right now
  for something that had not started. `BumpProgress` gained a `QUEUED` state, `BumpProbeService`
  tracks which key is actually executing in an `AtomicReference`, and the UI shows a distinct
  "queued behind another probe" message. Became directly relevant once B1's session-tabs
  redesign was in view: several tabs open at once makes starting more than one probe in a
  sitting the normal case, not a corner one.
- 2026-07-30 — **Every `mvn` invocation is captured in full and written to the main log**
  (`MavenInvocation`). Prompted by a report of the probe producing nothing usable on an
  air-gapped machine, with the activity log's one-line-per-probe summary too coarse to diagnose
  from. The command line is logged verbatim so it can be pasted into a terminal and reproduced;
  the whole output is logged at WARN on any failure and at DEBUG on success, so a working setup
  does not write a probe's worth of Maven chatter per candidate. `EffectivePomCache` previously
  discarded its output outright (`Redirect.DISCARD`) and failed silently — the workspace lift-in
  is what makes a supplier's own repository reachable, so losing it is the difference between
  probes that resolve and probes that cannot, and was never something to discover by inference.
- 2026-07-30 — **The probe could hang forever, with the timeout unable to fire.** The old runner
  read stdout to EOF, then stderr, then called `waitFor`. A child that fills the stderr pipe
  buffer (4–64 KB) blocks writing to it, so it never closes stdout, so the read never returns and
  `waitFor` is never reached — and because probes are serialised on one thread, one hang stalls
  every later probe for the life of the process. An air-gapped Maven emits a "Could not transfer
  artifact" block per artifact and reaches that buffer easily, so this is a prime suspect for the
  original report. Fixed by merging stderr into stdout (nothing distinguished them — both call
  sites concatenated them before looking) and enforcing the timeout with a watchdog that destroys
  the process, since killing the child is what actually unblocks the read.
- 2026-07-30 — **Plugin goals are version-pinned rather than invoked by prefix.**
  `dependency:tree` made Maven fetch the plugin group's `maven-metadata.xml` to resolve the
  prefix, then take the plugin's *latest* version: an avoidable round-trip, the literal source of
  `NoPluginFoundForPrefixException`, and a probe whose behaviour could change month to month with
  nothing changed locally — unacceptable for a tool whose output is meant to be reproducible. Now
  `maven-dependency-plugin:3.6.1:tree` and `maven-help-plugin:3.4.0:effective-pom`. **This does
  not make the plugin obtainable where it is not already.** A further argument that only surfaced
  afterwards: a pinned version makes the probe's plugin requirements a *finite, knowable set*,
  which is what makes seeding `probe-repo` from a connected machine possible at all — with
  "latest" you cannot pre-seed, because you do not know what it will ask for.
- 2026-07-30 — **The pinned plugin versions are user-configurable**, after the risk above was
  raised: a curated mirror proxying an approved subset of Central may not carry the pinned
  version, and on such a machine the feature would be unusable with no way to say so. Which
  version exists is a fact about the user's repository, not about SBOMscope — the same reasoning
  as pointing at your own `mvn` and naming your own profiles. Blank resets to the shipped default
  rather than being rejected, so clearing the field is a safe undo, and the panel shows the
  concrete version in use so there is something to change *from*. Validated against
  `VERSION_PATTERN`: the value is interpolated into a colon-separated goal coordinate, so a stray
  colon or space would not merely be invalid, it would change which goal Maven runs.
- 2026-07-30 — **`PLUGIN_UNAVAILABLE` split out of `NOT_FOUND`.** Maven failing to obtain its own
  plugin says nothing about the component being probed, and reporting it as "not found in any
  configured repository" sent the reader to fix the wrong thing.
- 2026-07-30 — **A cut-short major says so** (`BumpCandidate.higherReleasesUnchecked`). Budget
  exhaustion partway through a major used to report `probed=true` with whatever version it
  stopped at, making *"the highest 2.x still carries this"* indistinguishable from *"we got as
  far as 2.7.18 and stopped"* — the first is a verdict on the whole major, the second says
  nothing about what sits above it. The same unproven-versus-disproven distinction the
  feasibility short-circuit was removed for, one level down. Never set where the walk stopped on
  finding its earliest clean release: ascending order makes that a complete answer.
- 2026-07-30 — **An incomplete search can be continued rather than re-run.** Needed no new search
  logic: `rankMajor` already takes a `startAfterMinor`, which is exactly a resume point, so a
  cut-short major picks up above the version it stopped at and an unreached one starts from
  scratch. Settled rows cost nothing, and calibration and feasibility are not repeated — the
  model was validated on the first run, settings cannot have changed without clearing this cache,
  and the existing rows already enumerate every major. Each press takes a **fresh** budget, so it
  means "spend another run's worth on this" and can be pressed repeatedly.
- 2026-07-30 — **Two dead ends in the bump panel, both reported live.** With Maven unconfigured
  the probe is refused, and the panel hid its button as soon as any result existed — so someone
  who followed the Settings link, configured Maven and came back could not ask again short of
  restarting the application. Separately, a run that completed with no rows was returned from
  cache forever, escapable only by changing a setting to clear the cache as a side effect. Fixed
  together: the button is offered whenever there is nothing actionable (never started, refused,
  or completed without ranking anything), and continuing a run that ranked nothing starts it over
  rather than replaying it, since there is nothing to preserve.
- 2026-07-30 — **Recording an action must never be able to fail the action.** `ActivityLogger`
  called `mapper.writeValueAsString` unguarded, and Jackson 3's `JacksonException` is unchecked —
  so a serialisation failure would have propagated into whatever was being recorded, aborting a
  scan, an upload or a probe because the *note about it* could not be written. Now caught and
  degraded to the prose log. Found while reviewing the commit rather than by failing.
- 2026-07-30 — **"Test Maven" verifies the plugins, not just the binary.** It ran `mvn --version`,
  which on the air-gapped machine reported a perfectly good *Apache Maven 3.9.16* while every
  probe failed — a green tick that sends the reader looking for the problem everywhere except
  where it is. It now also runs both configured goals against a throwaway empty project in the
  real `probe-repo`, so green means the exact invocations a probe makes have been made once and
  worked. The Maven version is still reported when the plugin check fails, because "Maven runs
  but its plugins cannot be obtained" and "that is not Maven" need different fixes.
- 2026-07-30 — **Measured, on the maintainer's own Maven 3.9.16**, while answering "won't a
  correctly configured Maven just use `~/.m2`?": **no.** `-Dmaven.repo.local` *overrides* the
  local repository, so `settings.xml` still supplies mirrors and credentials but `~/.m2`'s
  contents are not consulted at all. With a reachable mirror the plugin downloads into
  `probe-repo` — which is why this works on an ordinary machine and fails air-gapped.
  A candidate fix was tested directly, offline, with an empty local repository:

  | Case | Result |
  |---|---|
  | no tail | `PluginResolutionException` |
  | `-Dmaven.repo.local.tail=~/.m2/repository -Dmaven.repo.local.tail.ignoreAvailability=true` | exit 0 |
  | files written into `~/.m2` by the tail run | **none** |

  So the tail reads through to `~/.m2` without writing to it, which preserves the entire reason
  the isolation exists — no `.lastUpdated` poisoning of a real build. **It is not a complete
  answer on its own**: it only surfaces artifacts genuinely present in `~/.m2`, and the
  maintainer's own `~/.m2` had *no* `maven-dependency-plugin` jar, only a failed-download
  marker — unsurprising, since the plugin is not part of an ordinary build lifecycle. A working
  air-gapped setup therefore needs the tail *and* a one-time seed of the pinned plugins while
  connected. Both halves are now cheap: pinning made the required set knowable, and "Test Maven"
  performs exactly the invocation that would seed it.
- 2026-07-30 — **The Inspector's open components are session state above the router, not a
  preference** (B1). Three candidate homes, and the choice follows from the bug rather than
  from taste: inside the page it cannot survive its own unmount, which *is* the bug; in
  localStorage it outlives a restart, and which libraries you had open is where you were in a
  session, not how you like to work — reopening yesterday's tabs is clutter, not a courtesy.
  `useState` in `SbomProvider` is above the router, so it survives every route change, and
  loses everything on restart, which is correct. It is also the simplest of the three.

  **Keyed per SBOM, `Record<sbomId, {open, active}>`.** This is what makes "switching to an
  SBOM that does not contain the selected component" stop being a case at all: that SBOM's own
  tabs are what you see, empty for one never opened this session. The former patch's
  single-purl map is removed rather than kept underneath, and its localStorage key is deleted
  on mount so it does not sit orphaned in every browser that ran that build.

  **The URL still names the active tab.** `?purl=` stays the source of truth for what is shown,
  so a refresh works and every "Inspect" link elsewhere stays a plain link; the tab list is
  what remembers, and the two are reconciled in one direction only — the list feeds the URL
  when the page is reached without one, never the reverse. A purl the SBOM does not contain is
  a 404 the page swallows deliberately: it clears the parameter and falls back to that SBOM's
  tabs, because "not in this document" is a different document, not a failure worth rendering.

  **A tab is opened only after its component loads.** Opening on navigation would let a stale
  purl put a tab in the strip that cannot be opened — the strip would then be advertising
  something the document does not have, which is the failure mode this item exists to remove.
- 2026-07-30 — **Tab labels carry the version, reversing B1's "the artifact name" wording.**
  The item's reasoning — the identity panel already carries the full purl, so the strip does
  not need the group — is right about the group and wrong about the version. This project's own
  adversarial fixture exists *because* one aggregate BOM routinely holds the same library at two
  versions across modules, and comparing exactly those two is a headline reason to want tabs at
  all; two tabs both reading `jackson-databind` would have made the feature useless for its best
  case. Caught by a verification step selecting the wrong tab, not by reading the code.
- 2026-07-30 — **Tier 2 pass D: the panel must say which library it is bumping, and which
  declaration decides.** Three observations from real use, and the middle one turned out to be a
  correctness problem rather than a labelling one.

  **The ancestor was chosen by the wrong criterion.** `distinctAncestorsInPrimaryModule` takes the
  ancestor on the shortest SBOM route; Maven resolves by depth in the *resolved* tree. Pass B
  already established the consequence — bumping the declaration Maven did not honour moves
  nothing — but the search was still picking by route length and the panel never named its choice,
  so a reader saw a bump that changed nothing and could not tell a losing declaration from an
  upstream that had not fixed the problem.

  **The fix costs no probes at all, which is why it is worth doing now.** `dependency:tree` already
  runs with `-DoutputType=text` into a file this code reads; `findVersion` scans it for a matching
  line and discards the indentation, **which is precisely the parent chain**. Parsing depth names
  the deciding direct dependency authoritatively from a probe already performed. It also retires
  the reason two other items were deferred: naming the blocker when nothing resolves, and stating
  which module an answer holds for, were both waiting on provenance that was being thrown away.

  **Rank the decider only, and name the others.** Ranking every declaring ancestor splits one
  fixed budget N ways, so each ranking becomes budget-truncated — the failure
  `higherReleasesUnchecked` exists to report — while buying nothing, since only one declaration can
  change the outcome. The others are listed with *why* bumping them alone would not help, which is
  information the panel has never carried. Combination testing stays the coarse fallback it is.

  **Across modules: state it, do not probe it.** This closes the question left open in pass B.
  Probing every owning module multiplies the budget by the module count, and for a library in
  every backend module that is several full runs; the missing half was never the coverage, it was
  saying which module the answer was verified against.

  **Status becomes the worst remaining severity** rather than a critical/high binary — more
  information and one concept fewer, since "still MODERATE" already says critical and high are
  clear. Derived in the frontend from the same array rendered beside it, so the chip cannot
  disagree with the list. An unrated remaining advisory shows as unrated and never as clean, which
  is the `NONE`-versus-`CLEAN` rule applied one level further down.
- 2026-07-30 — **An unmapped `/api/…` path answered 500, not 404.** Found in passing while
  checking settings during the B1a work. `NoResourceFoundException` **implements
  `ErrorResponse` but does not extend `ResponseStatusException`**, so the handler that exists
  precisely to stop deliberate 404s becoming 500s did not cover it, and every mistyped API URL
  produced a server error with a stack trace in the log.

  It also contradicted a property ARCHITECTURE.md states outright: unknown non-API paths are
  forwarded to `index.html` so a deep link survives a refresh, while `/api/` ones deliberately
  still fail — *so that a mistyped fetch URL fails as a missing endpoint rather than as an HTML
  parse error*. That only holds if the failure is a 404, and it was not.

  Now handled explicitly and covered by `ApiExceptionHandlerTest`, which also pins the older
  `ResponseStatusException` case and the SPA fallback's non-API behaviour. The test exists
  rather than a line in an existing one because this is the **second** exception type to fall
  through the same gap; the lesson recorded in AGENTS.md is to check what an exception extends
  rather than what its name suggests.
- 2026-07-30 — **The probe queue becomes visible and stoppable, and the Log tab becomes
  Monitoring** (B1a). Raised by B1: a probe outlives its tab by design, and the tab cap means the
  application can now close one, so a run could be left holding the single probe thread with no
  route back to it. The premise needed sharpening first — it was never an *orphan*: it is
  tracked, it finishes, its result is cached, and reopening the component rehydrates it. What was
  missing was an address and a stop.

  **Three sub-tabs rather than a fourth nav item**: processes, activity log, full log. The full
  log had never been surfaced at all — the previous session made the probe diagnosable by writing
  every `mvn` command and its whole output to `sbomscope.log`, then left the only route to it an
  "Open folder" button, which is no route on a machine where the browser and the file manager are
  not both to hand.

  **Stopping is expressed as budget exhaustion.** `SearchBudget.exhausted()` is the one checkpoint
  every level of the search consults, and every level already reports what it did not reach, so a
  stopped run is a cut-short run and `continueRun` resumes it with no new logic. Two corrections
  fell out of building it. Killing the `mvn` in flight makes *that invocation* fail, so a run
  stopped during calibration ended by reporting its own kill as "nothing resolves this cleanly" —
  a confidently wrong answer manufactured by the act of stopping it; `BumpProgress.stopped()` now
  discards that remedy and keeps the verdicts and settled rows, which were true before the stop.
  And the note has to be applied where every exit path passes through, not at each completion
  point, because a stop lands on whichever path the run happened to be on.

  **Auto-cancelling on tab close was considered and rejected.** B1 deliberately made the tab a
  view of backend state rather than its owner; auto-cancel would discard minutes of real Maven
  work because somebody tidied their tabs, or because the cap evicted one. Explicit only.

  **Finished runs are kept for the session, bounded at 25** (added on request, same day).
  "Did that thing I started actually do anything" is asked immediately after a run ends, and a
  list that empties itself at that moment answers with silence. `STOPPED` is distinct from
  `COMPLETED`: a run cut short and one that reached the end of its budget are different claims
  about how much of the search happened. Persistence across restarts is in the backlog, not here.
- 2026-07-30 — **`destroyForcibly()` was killing the wrapper and leaving Maven running**, and
  this was a live defect in the timeout watchdog before cancellation existed to expose it. On
  Windows the configured executable is `mvn.cmd`, a batch wrapper whose real work is a `java`
  grandchild; `Process.destroyForcibly()` terminates the named process and nothing beneath it.
  Confirmed by observation rather than inference — the live tree during a probe is `sbomscope
  java.exe → cmd.exe → java.exe`, and after a stop both the wrapper and the grandchild were gone
  while the next queued probe started its own. Descendants must be taken **first**: destroying
  the parent reparents them and the handle to walk from is gone. Implementing Stop without this
  would have manufactured precisely the orphaned process the feature was asked for to prevent.
- 2026-07-30 — **The Inspector's tab strip is capped at ten with LRU eviction, and scrolls
  rather than wraps.** Asked as "will too many tabs make it slow"; the performance half of that
  is not real — only the active tab's panel is mounted, so the others are list items — and
  saying so was worth more than agreeing. What *is* real is height and navigation.

  Wrapping was the original shape and had to go: rows two and three take height from the panel,
  which is precisely why the identity block was moved out of that column. One non-wrapping row,
  tabs shrinking to a floor and then scrolling, is what browsers do and it holds the strip at a
  measured constant 44px. The cap is IntelliJ's and VS Code's, at their usual default of ten,
  evicting the **least recently active** rather than the oldest opened — otherwise the tab you
  keep coming back to is the one that goes.

  **Eviction is silent, which needs the justification it does not obviously deserve** in a
  project that reports budget exhaustion rather than disguising it. The difference is that a tab
  holds nothing: panels re-fetch per (sbom, purl) and a probe's progress is backend state keyed
  by module and target, so closing a tab neither stops a probe nor loses its answer. Nothing
  went undone, so there is nothing to report.

  **Three attempts at revealing the active tab, and the first two were wrong in ways only
  measurement showed.** `scrollIntoView` left the tab 15px clipped *and* can scroll every
  ancestor, which on a long dependency tree means yanking the page. Moving the arithmetic into a
  `requestAnimationFrame` fixed the clipping and introduced a worse fault: rAF does not fire
  while the page is hidden — verified directly, `visibilityState` 'hidden' and the callback
  never ran — so a tab opened in a background browser tab stayed out of view. `useLayoutEffect`
  runs whatever the visibility. Two further faults came out of the same testing: the effect must
  depend on the **tab list**, not the active purl, because a not-yet-open component is appended
  only after it loads and the purl has stopped changing by then; and the strip must re-check
  when the panel below finishes loading, since the page gaining a vertical scrollbar takes
  ~15px off the column and clips the tab that was flush a moment earlier. A `ResizeObserver`
  covers reflows nothing announces, but it is **not** the fix for that one — it does not fire
  while hidden either, so the load is passed in as an explicit dependency and the observer is
  left to cover the window resizing and the sidebar collapsing.
- 2026-07-30 — **VEX becomes Phase 11, and is deliberately not "download the VEX database".**
  Raised from outside the plan. The research answer that shaped it: **there is no OSV-shaped
  universal VEX corpus and there structurally cannot be one.** OSV downloads whole because an
  advisory is a fact about a package, true for everyone holding it; a VEX statement is a
  supplier's assertion about their own build, and upstream OSS projects almost never publish one
  about themselves. For an ordinary Maven or npm tree there is simply nothing to fetch, so a
  "VEX feed" setting modelled on the OSV one would be a feature with no data behind it.

  Two halves, and **the smaller one is the more valuable**. Tier A reads a VEX document the user
  was handed — no feed, no network, no new policy — and is the common case: a supplier ships
  one, or a security team records a triage decision once instead of re-making it monthly. Tier B
  is Red Hat's CSAF VEX, the one genuinely bulk corpus worth having, and it earns its place by
  landing on B2 rather than by being large: Red Hat's Maven rebuilds are exactly B2's
  vendor-patched `a.b.c.d` artifacts, and for those OSV describes the *upstream* artifact while
  Red Hat's VEX describes the one actually installed.

  **Constraint 6 was checked and does not forbid this, which is worth recording because it looks
  like it does.** The constraint bans manual judgment *fields* — a comment box, a "mitigated?"
  tick — because those make SBOMscope the system of record for opinions it cannot check and
  drag in an annotation store. A VEX document is a standard-format artefact carrying its own
  author and timestamp, no different in kind from an OSV advisory. The boundary is sharp and
  must stay so: **SBOMscope reads VEX and never offers a UI for authoring one.** The moment a
  user can type a justification into our screen, constraint 6 is broken and this argument is no
  longer available.

  **The suppression rules are the reason it is a phase and not a bullet.** VEX hides findings,
  and a security tool that conceals something because a document said so needs the discipline
  applied everywhere else here: never delete, only mark; always show the suppressed count;
  always name the author, because `not_affected` is a claim and not a fact; and treat a
  statement made against an older version as stale rather than as an answer. Ordered below
  Phase 3 and B2; Tier A can move up alone the moment a real VEX document exists to test with.
- 2026-07-30 — **Open, needs a decision: the isolated probe repository cannot work air-gapped.**
  `~/.sbomscope/probe-repo` starts empty and `dependency:tree` needs the dependency plugin and
  its transitive dependencies from somewhere; the user's own `~/.m2` has them, and the isolation
  deliberately never touches it. On a machine with no route to any repository there is nowhere
  for them to come from, so *every* probe fails at plugin resolution regardless of anything else.
  The `NoPluginFoundForPrefixException` note in AGENTS.md documents the networked version of this
  and blames TLS interception. **Not decided — the isolation was a deliberate choice and changing
  it is the maintainer's call.** Given the tail measurement above, the leading candidate is now
  *tail-to-`~/.m2` plus a one-time seed of the pinned plugins while connected*, which keeps the
  isolation intact rather than reversing it; the alternatives (copying into `probe-repo`, or
  simply using `~/.m2` and accepting the poisoning risk) remain open. What is still unknown is
  whether the reporting machine is truly network-isolated or merely has no route to Central while
  reaching an internal mirror — the latter needs no change at all, and the new "Test Maven"
  plugin check answers that in one click.
