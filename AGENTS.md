# AGENTS.md

Guidance for AI coding agents working in this repository.

## What this project is

SBOMscope is a local-first SBOM analysis tool: upload a CycloneDX SBOM, get known
vulnerabilities, whether the code actually uses the vulnerable libraries, upgrade
paths, and an Excel export.

Start here, in this order:

| Document | What it holds |
|---|---|
| [README.md](README.md) | What the product is, and how to build and run it |
| **This file** | Constraints you must not break, conventions, and the working loop |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Data model, key flows, and the osv-scanner and Maven-probe contracts |
| [docs/IMPLEMENTATION-PLAN.md](docs/IMPLEMENTATION-PLAN.md) | What is built, what is next, and the decision log explaining why |

The decision log is the important one. Several designs in this codebase look
unnecessarily careful until you read why they are that way; it also records reversals,
so a rejected idea does not get re-proposed.

## Tech stack

- **Backend**: Spring Boot 4.1.x on Java 21 (LTS) — the local server process. 21 is a
  floor, not a ceiling: it builds and runs on newer JDKs, but nothing may rely on a
  feature above 21, or the build breaks on the restricted machines this is aimed at.
- **Frontend**: React + Vite, packaged into the backend jar and served from it.
- **Build**: Maven multi-module (parent + `frontend` + `backend`), one command
  producing a single runnable jar. Node 22.12+ and npm are expected on the PATH —
  the build does not install its own copy. The minimum is declared in
  `frontend/package.json` under `engines`.
- **Storage**: embedded H2. No external database.
- **Schema migrations**: Flyway, versioned SQL under
  `src/main/resources/db/migration`.
- **Excel export**: Apache POI (`poi-ooxml`, version pinned in the parent POM).
- **Vulnerability data**: OSV, via the osv-scanner binary invoked as an external
  process, reading a locally-downloaded OSV database. CISA KEV and EPSS are planned;
  the NVD API is deliberately not used (constraint 4).
- **Upgrade paths, Tier 2**: for a question the offline OSV data cannot answer, the user's
  own `mvn` is invoked as an external process (never downloaded) to resolve a real
  dependency tree. See "External tool contract: the Maven probe" in
  [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Hard constraints

These are architectural commitments, not preferences. Do not violate them without
raising it with the maintainer first.

1. **Offline-capable by default.** Every analysis path must produce an *honest* answer on a
   machine with no internet access, using only locally-cached data — narrower than the online
   one where it has to be, never silently wrong. No feature may require the network in order
   to say something true.

   Network access falls into three categories. **The line between them is what the traffic
   reveals about the user, not whether traffic happens** — "SBOMscope makes no network calls"
   would be a simpler claim and a false one, since it downloads the OSV archives itself.

   1. **Executable code — never fetched by us.** osv-scanner is placed by the user and
      pointed at from Settings. A supply-chain tool that downloads and runs somebody else's
      binary on your behalf has the wrong default, whatever the convenience.

   2. **Bulk public data — fetched by us, only when asked.** The OSV archives today; CISA KEV
      and EPSS when Phase 3 lands. One fixed URL, shown in the UI, no credentials, downloaded
      whole. Requesting *every* Maven advisory discloses nothing about which libraries you
      have — which is exactly why it can be a whole-archive download, and why it can be
      carried across on a USB stick to a machine with no network at all.

   3. **Anything specific to the user's dependencies — delegated, never asked directly.**
      "Which versions of `com.acme:internal-billing` exist" identifies that artifact as
      something you use. SBOMscope does not ask that of anyone. It invokes a build tool the
      user configured, which asks through *their* mirror with *their* credentials, over a
      channel their build already uses routinely — so no new disclosure is created and no
      credential is ever held here.

   Nothing in categories 2 or 3 is ever automatic, and both are written to the activity log.
   A direct outbound query about a specific artifact belongs to category 3 and must not be
   added to category 2 by convenience; that boundary was crossed once on 2026-07-29 and
   reverted the same day.
2. **Never *fetch* vulnerability data automatically — analysing it is a different act.**
   The original wording forbade background jobs, refresh-on-startup and refresh-on-upload
   outright, and was reworded on 2026-07-29 once the distinction it was reaching for became
   clear.

   **Fetching stays strictly on request.** Downloading an OSV archive, or anything else that
   leaves the machine, happens only when the user asks. No timers, no refresh-on-startup, no
   "while we're here".

   **Analysing may happen on its own**, because it costs nothing that anyone needs to
   consent to: running osv-scanner against an archive already on disk sends nothing anywhere.
   A newly uploaded SBOM is scanned automatically, and at startup components with no scan
   record are scanned in the background — *after* the application is serving, so launch is
   never delayed, one at a time, and only where the scanner is configured and its archive
   present. Every such run is written to the activity log, because it starts an external
   process.

   The line is the same one constraint 1 draws: **what leaves the machine, not what the CPU
   does.**
3. **Never commit secrets.** Any credential is read from an environment variable or a
   git-ignored local config file, never from the database and never from a committed
   file. Only templates and placeholders are committed. There are no secrets today —
   keep it that way unless a feature genuinely requires one.
4. **Vulnerability data comes from OSV, via osv-scanner.** The NVD API is deliberately
   not used: it contributes to no column SBOMscope displays. CVE cells link to
   nvd.nist.gov, which needs no API. Do not reintroduce it without a concrete need, and
   note that redistributing NVD data carries attribution obligations that linking does
   not.
5. **No new heavyweight external engines** without checking they can run in a
   locked-down environment: no admin rights, no installer, no mandatory outbound
   network calls. A single static binary is the bar to beat.
6. **No manual/judgment data fields.** The vulnerability table shows only what we can
   populate from a real data source. Users add their own notes in Excel post-export.
   This is deliberate — it keeps an annotation-persistence layer out of the product.
7. **Target ecosystems are Maven and npm.** Don't generalize prematurely to other
   package ecosystems.
8. **Schema changes go through Flyway migrations.** Never enable Hibernate auto-DDL
   (`ddl-auto` stays `validate` or `none`). The local database holds user data that has
   to survive an application upgrade, so schema evolution must be explicit, reviewable
   and repeatable — not inferred from entity mappings at startup.

   **The repository is public as of 2026-07-29. Migrations are strictly additive from here
   on** — never edit or squash a shipped migration, including `V1__baseline.sql`, because
   somebody else's data may already be on the other end of it. Before that date, while the
   only installations were the maintainer's, the baseline was rewritten instead of extended
   (V1–V4 squashed once, see the decision log) — that exception no longer applies and must
   not be reused.
9. **Keep the dependency tree lean.** SBOMscope's own SBOM is a credibility statement,
   and every transitive dependency is a vulnerability someone has to triage. Justify new
   dependencies; prefer the standard library or a few lines of our own code over a
   library that solves a problem we only partly have.

## Working agreement

- **This is a collaborative project.** The maintainer wants a say in design decisions.
  When you hit a genuine fork in the road — an architectural trade-off, an ambiguous
  requirement, a decision that would be expensive to reverse — ask rather than picking
  silently. Conventional defaults and obvious choices don't need a question.
- **Push back when warranted.** If a requested approach has a real problem, say so with
  the evidence. The dual-NVD-channel design in the decision log was rejected this way,
  and that was the right outcome.
- **Keep the implementation plan current.** When you complete an action item, check it
  off. When work reveals a new task, add it. When a design decision is made, append it
  to the decision log in that file with the date and the reasoning — including
  decisions that were reversed and why.
- **Verify before claiming.** If tests fail or a step was skipped, say so plainly with
  the output. Don't report work as done that hasn't been checked.
- **Never commit. The maintainer commits.** Leave finished work in the working tree and
  say what changed; the maintainer runs their own checks first and writes the commit
  themselves. Staging with `git add` is fine. Anything that rewrites history or touches a
  remote is not.

## Conventions

- Match the surrounding code's style, naming, and comment density rather than importing
  external conventions.
- Keep the backend's engine integrations behind interfaces — OSV-Scanner is invoked as
  an external process today, but a JVM-embedded reachability engine is a plausible
  future addition, and the call sites shouldn't care.
- Cache entries carry a last-refreshed timestamp. Anything reading cached vulnerability
  data must be able to surface staleness to the UI.

## Repository layout

```
pom.xml                 parent: module list, dependency and plugin versions, -parameters
frontend/               React + Vite UI
  vite.config.ts        build output goes to target/classes/META-INF/resources,
                        and /api is proxied to :8080 during development
  src/
    api/client.ts       fetch wrapper, response types, query/export URL building
    components/         shell pieces, settings panel, purl display helpers
      SearchField.tsx   the one search box: regex toggle, negation toggle, and how a rejected
                        pattern is reported. Four fields use it, and the meaning of those
                        controls is the same claim in all four — copies would be four places
                        for it to drift
    pages/              one component per route
    sboms/              SbomProvider: uploaded SBOMs, the current selection, and the
                        Component Inspector's open tabs per SBOM — in-memory above the
                        router, so they survive navigation but deliberately not a restart
    findings/           severity-band and CVE-link presentation shared by several views
    state/              usePersistentState/usePersistentToggle: localStorage-backed state
                        that survives navigation and reload (tab selection, sidebar width)
    theme/              ThemeProvider: light/dark/system resolution
    styles/             tokens.css holds every colour; app.css holds layout
backend/                Spring Boot application, produces the runnable jar
  src/main/java/dev/sbomscope/
    api/                REST controllers and the exception handler
    config/             web and infrastructure configuration
    export/             Excel writing and public registry links
    sbom/               CycloneDX parsing, storage, uploaded-document store
    scanner/            osv-scanner integration, OSV database, findings
    probe/              the Maven probe (Phase 8 Tier 2) — see ARCHITECTURE.md
    settings/           user-editable settings
    logging/            the activity log (~/.sbomscope/logs/activity.jsonl) and the
                        bounded, rotation-safe tails the Monitoring page reads
    maintenance/        the purge/erase-local-data feature
  src/main/resources/
    application.yml     committed config
    db/migration/       Flyway migrations, V<n>__<description>.sql
  src/test/resources/sboms/   real fixtures (see Testing below)
docs/ARCHITECTURE.md    data model, flows, external tool contract
docs/IMPLEMENTATION-PLAN.md  roadmap, risks, decision log
```

## Working loop

```bash
mvn clean package
```

builds both modules, runs the frontend typecheck and all backend tests, and produces
`backend/target/sbomscope.jar`.

```bash
java -Djavax.net.ssl.trustStoreType=Windows-ROOT -jar backend/target/sbomscope.jar
```

runs it on <http://localhost:8080>. The truststore flag is needed on Windows machines
whose security software inspects HTTPS — without it the OSV database download fails with
a PKIX error. See the README troubleshooting section.

Things that will bite otherwise:

- **Stop the running application before rebuilding.** Windows holds a lock on the jar and
  `mvn clean` fails with *"Failed to delete … sbomscope.jar"*. The same applies to any
  shell whose working directory is inside `target/` — including one left there by an earlier
  command, since the working directory persists between them.
- **Scratch files belong in `backend/target/`**, which is git-ignored and wiped by
  `clean` — not in a system temp directory.
- **`mvn test` without `clean` runs against stale resources.** Deleting a migration removes it
  from `src/` but not from `target/classes`, so Flyway keeps applying the old one and fails
  with errors that describe a schema nobody wrote. Use `clean` after touching anything under
  `src/main/resources`.
- **`MAVEN_OPTS` is not set in a fresh shell** despite the `setx` in the README, and PowerShell
  splits `-Djavax.net.ssl.trustStoreType=Windows-ROOT` at the first dot unless it is quoted.
  Both surface as a PKIX or "unknown lifecycle phase" failure that has nothing to do with the
  build.
- **Never rewrite source files with a PowerShell regex pass.** PowerShell 5.1 reads as ANSI, so
  a round-trip mangles every non-ASCII character and adds a BOM. Edit the file properly.

## Testing

Tests run against **real fixtures produced by the real tools**, not hand-written samples,
so they exercise the quirks those tools actually emit. All live in
`backend/src/test/resources/sboms/`:

| Fixture | Produced by |
|---|---|
| `maven-sbomscope.cdx.json` | `mvn org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom` — CycloneDX 1.6, 61 components |
| `npm-frontend.cdx.json` | `npm --prefix frontend sbom --sbom-format cyclonedx` — CycloneDX 1.5, 29 components |
| `osv-report-maven.json` | osv-scanner v2.4.0 scanning the Maven fixture |
| `vuln-multi-module.cdx.json` | An adversarial two-module Maven aggregate (see below) — CycloneDX 1.6, 62 components |

They are SBOMscope's own dependency trees, so regenerating them keeps the tests honest as
the project changes. Integration tests use an in-memory H2 built by the same Flyway
migrations as production, so the migrations are covered too.

**A different category: adversarial fixtures.** Testing richer scenarios — several critical
findings at once, the same library at two different versions across modules — needs an SBOM
built from deliberately old, vulnerable dependencies, which is not SBOMscope's own tree.
**Never commit the `pom.xml`/`package.json` that produces one.** The repository is public, and
GitHub's dependency scanning reads any manifest it finds, including test fixtures — a
committed pom declaring an old Keycloak or Netty would raise Dependabot alerts against
SBOMscope's own repository for libraries it does not ship. Build the throwaway project
outside the repository, and commit only the `.cdx.json` it produces — inert test data, not a
manifest format anything scans.

`vuln-multi-module.cdx.json` is the first: a two-module Maven aggregate (`module-a`,
`module-b`), never committed itself. `module-a` declares `spring-boot-starter-web
2.1.0.RELEASE` (dragging in old Jackson and `tomcat-embed-core`), `keycloak-core
4.8.3.Final` and `netty-all 4.1.42.Final`; `module-b` declares `pdfbox 2.0.4`, `poi-ooxml
3.17`, `keycloak-core 9.0.3` and `netty-all 4.1.68.Final`. `keycloak-core` and `netty-all`
each therefore appear at two different versions in the one aggregate BOM — the cross-module
version diamond Phase 8's route-completeness and bump-probe logic need a real case for.
Regenerate with `mvn org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom -DoutputFormat=json`
against the throwaway project if the scenario needs to grow.

**Tests must be isolated from `~/.sbomscope` in full, not just the database.** The in-memory
datasource only covers half of it: uploads also write documents through `SbomFileStore`,
which defaults to the user's real data directory. That leaked stray files for a while and
then became destructive, because `StoredDocumentSweeper` starts with every Spring context,
sees an empty `sbom` table and deletes every document it finds — so running the suite erased
real uploads. `sbomscope.data-directory` is overridden in `src/test/resources/application.yml`
for that reason; if a test needs local storage, point it there too.

Verify UI work in the browser rather than assuming: check the console for errors and read
the rendered DOM. Note that synthetic clicks from automation tooling do not always
register with React — dispatching a real DOM `click()` is more reliable.

**Anything driven by the rendering loop does not run in a hidden browser tab, and an automation
pane usually counts as hidden.** `requestAnimationFrame` callbacks and `ResizeObserver`
deliveries simply never fire while `document.visibilityState` is `'hidden'` — verified directly
here, an explicit width change produced zero observer callbacks. Two consequences. Code that
positions something must not depend on them: `useLayoutEffect` runs regardless of visibility and
is the right primitive for measure-then-adjust. And when a check like that appears to fail, test
whether the *mechanism* fires at all before concluding the code is wrong — an hour went into a
correct implementation that could not be observed.

**The same applies to `prefers-color-scheme`.** Switching the pane's emulated colour scheme
moves `matchMedia(...).matches` but fires **no `change` event** — a freshly registered listener
recorded zero events across a flip the query itself reported. Reload under each scheme to check
what a component reads at mount; live tracking cannot be observed here at all. Note also that
`window.matchMedia()` returns a **new** `MediaQueryList` each call, so dispatching a synthetic
event on your own instance never reaches the listener the component registered.

**Check that an activation actually changed something before concluding a handler is broken.**
Two "bugs" in one session were tests clicking an element that was already active, so the state
never changed, so the effect never re-ran. Assert the precondition, not just the outcome.

**Hard-refresh after rebuilding, or you will verify the previous build.** The jar serves the
bundle as static content and the browser caches `index.html`; a plain reload can render the
old UI while reporting success. A cache-busting query string is enough.

**Measure layout claims rather than eyeballing them.** `getBoundingClientRect` on the blocks
above the table answers "did this actually save space" in a way that survives disagreement —
the severity summary went through two designs before the numbers showed which one was right.

## Gotchas worth knowing

- **Spring Boot 4 splits autoconfiguration into per-integration modules.** Adding a
  library alone is not enough to activate it. `flyway-core` on its own put Flyway on
  the classpath while silently never running a single migration — the application
  started perfectly and the schema was simply never created. Use the matching
  `spring-boot-starter-*` (or `spring-boot-<integration>`) module, and verify the
  integration actually ran by checking the startup log rather than assuming.
  Packages moved too: MockMvc's `@AutoConfigureMockMvc` now lives in
  `spring-boot-webmvc-test` under `org.springframework.boot.webmvc.test.autoconfigure`.
  When an import goes missing, find the class in the local Maven repository
  (`jar tf` over `~/.m2`) rather than guessing at the new coordinates.

- **Spring Boot 4 uses Jackson 3.** Core classes moved from
  `com.fasterxml.jackson.databind` to `tools.jackson.databind`, and `JacksonException`
  is now an unchecked `RuntimeException` — so `readValue` declares no checked exception
  and catching `IOException` around it is a compile error. Annotations are the
  exception to the rename: `@JsonProperty` and friends stay at
  `com.fasterxml.jackson.annotation`.

- **`-parameters` is set explicitly in the parent POM — leave it there.** This project
  imports the Spring Boot BOM rather than inheriting `spring-boot-starter-parent`, so it
  gets dependency versions but none of that parent's build configuration. Without the
  flag, Spring cannot bind `@PathVariable`/`@RequestParam` without an explicit name and
  those endpoints return 400 at runtime, while parameter-free endpoints keep working —
  which reads like a routing bug rather than a compiler setting.

- **Do not let `@ExceptionHandler(Exception.class)` swallow `ResponseStatusException`.**
  A catch-all advice without a more specific handler turns every deliberate 404 into a
  500. `ApiExceptionHandler` declares handlers for that, `HttpMessageNotReadableException`
  (malformed JSON is a 400, not a 500) and `IllegalStateException` (409). Keep them.

  **`InvalidFilterPatternException` has its own handler for the same reason**, added when the
  search fields learned regular expressions. It is the one 400 here that arrives several times
  per second — a filter field is typed into one character at a time, so `^(org\.spring` exists on
  the way to every pattern beginning that way — which is also why it is deliberately **not**
  logged: a line per keystroke would bury the entries that mean something, and nothing has gone
  wrong.

  **`NoResourceFoundException` is not covered by the `ResponseStatusException` handler**, which
  is the trap: it implements `ErrorResponse` without extending it, so it fell to the catch-all
  and every unmapped `/api/…` path answered 500 with a stack trace in the log. Found live on
  `/api/settings` — a near-miss for the real `/api/settings/scanner`. It has its own handler now,
  and `ApiExceptionHandlerTest` pins all of it, because the same mistake has now been made twice
  with two different exception types. Before adding a handler, check what the exception actually
  extends rather than what its name suggests.

- **osv-scanner exits 1 when it finds vulnerabilities.** Only 0 and 1 are success.
  Its errors also appear on the *last* line of stderr, after progress output — and it
  picks its parser from the **filename**, which is why uploads are stored as
  `<uuid>.cdx.json`. All three are covered in
  [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

- **Maven is the opposite of osv-scanner about where the error is, and the assumption was
  borrowed once already.** Maven *leads* with its summary and closes every failure with four
  lines of advice and a `[Help 1]` wiki URL, so taking the last line reported
  `[ERROR] [Help 1] http://cwiki.apache.org/…` as the cause of every probe failure.
  `MavenInvocation.Result.lastMeaningfulLine` takes the first informative `[ERROR]` line for
  this reason. Do not generalise one external tool's output convention to another.

- **`Could not transfer artifact` does not mean the artifact is missing.** Maven prints it for
  an untrusted certificate and for a genuinely absent artifact alike, so any classification has
  to test for the TLS and connectivity signatures *first* — `ProbeFailureReason` has
  `REPOSITORY_UNREACHABLE` ahead of `NOT_FOUND` for exactly that, after a real PKIX failure was
  reported to the user as "Not found in any configured repository" for a library sitting in
  Central. On these target machines that is the common case, not the exotic one.

- **`npm` is `npm.cmd` on Windows.** The frontend build invokes npm from the PATH via
  `exec-maven-plugin`, with OS profiles in `frontend/pom.xml` selecting the right
  executable name. `frontend-maven-plugin` was removed because it has no system-Node mode
  — it always installs its own ~105 MB copy and hardcodes that path.

- **Severity `NONE` and `CLEAN` are different things.** `NONE` is a vulnerability with no
  CVSS score; `CLEAN` is a component with no vulnerability. Never collapse them — see
  [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

- **The view and the export share one query path** (`FindingQuery` → SQL). If you add
  sorting or filtering, add it there rather than in a second implementation, or an
  exported spreadsheet will stop matching the screen it came from.

  Two traps that only appear once you do. **`SELECT DISTINCT` rejects an `ORDER BY` expression
  that is not in the result** — adding `FIXED_VERSION` made the findings endpoint answer 500 for
  one value of one parameter with the whole suite green, so `FindingSortTest` now walks
  `SortField.values()` across both directions and both hand-assembled statements. And **the
  export endpoint already uses `scope`** for its visible/all selector, so the dependency-scope
  filter travels as `scope_filter` there; reusing the name would have let `exportUrl` overwrite
  the filter silently.

- **Sorting by a version needs a stored key, not a comparator.** H2 orders `1.10.0` before
  `1.9.0`. `VersionOrder.sortKey` builds the key from the comparator's own parse — not a helper
  beside it, because "one reading of what a version is" is the whole requirement — and
  `VersionSortKeyTest` asserts the two agree across every version in the fixtures. Adding a
  column like this to an existing table also needs a **backfill**: a null key sorts as "no fix",
  which is a false statement about an advisory rather than a wrong position, and it cannot be
  done in SQL without reimplementing the parse there.

- **A local Maven repository does not cache `maven-metadata.xml`.** It caches metadata
  **per remote repository**, named after the repository id — `maven-metadata-central.xml`
  for the ordinary case. Looking for the bare filename after resolving a version range
  finds nothing, even though Maven resolved the range correctly moments earlier.
  `MavenDependencyResolver.knownVersions` reads every `maven-metadata*.xml` present and
  merges them, rather than assuming one name. Caught live: the ascending-refinement search
  silently no-opped (zero candidate versions, not an error) and fell back to whatever the
  range had already resolved to, which happened to still be correct here — a quieter
  failure than it deserved, since a different scenario could have made it look like
  "nothing to refine" when versions genuinely existed.

- **The Maven probe's child `mvn` process needs `MAVEN_OPTS`, not a JVM `-D` flag.**
  Environment variables propagate to a child process; `-D` system properties on the
  parent JVM do not. On a machine where Maven itself needs
  `-Djavax.net.ssl.trustStoreType=Windows-ROOT` (TLS-inspecting security software — see
  the README), the probe's `mvn` needs that same setting in its own environment, which
  means it must be present in the environment SBOMscope itself was launched from. A fresh,
  empty `probe-repo` cannot resolve *any* plugin without it, so the first probe on such a
  machine fails until this is set.

- **The probe cannot resolve a plugin it has no route to, and that is not a bug in the
  component being probed.** `probe-repo` starts empty and is deliberately never `~/.m2`, so on
  a machine that cannot reach a repository *every* probe fails at plugin resolution. This is
  reported as `ProbeFailureReason.PLUGIN_UNAVAILABLE`, kept distinct from `NOT_FOUND` for
  exactly that reason. **Unresolved design question** — see the 2026-07-30 decision log entry
  before changing anything here.

- **Never invoke a Maven plugin by prefix (`dependency:tree`) from the probe.** A prefix costs
  a `maven-metadata.xml` lookup to resolve it and then takes the plugin's *latest* version, so
  the probe's behaviour could change with nothing changed locally, and the required artifacts
  stop being a knowable set that a disconnected machine could pre-seed. Goals are fully
  qualified and version-pinned, with the versions user-configurable in Settings.

- **`Process.destroyForcibly()` kills the process you name and nothing it started.** On Windows
  the configured Maven is `mvn.cmd`, a batch wrapper whose real work is a `java` grandchild, so
  destroying the wrapper leaves the actual Maven JVM running — holding the repository, the
  network connection and the CPU, with nothing tracking it. Confirmed live: the tree is
  `sbomscope java.exe → cmd.exe → java.exe`. `MavenInvocation.destroyTree` walks
  `descendants()` **first** (destroying the parent reparents them and the handle to walk from is
  gone) and every kill site goes through it — the timeout watchdog included, which had the bug
  before cancellation existed to expose it.

- **Cancelling a probe means killing its child, not interrupting its thread.** The probe thread
  is blocked reading the child's merged output stream, and a stream read does not answer an
  interrupt — the same fact the stderr-deadlock note above turns on. `MavenInvocation` publishes
  the live process per thread so `BumpProbeService.cancel` can reach it.

- **`.formatted()` binds to the last literal in a concatenation, not the whole expression.**
  `"a %s" + "b %s".formatted(x, y)` leaves the first placeholder literal and silently drops the
  extra argument — no compiler warning, no exception, just a broken message that only shows up
  when someone reads it. Parenthesise the whole string: `("a %s" + "b %s").formatted(x, y)`.
  Introduced twice in one session, once in a diagnostic message meant to be read on the machine
  that was failing.
