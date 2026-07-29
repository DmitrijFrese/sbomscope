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
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Data model, key flows, and the osv-scanner contract |
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

   **Until the repository is public, the baseline may be rewritten instead of extended.**
   The only installations are the maintainer's, so a migration that would immediately be
   undone by the next one is better folded into `V1__baseline.sql` than shipped — a reader
   should meet one description of the current schema, not a history to reconstruct. The
   cost is that existing databases must be deleted, which is stated in the migration itself.
   **Once the repository is public this stops**: migrations become strictly additive, because
   from then on somebody else's data is on the other end of them.
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
    pages/              one component per route
    sboms/              SbomProvider: uploaded SBOMs and the current selection
    theme/              ThemeProvider: light/dark/system resolution
    styles/             tokens.css holds every colour; app.css holds layout
backend/                Spring Boot application, produces the runnable jar
  src/main/java/dev/sbomscope/
    api/                REST controllers and the exception handler
    config/             web and infrastructure configuration
    export/             Excel writing and public registry links
    sbom/               CycloneDX parsing, storage, uploaded-document store
    scanner/            osv-scanner integration, OSV database, findings
    settings/           user-editable settings
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

They are SBOMscope's own dependency trees, so regenerating them keeps the tests honest as
the project changes. Integration tests use an in-memory H2 built by the same Flyway
migrations as production, so the migrations are covered too.

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

- **osv-scanner exits 1 when it finds vulnerabilities.** Only 0 and 1 are success.
  Its errors also appear on the *last* line of stderr, after progress output — and it
  picks its parser from the **filename**, which is why uploads are stored as
  `<uuid>.cdx.json`. All three are covered in
  [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

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
