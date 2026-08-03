# SBOMscope

**Local-first SBOM analysis for restricted environments.**

Upload one or more CycloneDX JSON SBOMs and analyze them locally. Today SBOMscope can:

- match **Maven and npm** components against locally cached OSV vulnerability data;
- enrich findings with CISA KEV and FIRST EPSS exploitation signals;
- trace direct and transitive dependency routes in the Component Inspector;
- derive offline fix versions, pins and npm overrides, and use your configured `mvn` to test
  resolved upgrade paths for Maven builds;
- export the visible findings and their provenance to a linked Excel workbook; and
- keep network access, external processes, maintenance and destructive actions explicit and
  visible in the application.

> **Ecosystem boundary:** Maven and npm are the only supported ecosystems today. Full Tier 2
> release enumeration and resolved-ancestor probing exists only for Maven builds that the
> configured `mvn` can model. npm currently has offline advisory-derived fixes and ready-to-paste
> `overrides`, but no npm package-tool probe. Gradle has no adapter even though it commonly emits
> Maven purls. Rust, Go, Python, .NET and other ecosystems are not supported by SBOMscope yet;
> osv-scanner supporting an ecosystem does not make it an SBOMscope feature automatically.

> **Status: working, in active development.** An initial, experimental Maven workspace
> reachability slice is available: it reads already-built production classes and an explicitly
> configured read-only Maven cache, then shows module-isolated conservative WALA bytecode call paths in the
> Component Inspector. It never builds the workspace and does not yet prove that an advisory's
> vulnerable method was called. VEX consumption and container-image scanning remain planned. See
> [docs/IMPLEMENTATION-PLAN.md](docs/IMPLEMENTATION-PLAN.md) for the exact roadmap and evidence
> boundaries.

---

## Why

Existing tools each solve part of this problem, but nothing free covers all of it in a
single tool a developer can run on their own machine:

- **OWASP Dependency-Track** is excellent, but it's architected as a continuously
  running server for an organization (API server + frontend + PostgreSQL), not as
  something a single developer spins up against one repository.
- **Enterprise vulnerability-management platforms** vary widely in export support.
  Getting findings out into a spreadsheet you can sort, filter, and share is often
  awkward or simply unavailable.
- **Reachability remains difficult to establish honestly.** An import is not proof that a
  vulnerable method executes, while reflection and framework callbacks can hide real use from a
  simple source search. The experimental workspace analysis therefore reports call paths and
  explicit coverage rather than a confident text-match verdict.

SBOMscope targets the intersection: today, run it locally, point it at an SBOM, and get
actionable, exportable dependency and vulnerability answers. The experimental Maven workspace
slice adds conservative component-boundary call-path evidence; it remains deliberately narrower
than a vulnerable-method verdict.

### Designed for locked-down environments

The analysis machine never needs internet access. All vulnerability data comes from
locally-cached feeds that can be populated from a separate, connected machine and
refreshed only when you explicitly ask for it. No background network calls, no
auto-updates, no admin rights required to install an engine.

SBOMscope does use the network for some things, and the useful question is not whether it
does but **what that traffic says about you**:

- **It never downloads executable code.** You place the osv-scanner binary and point
  SBOMscope at it.
- **It downloads bulk public data when you ask it to** — the OSV advisory archives, CISA's
  Known Exploited Vulnerabilities catalogue and FIRST's EPSS scores, each from one fixed URL
  shown in the interface, with no credentials. Asking for *every* Maven advisory, or *every*
  exploited vulnerability, discloses nothing about which libraries you happen to have, which is
  why each can be a whole file rather than a series of questions, and why you can copy them
  across on a USB stick to a machine with no network at all. EPSS publishes a per-CVE lookup
  API and SBOMscope deliberately does not use it — asking about one CVE would say which one you
  care about, and FIRST's own guidance names the bulk file as the right mechanism anyway.
- **It never asks anyone directly about your specific dependencies.** "Which versions of
  `com.acme:internal-billing` exist" would identify that artifact as something you use. When
  Maven upgrade analysis needs an answer like that, SBOMscope drives the build tool you already
  have and trust — point it at your `mvn` and prove it works with a test button — so the question
  goes through your mirror, with your credentials, over a channel your build already uses every
  day. No credentials are ever entered here. No equivalent npm, Gradle, Rust, Go, Python or .NET
  adapter exists today.

With no Maven probe configured, nothing degrades into a guess: SBOMscope still names the fix
versions the advisories carry, still tells you which of your modules pull a vulnerable library
in, still provides the ecosystem-specific Tier 1 remedy it knows, and still says plainly which
questions it cannot answer. Everything it does that touches the network or runs an external
process is written to a log you can read inside the application.

## Core features

| Feature | Description |
|---|---|
| **SBOM upload** | CycloneDX JSON, as produced by the Maven and npm CycloneDX plugins. Several files at once, reported per file so one malformed document does not hide the rest. The stored document can be downloaded back, byte for byte. |
| **Workspace reachability analysis — experimental Maven slice** | Reads existing `target/classes` and exact dependency JARs from a configured **read-only** Maven cache. Each mapped module is analyzed against its own SBOM dependency closure; WALA reports direct/transitive bytecode paths into a component, or an explicit incomplete/ambiguous result. It does not build the workspace or claim a vulnerable method was reached. Runs are isolated, cancellable, retryable, and capped by configurable defaults of 10 minutes and 1 GiB heap. |
| **CVE overview** | Known vulnerabilities per library, blended from several data sources (see below). |
| **Upgrade paths** | Maven and npm both get offline advisory-derived upgrade/pin guidance; npm also gets a ready-to-paste `overrides` snippet. For the transitive question Tier 1 cannot answer — whether a newer version of what pulls it in already ships the fix — only the Maven path drives your configured `mvn`, ranking every major line as its own candidate rather than guessing at one winner. npm and Gradle have no Tier 2 probe. |
| **Dependency graph** | For any selected library, walk parents up to the roots and children down to the leaves, within the scope of your SBOM. |
| **Excel export** | A real spreadsheet, with CVE cells hyperlinked to the NVD, library cells to the artifact's registry page and version cells to that exact version. A second sheet records what was selected, so a filtered workbook can account for its own size. |

## How it works

SBOMscope orchestrates proven open-source engines rather than reimplementing
vulnerability matching from scratch. Every component below was chosen specifically
because it can run fully offline against locally-cached data.

| Concern | Engine / source | Status |
|---|---|---|
| CVE matching (npm + Maven) | [OSV-Scanner](https://google.github.io/osv-scanner/) in `--offline` mode — a single portable binary, no installer or admin rights. Its database already blends OSV and GitHub Advisories, and supplies a numeric CVSS score and the GHSA→CVE mapping. | working |
| Excel export | Built in-house (Apache POI) | working |
| Actively-exploited flag | [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) — the whole catalogue, one file, ~1.5 MB | working |
| Exploitation probability | [EPSS](https://www.first.org/epss/) (FIRST.org) — the whole daily score file, ~2.4 MB | working |
| Dependency graph | The SBOM's own CycloneDX `dependencies` graph | working |
| Workspace reachability analysis | WALA 1.8.0 in an SBOMscope-owned worker JVM; existing Maven build output and a user-configured read-only Maven cache only | experimental Maven slice |
| Upgrade paths | Local OSV data for Maven/npm Tier 1; your own `mvn`, driven as an external process, for Maven Tier 2 | Maven working; npm Tier 1 only |

CVE cells link to [NVD](https://nvd.nist.gov/), but the NVD **API** is deliberately not
used — it contributes to none of the columns shown, and the link is derivable from the
CVE identifier alone.

Library links are public by design, because an exported spreadsheet is usually read by somebody
outside the network it was produced on. Where a purl declares its own `repository_url` —
vendor rebuilds such as Red Hat's `a.b.c.d` artifacts do — that destination is honoured instead,
provided the host is a public repository a reader can actually reach. For anywhere else, no link
at all: a link into a private Artifactory is useless to the reader, and Maven Central would be a
confident 404.

### Caching and freshness

Vulnerability data is cached per component (keyed by package URL), shared across every
SBOM you've uploaded — so a library appearing in five SBOMs is looked up once. Each
cache entry records when it was last refreshed and is flagged stale after a
configurable threshold (default: 7 days), so the UI can tell you the data may be
outdated.

**Downloading advisory data is always a deliberate action; analysing what is already on disk is
not.** A newly uploaded SBOM is scanned by itself, and at startup anything holding a component
that has never been checked is scanned in the background — after the application is serving,
one at a time, and only where you have configured a scanner and its archive is present. That
sends nothing anywhere, which is the whole reason it needs no asking; every run is written to
the activity log. Re-scanning against a freshly downloaded archive stays a button you press.

## Interface

A browser-based UI served by the local backend.

- **Top menu** — icons with text, collapsible to icons only.
- **Left sidebar** — your uploaded SBOMs: filename, upload date, and metadata such as
  the associated workspace path.
- **Vulnerability view** — the selected SBOM's findings as an exportable table. List-centred:
  what is wrong across this SBOM, sorted and filtered.
- **Component Inspector** — one library in depth: what to upgrade to and what each option
  still carries, who pulls it in and what it drags along, and whether your own code touches
  it. Reached by a per-row action from the vulnerability view, or by picking a library
  directly in a type-ahead finder, which lists worst-first and marks each library with the
  severity standing against it — including a distinct mark for one nothing has scanned, since
  "not checked" must never look like "nothing found".

**Every search field takes a regular expression**, behind a `.*` toggle beside it, with full
Java syntax — lookahead, lookbehind, backreferences, named groups. A second toggle, `!`, inverts
the match so the field hides what it finds instead of showing it; the two combine, so `(ABC|DEF)`
with both on removes every row matching either. Off by default, both of them: `.` is a valid
regular expression and a purl is made almost entirely of dots, so `spring.core` keeps meaning
what it has always meant until you say otherwise. An invalid pattern is ordinary input — it
reports itself beside the field and leaves the last good result on screen, because half-typed
patterns are what a filter field is full of.

One exception worth stating rather than discovering: the Component Inspector's finder filters a
list the browser already holds, so it runs on **JavaScript's** regular expressions rather than
Java's. The two agree on everything a library finder is realistically typed with; they part
company over possessive quantifiers, atomic groups and `\A`/`\z`, all of which exist to control
backtracking that costs nothing over a few thousand rows in memory.

### Vulnerability table columns

Component · CVE ID (→ NVD) · Severity (CVSS score + rating) · EPSS score · Known
Exploited (KEV) · Fix available · Recommended upgrade · Direct/Transitive · Workspace
usage status

**An empty exploitation cell is never a clearance.** KEV is a positive list, so absence means
CISA has not confirmed exploitation — not that a flaw cannot be exploited. The column says
*not listed* rather than "No" for that reason, and shows a dash where a finding carries no CVE
at all, because both feeds are keyed by CVE and for those rows the question cannot be asked
rather than answered. A feed you have not downloaded is reported once above the table instead
of being repeated into every row.

Only columns SBOMscope can populate from a real data source are included by design.
Manual judgment fields (mitigation notes, comments) are deliberately absent — add those
in Excel after export, rather than having the tool maintain an annotation store.

## Tech stack

- **Backend** — Spring Boot 4 on Java 21 (LTS). Runs locally; a local process is
  required because workspace scanning needs filesystem access.
- **Frontend** — React with Vite.
- **Build** — one Maven multi-module build produces a single runnable jar containing
  both frontend and backend. In development the Vite dev server proxies API calls to
  the backend, so hot reload still works.
- **Storage** — embedded H2 database. No external database to install.
- **Schema migrations** — Flyway, with versioned SQL migrations. Your local database
  holds real data (uploaded SBOMs, vulnerability caches), so it migrates cleanly when
  you upgrade SBOMscope rather than being rebuilt from scratch.

## Getting started

Requirements: **Java 21 or newer**, **Maven 3.9+**, and **Node 22.12+** with npm on your
PATH.
The build uses the Node already installed on the machine rather than downloading its
own copy.

Build everything into a single runnable jar:

```bash
mvn clean package
```

Run it:

```bash
java -jar backend/target/sbomscope.jar
```

Then open <http://localhost:8080>.

The packaged server binds to `127.0.0.1` by default. This is a security boundary, not merely a
convenience: SBOMscope has no authentication or multi-user access controls, and its API can read
configured workspace/cache paths and manage local data. A deliberate deployment on another
interface requires an explicit Spring Boot `server.address` override and must add its own access
control; CORS configuration alone is not access control.

Your data lives in `~/.sbomscope/` — the H2 database (`db/`), uploaded SBOM documents
(`sboms/`), the OSV vulnerability archives (`osv-db/`), the exploitation feeds (`exploit/`),
the Maven probe's isolated repository (`probe-repo/`) and the logs (`logs/`). Nothing is
written into the project directory.

**Settings → Erase local data** keeps those recovery costs separate. Offline vulnerability
data removes OSV archives and their index together with KEV and EPSS. Rolled log history removes
only the eight inactive numbered logs and keeps the two active files while SBOMscope is running.
The Maven probe cache removes only `probe-repo/`, never `~/.m2`, and is refused while a probe is
queued or running; later probes may need repository access to fetch the cache contents again.

SBOMscope works immediately as an SBOM inventory. Vulnerability scanning is off until
you turn it on.

### Enabling vulnerability scanning

SBOMscope never downloads the scanner for you — you place it, and point the application
at it.

1. Download the build for your platform from the
   [OSV-Scanner releases page](https://github.com/google/osv-scanner/releases/latest);
   for example `osv-scanner_windows_amd64.exe`, around 55 MB. It is a single portable
   executable: no installer, nothing to extract, no admin rights.
2. Verify it against the published `SHA256SUMS` before running it. It is an executable
   arriving from the internet, and this is a supply-chain tool.
3. Put it anywhere, then open **Settings → Vulnerability scanning**, set the path, tick
   **Use OSV-Scanner**, and press **Test scanner** to confirm it responds.
4. Download the offline database for the ecosystems you need — Maven is around 10 MB,
   npm around 200 MB, each with its own button and a progress bar.

From that point everything runs offline, and uploaded SBOMs are scanned without being asked —
including anything already uploaded that has never been checked, picked up the next time
SBOMscope starts. **Scan for vulnerabilities** stays available for re-running the analysis
against a refreshed archive.

On a machine with no internet access, copy the database directory across from a machine
that has it; the layout is all osv-scanner needs.

### Exploitation signals (CISA KEV and EPSS)

Severity says how bad a flaw would be; these two say whether anyone is exploiting it. Open
**Settings → Exploitation signals** and press Download on each — about 1.5 MB and 2.4 MB, from
one fixed public URL each, with no credentials and nothing about your dependencies in the
request. There is nothing to switch on: the columns fill in as soon as the data is there.

Both files can also be carried across to a disconnected machine. Drop them into
`~/.sbomscope/exploit/` under the names shown in Settings and press **Load** — being on disk
and being loaded are separate states, and SBOMscope will not re-download something it already
has.

Each feed reports the date its *own data* claims, not when you fetched it — CISA's catalogue
version and EPSS's score date and model version — so a file copied from elsewhere still
describes itself honestly. EPSS data is provided by [FIRST.org](https://www.first.org/epss/);
the KEV catalogue is published by CISA under CC0 1.0.

### Working on the frontend

For hot reload, start the backend as above and run the Vite dev server alongside it:

```bash
npm --prefix frontend run dev
```

The UI is then served from <http://localhost:5173>, with `/api` proxied to the backend.

### Troubleshooting

**Maven fails with `PKIX path building failed`.** Security software on your machine is
intercepting HTTPS and re-signing certificates with a root certificate that Java's own
truststore does not know about. Browsers and `curl` keep working because they use the
operating system's certificate store. Point Java at that same store — on Windows:

```bash
setx MAVEN_OPTS "-Djavax.net.ssl.trustStoreType=Windows-ROOT"
```

This grants no new trust; it reuses the certificates your system already accepts.

**The build fails in `npm ci` with `UNABLE_TO_VERIFY_LEAF_SIGNATURE`.** Node has its own
certificate handling, so the Java setting above does not affect the frontend install that Maven
launches. Reuse the operating system's trusted roots for this build too. In PowerShell:

```powershell
$env:NODE_OPTIONS="--use-system-ca"
mvn clean package
```

This is again a trust-store selection, not a disabled certificate check. If npm instead reports
`EPERM` against its cache, that is a filesystem permission or file-lock problem rather than TLS.

The same applies to the running application when it downloads the vulnerability
database, so start it with:

```bash
java -Djavax.net.ssl.trustStoreType=Windows-ROOT -jar backend/target/sbomscope.jar
```

**The Maven probe (upgrade paths, Tier 2) fails the same way, for the same reason.** It
runs your own `mvn` as a child process, which inherits environment variables — not JVM
`-D` flags — from whatever launched SBOMscope. Setting `MAVEN_OPTS` with `setx` as above
covers this automatically, since it is the same environment the probe's `mvn` inherits; a
one-off `export`/`set` in the terminal you happen to launch SBOMscope from works too, as
long as it is set before SBOMscope starts. A probe failing with something like
`NoPluginFoundForPrefixException` on a fresh install of the probe's isolated repository
almost always means this, not a real dependency problem.

**Check this first: press "Test Maven" in Settings.** It verifies both that the path is Maven
*and* that the plugins the probe drives can actually be fetched and run — the second is the one
that fails in a restricted network, and `mvn --version` alone would report success there.

**The probe reports "could not obtain the plugin".** The probe resolves into its own repository
(`~/.sbomscope/probe-repo`), never your `~/.m2`, so that a failed probe can never leave markers
that make a later real build refuse to retry a download. That isolation has a cost: the probe
must be able to fetch `maven-dependency-plugin` itself. On a machine with no route to any
repository — proxied or otherwise — it cannot, and no setting will change that. Every `mvn`
command the probe runs, and everything Maven said back, is written to
`~/.sbomscope/logs/sbomscope.log`, so the actual failure is readable rather than inferred. If
your mirror carries different plugin versions than the ones SBOMscope pins, set them under
**Settings → Maven probe**.

## Scope

SBOMscope is currently built for **a single developer running it on their own machine**
against **Maven and npm** projects. Running it as a shared network service, and
supporting further ecosystems, are possible later directions but explicitly out of
scope for the first version.

The available Maven workspace analysis is **component-boundary** evidence: it can show that
compiled application bytecode reaches a library, but the local Maven OSV archive currently has no
structured vulnerable-method data with which to narrow that path further. Vulnerable-method
reachability, VEX and deterministic assessment remain later roadmap work.

## Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — data model, key flows, and the
  osv-scanner and Maven-probe integration contracts.
- [docs/IMPLEMENTATION-PLAN.md](docs/IMPLEMENTATION-PLAN.md) — phased build plan,
  working action list, and the decision log explaining why the architecture is the way
  it is.
- [docs/IMPLEMENTATION_PLAN_WORKSPACE_BASED_EVIDENCE.md](docs/IMPLEMENTATION_PLAN_WORKSPACE_BASED_EVIDENCE.md)
  — detailed reachability, VEX and assessment execution plan; its handoff section names the
  next implementation step and remaining decision gates.
- [AGENTS.md](AGENTS.md) — conventions and constraints for AI coding agents working in
  this repository.

## License

[Apache License 2.0](LICENSE).

Chosen for the environment SBOMscope is built for: it passes a corporate procurement review
without discussion, which a copyleft licence often does not — and a supply-chain tool that
its target organisations cannot approve is not much use to them. It also carries an explicit
patent grant, and §9 makes clear that anyone redistributing SBOMscope with their own support
or warranty does so on their own behalf.
