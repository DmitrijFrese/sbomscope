# SBOMscope

**Local-first SBOM analysis for restricted environments.**

Upload a CycloneDX SBOM, find out which of your dependencies have known
vulnerabilities, whether your code actually uses them, what upgrade would fix them —
and get all of it into a spreadsheet your security team can actually read.

> **Status: working, in active development.** Upload, offline vulnerability scanning, the
> findings view, the Excel export, the Component Inspector, the dependency graph, and upgrade
> paths (offline advisory-derived fixes, plus driving your own `mvn` for the questions that
> need it) all work today. Workspace usage detection and the exploitation-signal columns
> (CISA KEV, EPSS) are not built yet. See
> [docs/IMPLEMENTATION-PLAN.md](docs/IMPLEMENTATION-PLAN.md) for exactly what is done.

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
- **Nothing free** tells you whether a vulnerable library is genuinely used in your
  source or is just sitting in the dependency graph unused.

SBOMscope targets the intersection: run it locally, point it at an SBOM and (optionally)
your source tree, and get actionable, exportable answers.

### Designed for locked-down environments

The analysis machine never needs internet access. All vulnerability data comes from
locally-cached feeds that can be populated from a separate, connected machine and
refreshed only when you explicitly ask for it. No background network calls, no
auto-updates, no admin rights required to install an engine.

SBOMscope does use the network for some things, and the useful question is not whether it
does but **what that traffic says about you**:

- **It never downloads executable code.** You place the osv-scanner binary and point
  SBOMscope at it.
- **It downloads bulk public data when you ask it to** — the OSV advisory archives, from one
  fixed URL shown in the interface, with no credentials. Asking for *every* Maven advisory
  discloses nothing about which libraries you happen to have, which is why it can be a whole
  archive rather than a series of questions, and why you can copy it across on a USB stick to
  a machine with no network at all.
- **It never asks anyone about your specific dependencies.** "Which versions of
  `com.acme:internal-billing` exist" would identify that artifact as something you use. When
  upgrade analysis needs an answer like that, SBOMscope drives a build tool you already have
  and already trust — point it at your `mvn` and prove it works with a test button — so the
  question goes through your mirror, with your credentials, over a channel your build already
  uses every day. No credentials are ever entered here.

With no build tool configured, nothing degrades into a guess: SBOMscope still names the fix
versions the advisories carry, still tells you which of your modules pull a vulnerable
library in, still tells you what to pin it to, and still says plainly which questions it
cannot answer. Everything it does that touches the network or runs an external process is
written to a log you can read inside the application.

## Core features

| Feature | Description |
|---|---|
| **SBOM upload** | CycloneDX JSON, as produced by the Maven and npm CycloneDX plugins. Several files at once, reported per file so one malformed document does not hide the rest. The stored document can be downloaded back, byte for byte. |
| **Workspace usage detection** | Optionally supply a path to your source tree. SBOMscope scans it for imports/references to vulnerable libraries and reports the total hit count, the full list of affected files with fully-qualified paths, and a ±5-line preview of any selected hit with language-aware syntax highlighting. |
| **CVE overview** | Known vulnerabilities per library, blended from several data sources (see below). |
| **Upgrade paths** | Offline, from the advisory data alone: pin, upgrade, or exclude, with the exact fix version an advisory names. For a transitive dependency Tier 1 cannot answer — whether a newer version of what pulls it in already ships the fix — SBOMscope drives your own `mvn` to check, ranking every major line as its own candidate rather than guessing at one winner. Each candidate lists the vulnerabilities it would still carry — not a count, since which one remains is the decision. |
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
| Actively-exploited flag | [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | planned |
| Exploitation probability | [EPSS](https://www.first.org/epss/) (FIRST.org) | planned |
| Dependency graph | The SBOM's own CycloneDX `dependencies` graph | working |
| Workspace usage detection | Built in-house | planned |
| Upgrade paths | Local OSV data for the offline tier; your own `mvn`, driven as an external process, for the questions offline data cannot answer | working |

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
  directly in a type-ahead finder.

### Vulnerability table columns

Component · CVE ID (→ NVD) · Severity (CVSS score + rating) · EPSS score · Known
Exploited (KEV) · Fix available · Recommended upgrade · Direct/Transitive · Workspace
usage status

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

Your data lives in `~/.sbomscope/` — the H2 database, uploaded SBOM documents, and the
vulnerability database. Nothing is written into the project directory.

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

Deeper *call-graph* reachability analysis — proving that a vulnerable **method** is
actually invoked, as [Eclipse Steady](https://github.com/eclipse-steady/steady) and
[OWASP dep-scan](https://owasp.org/www-project-dep-scan/) do — is a candidate for a
future version. Version 1 does simpler import/symbol-level usage detection.

## Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — data model, key flows, and the
  osv-scanner and Maven-probe integration contracts.
- [docs/IMPLEMENTATION-PLAN.md](docs/IMPLEMENTATION-PLAN.md) — phased build plan,
  working action list, and the decision log explaining why the architecture is the way
  it is.
- [AGENTS.md](AGENTS.md) — conventions and constraints for AI coding agents working in
  this repository.

## License

[Apache License 2.0](LICENSE).

Chosen for the environment SBOMscope is built for: it passes a corporate procurement review
without discussion, which a copyleft licence often does not — and a supply-chain tool that
its target organisations cannot approve is not much use to them. It also carries an explicit
patent grant, and §9 makes clear that anyone redistributing SBOMscope with their own support
or warranty does so on their own behalf.
