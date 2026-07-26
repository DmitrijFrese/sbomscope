# SBOMscope

**Local-first SBOM analysis for restricted environments.**

Upload a CycloneDX SBOM, find out which of your dependencies have known
vulnerabilities, whether your code actually uses them, what upgrade would fix them —
and get all of it into a spreadsheet your security team can actually read.

> **Status: pre-implementation.** The specification is complete and agreed; no code has
> been written yet. See [docs/IMPLEMENTATION-PLAN.md](docs/IMPLEMENTATION-PLAN.md) for
> the roadmap.

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

## Core features

| Feature | Description |
|---|---|
| **SBOM upload** | CycloneDX JSON, as produced by the Maven and npm CycloneDX plugins. |
| **Workspace usage detection** | Optionally supply a path to your source tree. SBOMscope scans it for imports/references to vulnerable libraries and reports the total hit count, the full list of affected files with fully-qualified paths, and a ±5-line preview of any selected hit with language-aware syntax highlighting. |
| **CVE overview** | Known vulnerabilities per library, blended from several data sources (see below). |
| **Upgrade path analysis** | For a vulnerable `1.2.3`, shows whether bumping the patch (`1.2.x`), minor (`1.x.y`), or major (`x.y.z`) version would reduce or eliminate its known vulnerabilities — smallest effective jump first. |
| **Dependency tree** | For any selected library, walk parents and children recursively within the scope of your SBOM. |
| **Excel export** | A real spreadsheet, with CVE cells hyperlinked to the NVD and library cells hyperlinked to Maven Central or npmjs.com. |

## How it works

SBOMscope orchestrates proven open-source engines rather than reimplementing
vulnerability matching from scratch. Every component below was chosen specifically
because it can run fully offline against locally-cached data.

| Concern | Engine / source |
|---|---|
| CVE matching (npm + Maven) | [OSV-Scanner](https://google.github.io/osv-scanner/) in `--offline` mode — a single static binary, no installer or admin rights. Its local database already blends OSV and GitHub Advisories. |
| Canonical CVE metadata + links | [NVD](https://nvd.nist.gov/) JSON data feed, mirrored locally |
| Actively-exploited flag | [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) |
| Exploitation probability | [EPSS](https://www.first.org/epss/) (FIRST.org) |
| Upgrade path analysis | [OSV-Scanner Guided Remediation](https://google.github.io/osv-scanner/experimental/guided-remediation/) |
| Dependency tree | The SBOM's own CycloneDX `dependencies` graph |
| Workspace usage detection | Built in-house |
| Excel export | Built in-house (Apache POI) |

### Caching and freshness

Vulnerability data is cached per component (keyed by package URL), shared across every
SBOM you've uploaded — so a library appearing in five SBOMs is looked up once. Each
cache entry records when it was last refreshed and is flagged stale after a
configurable threshold (default: 7 days), so the UI can tell you the data may be
outdated. Refreshing is always a deliberate action: per-component or global, never
automatic.

## Interface

A browser-based UI served by the local backend.

- **Top menu** — icons with text, collapsible to icons only.
- **Left sidebar** — your uploaded SBOMs: filename, upload date, and metadata such as
  the associated workspace path.
- **Vulnerability view** — the selected SBOM's findings as an exportable table.
- **Workspace view** — usage hits and source previews, with a live-search library
  selector. Reachable directly, or by drilling in from any row of the vulnerability
  view.

### Vulnerability table columns

Component · CVE ID (→ NVD) · Severity (CVSS score + rating) · EPSS score · Known
Exploited (KEV) · Fix available · Recommended upgrade · Direct/Transitive · Workspace
usage status

Only columns SBOMscope can populate from a real data source are included by design.
Manual judgment fields (mitigation notes, comments) are deliberately absent — add those
in Excel after export, rather than having the tool maintain an annotation store.

## Tech stack

- **Backend** — Spring Boot (Java). Runs locally; required because workspace scanning
  needs filesystem access.
- **Frontend** — React, served in the browser.
- **Storage** — backend-local embedded database / files. No external database to
  install.

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

- [docs/IMPLEMENTATION-PLAN.md](docs/IMPLEMENTATION-PLAN.md) — phased build plan,
  working action list, and the decision log explaining why the architecture is the way
  it is.
- [AGENTS.md](AGENTS.md) — conventions and constraints for AI coding agents working in
  this repository.

## License

Not yet chosen — see the open questions in the implementation plan.
