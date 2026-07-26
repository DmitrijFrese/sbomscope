# AGENTS.md

Guidance for AI coding agents working in this repository.

## What this project is

SBOMscope is a local-first SBOM analysis tool: upload a CycloneDX SBOM, get known
vulnerabilities, whether the code actually uses the vulnerable libraries, upgrade
paths, and an Excel export. See [README.md](README.md) for the full picture and
[docs/IMPLEMENTATION-PLAN.md](docs/IMPLEMENTATION-PLAN.md) for what to build next.

## Tech stack

- **Backend**: Spring Boot (Java) — the local server process. Build tool not yet
  chosen (see open questions in the implementation plan).
- **Frontend**: React, browser-based.
- **Storage**: backend-local embedded DB / files. No external database.
- **Excel export**: Apache POI.
- **Vulnerability engines**: OSV-Scanner invoked as an external binary; NVD, CISA KEV
  and EPSS consumed as locally-cached feeds.

## Hard constraints

These are architectural commitments, not preferences. Do not violate them without
raising it with the maintainer first.

1. **Offline-capable by default.** Every analysis path must work on a machine with no
   internet access, using only locally-cached data. Network access is exclusively for
   explicit, user-triggered cache refreshes.
2. **Never refresh vulnerability data automatically.** No background jobs, no
   refresh-on-startup, no refresh-on-upload. The user asks; only then do we fetch.
3. **Never commit secrets.** The NVD API key is read from an environment variable or a
   git-ignored local config file. Only templates/placeholders are committed.
4. **One authenticated NVD channel, rate-limited.** Do not add parallel or unkeyed
   request channels to increase throughput — NVD's terms permit blocking access for
   apparent circumvention of rate limits. Stay meaningfully under 50 requests / 30
   seconds.
5. **No new heavyweight external engines** without checking they can run in a
   locked-down environment: no admin rights, no installer, no mandatory outbound
   network calls. A single static binary is the bar to beat.
6. **No manual/judgment data fields.** The vulnerability table shows only what we can
   populate from a real data source. Users add their own notes in Excel post-export.
   This is deliberate — it keeps an annotation-persistence layer out of the product.
7. **Target ecosystems are Maven and npm.** Don't generalize prematurely to other
   package ecosystems.

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

## Conventions

- Match the surrounding code's style, naming, and comment density rather than importing
  external conventions.
- Keep the backend's engine integrations behind interfaces — OSV-Scanner is invoked as
  an external process today, but a JVM-embedded reachability engine is a plausible
  future addition, and the call sites shouldn't care.
- Cache entries carry a last-refreshed timestamp. Anything reading cached vulnerability
  data must be able to surface staleness to the UI.

## Repository layout

Not yet scaffolded. This section should be filled in as part of the first
implementation phase.
