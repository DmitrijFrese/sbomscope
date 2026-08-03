# Workspace-Based Vulnerability Evidence — Implementation Plan

Status: **Maven/JVM component-boundary reachability and source-run hardening implemented; VEX is next**
Last updated: 2026-08-03

This is the detailed execution plan for Phase 9 (workspace reachability), Phase 11 Tier A
(VEX consumption), and the assessment layer that distinguishes findings worth active attention
from findings that can be deferred with evidence. The parent roadmap and decision log remain in
[IMPLEMENTATION-PLAN.md](IMPLEMENTATION-PLAN.md).

## Fresh-session handoff

Stage 3C is complete. The next executable work is **Stage 5, adapter 1: embedded CycloneDX VEX**.
Stage 4 is not unfinished prerequisite work: vulnerable-symbol enhancement is deliberately gated
because the measured local Maven OSV archive supplies no structured vulnerable methods. Do not
scrape advisory prose to manufacture them, and do not delay VEX Tier A waiting for that data.

Before writing the VEX schema/parser, bring the maintainer the remaining consequential choice:
which official or real supplier CycloneDX VEX document will be the first committed fixture. It
must exercise real product/version/component identity and provenance; a handwritten happy-path
sample is not sufficient. Once selected, implement the normalized statement model and embedded
CycloneDX adapter described in Stage 5, keeping reachability evidence and supplier VEX as separate
sources. The latest verified baseline is `mvn clean package`: 285 backend and 28 frontend tests
passed, with typecheck, production bundle and runnable JAR. The production npm audit intentionally
still reports GHSA-qwww-vcr4-c8h2; Stage 3C records its reviewed RSC-only non-applicability and why
the npm-suggested 7.11.0 downgrade is less safe.

Container-image scanning is deliberately outside this plan. It follows the workspace work and
has its own ecosystem and engine decisions.

---

## 1. Outcome

For every vulnerability finding, SBOMscope should answer four separate questions:

1. **Presence** — is the vulnerable component and version in this SBOM?
2. **Reachability** — does compiled production code contain a direct or transitive call path
   into that component, or into a vulnerable method when one is known?
3. **Supplier assessment** — does a matching VEX document say the product is affected, fixed,
   not affected, or still under investigation, and why?
4. **Action** — given that evidence, should the finding remain actionable, be reviewed, be
   deferred with evidence, be considered resolved, or remain explicitly unassessed?

These are not collapsed into a risk score. Severity, KEV and EPSS describe impact and threat;
reachability and VEX describe applicability. A reader must be able to see which fact caused a
finding to enter an action lane.

### Non-goals

- Do not call a negative static-analysis result a false positive or proof of non-exploitability.
- Do not execute or build an attached workspace automatically.
- Do not query GitHub, OSV or another service per finding for vulnerable methods.
- Do not let users manually assign VEX statuses or action lanes inside SBOMscope.
- Do not delete findings when they are deferred or covered by VEX.
- Do not generalize the implementation beyond the current Maven/npm product scope. JVM/Maven is
  first; npm needs its own later analysis design.

---

## 2. What the local Maven archive actually contains

Measured 2026-08-02 against the archive currently used by the live application:

| Measure | Result |
|---|---:|
| Archive | `~/.sbomscope/osv-db/osv-scanner/Maven/all.zip` |
| Archive size | 9,942,875 bytes |
| JSON advisory documents | 6,898 |
| Advisories with a structured candidate method/function key | **0** |
| `affected[].ecosystem_specific` properties | **0** |

The measurement searched JSON property names, not free text, for:
`vulnerable_functions`, `affected_functions`, `vulnerable_methods`, `affected_methods`,
`functions`, `methods`, `symbols`, and `imports`.

This corrects an earlier ambiguity: the measurement had been proposed but had not yet been
performed. The result does **not** prove that no advisory description mentions a class or method,
or that a linked upstream commit cannot identify one. It proves that the current offline Maven
archive supplies no machine-readable vulnerable-symbol field we can safely join to a call graph.
Mining prose or fetching one linked advisory at a time would be a different, less reliable data
source and is not part of the MVP.

### Consequence

**Component-boundary reachability is the dependable first product.** It can establish that
production code directly calls a vulnerable library or reaches it through another dependency.
Vulnerable-method reachability remains a stronger optional result when a future advisory source,
imported VEX document, or other explicit local artifact supplies a structured symbol.

### VEX sources we can leverage

VEX is not one central vulnerability database. It is a product-scoped assertion published by a
supplier or product authority. That makes it valuable only when SBOMscope preserves the author,
document identity, time, product/version scope and matching decision rather than treating a CVE
status as globally true.

There are nevertheless concrete inputs available now:

| Source | SBOMscope use | Boundary |
|---|---|---|
| **CycloneDX VEX** | Read vulnerability `analysis` data already embedded in an uploaded CycloneDX document, then accept standalone CycloneDX VEX documents. This reuses the format and Jackson parsing approach already in SBOMscope. | Best first adapter: no new runtime engine, registry or network call. A producer's assertion still needs exact product/version matching. |
| **OpenVEX** | Accept the small JSON-LD format as a standalone upload. Use the official schema/examples and `vexctl` as development-time fixtures and a validation oracle. | OpenVEX is still described as a draft. Do not make `vexctl` a required runtime binary and do not add its Go implementation to the JVM application. |
| **CSAF 2.0/2.1 VEX** | Accept supplier CSAF documents and normalize product-tree relationships, statuses, justifications, remediations and notes. | More complex than the other adapters; validate against the official schemas/test corpus and never reduce a product-tree near-match to a CVE-only match. |
| **Red Hat bulk CSAF VEX** | Later, optionally load Red Hat's complete signed archive as bulk public data, exactly like an explicitly requested offline feed. It contains fixed/unfixed product/component assessments and machine-readable justifications; Maven component purls occur for Red Hat middleware where published. | It is authoritative for matching Red Hat products and builds, **not a universal Maven VEX feed**. The current archive is about 257 MB compressed and uses `.tar.zst`; attribution, checksum/signature verification and deleted-record handling are required. |

#### Acquisition reality

The current `maven-sbomscope.cdx.json` fixture was measured on 2026-08-02: it is CycloneDX 1.6
with 60 components and **zero** top-level `vulnerabilities`, so it contains no VEX `analysis`
objects. That is expected. The CycloneDX Maven plugin produces inventory and dependency
relationships; it cannot decide whether a vulnerability is exploitable in the product. The
presence of a VEX-capable format does not mean an ordinary SBOM generator fills the VEX fields.

Users can obtain VEX through three honest paths:

1. **Supplier-provided VEX.** A product or distribution supplier publishes a standalone
   CycloneDX, OpenVEX or CSAF document. The user downloads it through their established supplier
   channel and imports it into SBOMscope. Bulk feeds such as Red Hat's can cover exact supplier
   products, but ordinary upstream Maven libraries often have no published product VEX.
2. **Their own product-security pipeline.** When the analyzed application is the user's own
   product, that organization is the authority that can issue VEX. Existing tools can create an
   OpenVEX document (`vexctl`) or validate/inspect a CycloneDX VEX document (`sbom-utility`), but
   the status and justification still come from that organization's review and evidence—not
   from the SBOM generator. Organizations already running Dependency-Track can export CycloneDX
   VEX from its per-project audit decisions; SBOMscope should accept that output but not require
   or embed that much heavier platform.
3. **A later SBOMscope evidence-backed draft export.** Once workspace reachability is implemented,
   SBOMscope can prepare a standalone CycloneDX VEX draft linked to the original BOM with BOM-Link.
   It may include only deterministic analyzer facts and their limitations, remain visibly
   unsigned/unattested, and require the product owner to review and publish/sign it outside
   SBOMscope. This avoids turning a local static-analysis result silently into supplier authority.

CycloneDX recommends keeping dynamic VEX separate from the more static inventory BOM. That is a
good fit here: users do not need to regenerate or modify the uploaded SBOM whenever an assessment
changes, and the exact BOM serial/version/component reference remains auditable.

Primary references:

- [CycloneDX VEX capability](https://cyclonedx.org/capabilities/vex/)
- [OpenVEX specification and JSON schema](https://github.com/openvex/spec)
- [OpenVEX `vexctl`](https://github.com/openvex/vexctl)
- [Red Hat security-data terms and CSAF/VEX description](https://access.redhat.com/security/data)
- [Red Hat bulk CSAF VEX archive](https://security.access.redhat.com/data/csaf/v2/vex/)

The immediate product value does not depend on vulnerable-method data. An exact supplier
`known_not_affected` statement with a standard justification can support **Deferrable with
evidence**; `known_affected` supports **Actionable**; `fixed` supports **Resolved**; and
`under_investigation` supports **Needs review**. Reachability remains independent evidence that
can corroborate or contradict those assertions.

CycloneDX external references may identify an `exploitability-statement`. SBOMscope may show and
copy such a URL as a discovery hint, but it must not fetch it automatically: the URL is specific
to the user's product/dependency context and crosses the dependency-specific network boundary.
The user imports the document explicitly.

---

## 3. Evidence vocabulary

Reachability facts are stored independently from the action lane derived from them.

| Reachability evidence | Exact claim |
|---|---|
| **Vulnerable symbol reached** | A call path from a production workspace method reaches a structured vulnerable method/function identity. |
| **Component reached** | A call path crosses into a class/method owned by the vulnerable component; no usable vulnerable-symbol input exists, or the path does not reach one. |
| **Referenced only** | Production bytecode/source names a component type or symbol, but no call path was constructed. |
| **Not reached in analyzed graph** | No direct or transitive bytecode call path was found within the recorded analysis boundary. |
| **Unknown / incomplete** | Missing classes, dependencies, modules, unsupported bytecode, cancellation or engine failure prevented an honest result. |
| **Not analyzed** | No current analysis run exists for this SBOM/workspace. |

Every result records:

- SBOM and owning module;
- workspace identity/revision and analyzed production output directories;
- dependency artifacts and hashes where available;
- analyzer name/version and algorithm;
- roots used for traversal;
- missing classes, unresolved edges and unsupported bytecode;
- whether test code was excluded;
- start/completion time, duration and cancellation/failure state; and
- known blind spots: reflection, dependency injection/framework callbacks, service loading,
  serialization, generated code, JNI/native calls, runtime plugins and dynamic configuration.

### Spring and runtime dispatch boundary

**Decision, 2026-08-02: a Spring/proxy/reflection marker prevents WALA-only negative evidence
from becoming Deferrable with evidence.** WALA can establish ordinary bytecode paths through a
Spring JAR, including static and resolvable virtual/interface dispatch, but it is not a Spring
container simulator. Dependency injection, conditional configuration, component scanning,
JDK/CGLIB/Byte Buddy proxies, AOP advice, reflection and framework callbacks can introduce
runtime edges that do not exist in the analysed class files.

Therefore:

- a positive WALA path remains **Actionable** evidence, whether or not Spring is present;
- the analyzer records observed Spring/AOP/proxy/reflection markers as completeness blockers;
- a negative result with any such blocker is **Needs review**, never Deferrable solely because
  WALA found no path; and
- a later Spring-aware adapter may add evidence from compiled metadata or explicitly supplied
  AOT/runtime configuration, but it must be separately scoped, inspectable and measured. It is
  not inferred by generic WALA analysis.

### Conservative roots for the first implementation

The first graph treats **every compiled production workspace method** as a potential root. This
answers “can any of our production code call this?” without first pretending we can identify
every runtime entry point in Spring or another framework.

This intentionally prefers false positives over unsafe false negatives: a dead production method
may keep a component actionable, but it cannot cause an actually used component to be deferred.
Framework-aware entry points (`main`, controllers, listeners, scheduled jobs and similar) are a
later precision layer, not an MVP prerequisite.

---

## 4. Action lanes

The UI term is **Assessment**, not “meaningful/false positive”. The compact finding-table value
is one of five deterministic lanes:

| Lane | Meaning | Examples |
|---|---|---|
| **Actionable** | Evidence says the component is used or the product is affected. Keep in the active remediation set. | Vulnerable symbol reached; component reached directly or transitively; exact-product VEX `known_affected`. |
| **Needs review** | Evidence exists but is incomplete, contradictory or demands human investigation outside SBOMscope. | Reference only; VEX `under_investigation`; stale/mismatched evidence; structural conflict; KEV plus only negative static evidence. |
| **Deferrable with evidence** | Current evidence supports postponing remediation, while retaining and exporting the finding. | Exact matching VEX `known_not_affected`; current sufficiently complete analysis found no path and no stronger evidence contradicts it. |
| **Resolved** | Evidence says the current delivered product no longer carries the finding. | Regenerated SBOM is clean/component absent; exact-product VEX `fixed`. |
| **Unassessed** | No usable reachability or VEX evidence exists. | No workspace analysis; failed/cancelled run; unsupported module or missing compiled output. |

Severity, KEV and EPSS do not manufacture applicability:

- severity and EPSS order work **within** a lane;
- KEV makes a static-analysis-only negative result **Needs review**, because exploitation in the
  wild raises the cost of trusting static blind spots;
- an exact, current supplier VEX `known_not_affected` may still support deferral for a KEV CVE,
  because it is a product-specific assertion rather than a generic probability; and
- all three remain visible beside the assessment reason.

### Deterministic precedence

Apply these rules in order and retain every contributing reason:

1. **Structural conflicts → Needs review.** Examples:
   - VEX says `component_not_present`, but the component is in the SBOM;
   - VEX says `vulnerable_code_not_present`, but that exact symbol is resolved in the artifact;
   - VEX says `vulnerable_code_not_in_execute_path`, but the analyzer reaches that symbol.
2. **Delivered fix/removal or exact VEX `fixed` → Resolved.** A proposed upgrade is not a fix;
   the regenerated SBOM or exact matching VEX is the evidence.
3. **Exact VEX `known_affected` or positive reachability → Actionable.** Component reachability
   is sufficient to keep a finding active even without vulnerable-method data.
4. **Exact VEX `known_not_affected` → Deferrable with evidence**, unless rule 1 applies. The
   justifications `vulnerable_code_cannot_be_controlled_by_adversary` and
   `inline_mitigations_already_exist` are not contradicted merely because the component is called.
5. **VEX `under_investigation`, reference-only evidence, incomplete analysis, or incompatible
   evidence → Needs review.**
6. **Current sufficiently complete negative reachability → Deferrable with evidence**, except a
   KEV finding or an observed Spring/AOP/proxy/reflection completeness blocker remains Needs
   review without exact supplier VEX.
7. **Nothing usable → Unassessed.**

No user-editable lane is stored. The lane is a projection of source evidence with stable reason
codes such as `COMPONENT_REACHED`, `VULNERABLE_SYMBOL_REACHED`, `VEX_KNOWN_AFFECTED`,
`VEX_NOT_AFFECTED`, `ANALYSIS_INCOMPLETE`, `KEV_NEGATIVE_REQUIRES_REVIEW`, and
`EVIDENCE_CONFLICT`.

---

## 5. Delivery sequence

### Stage 0 — JVM engine and fixture spike

No production dependency or schema change is made until this spike is reviewed.

#### Real multi-module demonstration workspace

Extend the existing throwaway high-vulnerability Maven project outside the repository with
compiled production code that demonstrates four cases:

1. **Direct call:** an application method calls a class in a vulnerable library.
2. **Transitive call:** application code calls Spring and a bytecode path continues from Spring
   into Jackson.
3. **Present but uncalled:** a vulnerable dependency remains in the SBOM/classpath but has no
   bytecode call path from any production workspace method.
4. **Module isolation:** the same dependency is reached from `module-a` and not reached from
   `module-b`.

The deliberately vulnerable POM stays outside the public repository, as required by AGENTS.md.
The spike records commands, tool versions and expected call paths. The safe synthetic equivalent
is now automated in `WalaReachabilityEngineTest`: it compiles the four cases into temporary
classes/JARs, asserts the direct and Spring-mediated Jackson edges, confirms the unused library is
not reached from `module-b`, and executes neither a Maven build nor the fixture code. It does not
replace the pending live check against the external high-vulnerability workspace.

#### Baseline and candidates

Compare:

- **`jdeps` baseline:** zero added dependency and useful class/package relationships, but not a
  method-level call graph;
- **SootUp:** method-aware JVM bytecode analysis with at least CHA and RTA call-graph modes;
- **WALA:** a second mature method-aware candidate so the decision is not made from one engine;
  and
- a minimal in-house bytecode edge reader only as a measured fallback if existing engines fail
  the locked-down/dependency-weight bar. It is not the preferred starting point.

#### Evaluation matrix

| Criterion | Required evidence |
|---|---|
| Four cases | Exact expected result and inspectable path for each case |
| Java compatibility | Java 21 floor and current class-file versions used by the workspace |
| Call precision | Static, special, virtual, interface and invokedynamic behavior documented |
| Incomplete classpath | Missing classes reported; never silently interpreted as “not reached” |
| Explainability | Caller, callee, owning artifact and source line when debug data permits |
| Module isolation | Results stay attached to the correct CycloneDX root/module |
| Offline operation | No registry/API access and no workspace build during analysis |
| Safety | Reads class files/jars only; executes neither application nor build/plugin code |
| Cancellation | Cooperative cancellation or isolation that can terminate bounded work |
| Performance | Cold/warm time and peak memory on the real workspace and a larger project |
| Dependency cost | Added jars/transitives, licenses and effect on SBOMscope's own SBOM |
| Maintenance | Active release history, documented API and output stability |

#### Decision — WALA 1.8.0 selected (2026-08-02)

**Use WALA 1.8.0 behind a SBOMscope reachability-engine interface.** The maintainer selected it
after the local spike, rather than selecting an engine from documentation alone.

The decision is founded on these checked results:

| Check | Result |
|---|---|
| Four-case synthetic, multi-module workspace | WALA found the direct application-to-library call, the application-to-framework-to-library transitive path, and kept the dependency present-but-uncalled in `module-b` negative. |
| Inspectable result | The spike produced method-to-method edges, including the two intermediate framework/library hops, not merely a component boolean. |
| Locked-down/offline boundary | WALA analyses already-built `.class` files and dependency JARs in an SBOMscope-owned worker JVM. It does not execute workspace code, invoke a workspace build, fetch data, or use the Maven probe repository. |
| Java currency | WALA 1.8.0 requires Java 17+ and was exercised here on Java 25 against Java 21 bytecode. A real Java 21 runtime test remains an implementation gate because Java 21 is SBOMscope's supported floor. |
| Dependency cost | The resolved closure is 11 JARs / about 6.1 MiB: WALA core, util and Shrike plus Guava, Gson, JSpecify, `org.json` and small support artifacts. This is accepted for actual call-graph capability, not for incidental convenience. |
| Alternatives | `jdeps` showed only class/package relationships; the small ASM reader found static edges but cannot safely model virtual/interface dispatch and framework paths. SootUp 1.1.2 brought a much larger, Android-oriented closure and produced no edges on the direct fixture. WALA 1.5.9 failed modern-JDK module discovery. |
| Maintenance and licensing | WALA 1.8.0 is a current Java 17+ release with modern-JDK fixes and is EPL-2.0; Guava 33.6.0 is current and a WALA implementation dependency, not an SBOMscope application API. The implementation must retain notices, expose WALA source/licence information, regenerate SBOMscope's SBOM and scan the added closure. |

Implementation guardrails:

- use WALA's concrete `ZeroXContainerCFABuilder`, with the same standard selectors and bypass
  logic as the former convenience factory; the direct application-to-library edge test pins it;
- keep WALA's input classpath distinct from `~/.sbomscope/probe-repo`: it is assembled only from
  existing workspace outputs and dependency JARs, never from a Maven probe cache;
- report missing classes and unresolved edges as incomplete/Unknown, never as not reached;
- add Maven dependency-convergence and Java 21 compatibility checks; and
- package complete third-party notices before distribution, including EPL-2.0 and the resolved
  third-party licence inventory.

#### Decision — implicit refresh; read-only Maven cache (2026-08-02)

Workspace reachability has no standalone **Rescan** control and does not poll or watch a working
directory. The user expresses intent by attaching a workspace to an SBOM and opening a finding or
Inspector view that needs its evidence. At those points SBOMscope computes a cheap fingerprint of
the already-built production outputs and selected dependency JARs. If there is no completed run
for that fingerprint, it queues analysis automatically and exposes that work in Processes; if
the fingerprint is unchanged, it reuses the recorded evidence. This avoids a second user action
without repeatedly racing a user's build or silently consuming CPU in the background.

The initial Maven input contract is:

- each mapped workspace module must already have `target/classes`; SBOMscope never builds it and
  tells the user to run their usual build when it is absent;
- dependency JARs are resolved read-only from a user-configured Maven local-repository directory,
  defaulting to `~/.m2/repository`; the exact SBOM Maven purl/version determines the expected
  path;
- the configured directory is visibly labelled **read-only** in Settings. SBOMscope does not
  create, download, alter, or clean anything there; and
- it is expressly different from the app-owned `~/.sbomscope/probe-repo`. The probe repository is
  never an analysis input, and changing the analysis cache cannot change probe behaviour.

Custom Maven caches are supported by changing that directory in Settings. An absent unreadable or
missing dependency JAR makes the affected module/run incomplete rather than negative.

#### Decision — isolated worker and strong cancellation (2026-08-02)

Each WALA run starts a separate **SBOMscope-owned worker JVM** through the internal
`--reachability-worker <input.json> <output.json>` mode. This is an implementation detail; users
continue to start SBOMscope normally and never supply that argument. The parent sends the worker
only a JSON list of already-approved class-output and JAR paths, then reads bounded per-component
coverage and representative paths; the full WALA graph never crosses into the parent JVM.
The worker has no workspace-build, Maven or network step.

The parent owns the worker process tree, exposes its queued/running state in **Monitoring →
Processes**, and can stop it safely. Stop terminates only that worker tree; it never interrupts the
user's build, their Maven process or the SBOMscope server. The default wall-clock ceiling is **10
minutes**, configurable from 1 to 60 minutes in Settings. Timeout is a failed/incomplete analysis;
an explicit Stop is recorded distinctly as stopped. Parent-owned request/output/stderr files live
under SBOMscope's data directory and are deleted best-effort after the outcome.

#### Spike exit decision

**Met: WALA 1.8.0 is the selected engine.** Missing inputs must still become Unknown, not
negative. The class/package-reference baseline remains a diagnostic/fallback tool, not the
reachability feature's verdict engine.

### Stage 1 — Analysis inputs and module mapping

**Completed, 2026-08-03:** the JVM implementation discovers existing
`target/classes` directories, exact Maven JARs in the user-configured read-only cache, and a
file-level input fingerprint. It excludes test output and never invokes Maven. The remaining
mapping work is to tie aggregate CycloneDX application roots to discovered module labels rather
than treating filesystem labels as final SBOM identity.

- Discover existing production output (`target/classes`) without running Maven.
- Map aggregate CycloneDX roots to workspace modules by exact Maven coordinates and build output;
  ambiguous or missing mappings stay Unknown. **Initial implementation:** read the module POM only,
  taking direct or parent group/version values; unresolved properties, unreadable POMs and duplicate
  matches are intentionally Needs review rather than inferred. Full effective-model support remains
  out of scope unless a separately approved explicit Maven action is introduced.
- Resolve dependency jars already present on disk from exact SBOM identities and the user's local
  build environment without modifying the repository or fetching artifacts.
- Record hashes/paths for analyzed artifacts where available.
- Exclude test outputs by default; add an explicitly separate test-reachability analysis later if
  a real use case appears.
- Refuse a negative conclusion when the required classpath cannot be assembled completely enough
  for the selected engine's stated contract.

The exact classpath-discovery mechanism is a spike decision. Invoking a Maven goal can execute
plugin/build machinery and contact repositories, so it is not an automatic fallback. If a later
explicit user action delegates classpath construction to Maven, it must use the existing process,
privacy, logging, timeout and cancellation rules.

### Stage 2 — Persist reachability evidence

**Completed, 2026-08-03:** additive migrations V6–V8 store immutable fingerprinted run lifecycle
records and per-component/per-module method-path evidence. The first UI slice uses a compact JSON
path representation and keeps results per SBOM/run; module-to-SBOM-root and advisory-symbol fields
remain deliberately absent until their sources are available.

Use additive Flyway migrations. Conceptual records:

- `workspace_analysis_run`: SBOM, workspace fingerprint, analyzer/version/algorithm, lifecycle,
  coverage summary, timestamps and failure/cancellation;
- `workspace_analysis_module`: run, SBOM root, workspace module, production outputs, mapping state
  and missing inputs;
- `reachability_evidence`: run/module, component purl/bom-ref, optional advisory/symbol, evidence
  kind and reason; and
- `reachability_edge` or a compact path representation: ordered caller/callee/artifact/source
  evidence for the displayed paths.

Reachability is **per SBOM, workspace and module**. It must never be attached globally to the
shared `vulnerability_finding` row merely because findings are cached by purl.

Cache invalidation includes SBOM identity, workspace/build-output fingerprint, analyzer version,
algorithm/configuration, artifact hashes and vulnerable-symbol source identity.

### Stage 3 — Component-boundary reachability MVP

**Completed MVP, 2026-08-03:** opening the Component Inspector's **Workspace usage** tab
implicitly queues one single-threaded, offline WALA run when the stored fingerprint is stale. It
shows up to ten inspectable method paths per module. It does not run a workspace build or Maven
probe. WALA runs in a separate SBOMscope-owned JVM; Monitoring → Processes shows its state and
Stop terminates only that process tree. The configurable default wall-clock limit is 10 minutes.

- Build a graph from every compiled production workspace method.
- Traverse direct and transitive bytecode calls through dependency jars.
- Attribute every class/method to the exact SBOM component where possible.
- [x] Return at most ten shortest useful paths while computing coverage independently of the
  display cap. Coverage is the exact finite set of compiled production methods in the module
  that can reach the component boundary; it is not an unbounded count of cyclic graph walks.
- Keep module results separate.
- [x] Report direct calls distinctly from transitive calls in the Inspector: a two-method path is
  direct; additional methods are labelled as an explicit transitive path with their intermediate
  method count.
- Produce Not reached only when the run's completeness gate passes; otherwise Unknown/incomplete.
- [x] Make analysis asynchronous, cancellable and visible in Monitoring → Processes.
- Log the external/embedded engine run and outcome without logging source contents.

Inspector first: show paths and limitations before adding any table-level assessment. A live
reader should be able to challenge the evidence before it changes prioritization.

#### Decision — worker memory ceiling (2026-08-03)

The isolated WALA worker has a configurable **1 GiB heap default** (range 256 MiB–8 GiB), in
addition to its configurable ten-minute wall-clock default. A real multi-module probe reached
approximately 2 GiB before completing, so time alone was not an adequate resource boundary.
The parent can still stop the worker process tree; a heap exhaustion is an incomplete failed run,
never negative evidence.

### Stage 3b — Correctness hardening before VEX (blocking patch set)

**Completed, 2026-08-03.** The review findings below were blocking because the MVP evidence was
not yet safe to drive assessment lanes, exclusion recommendations or VEX statements. The patch
set now establishes the hardened contract Stage 4 may build on.

- [x] **Isolate module classpaths and version attribution.** The former aggregate WALA scope
  combines every module output and every dependency jar in one application class loader, then
  attributes graph nodes by class name. That can merge two versions of the same class and let one
  module's dependencies bleed into another module's result. Analyze each mapped module against
  that module's exact SBOM dependency closure, and preserve component/version identity throughout
  evaluation. Treat duplicate or unresolved ownership as incomplete/ambiguous evidence, never as
  proof that every matching component is reached.
- [x] **Make verdicts independent of representative-route limits.** Exact coverage and displayed
  paths are separate products. A component with reachable methods remains Reachable even when its
  path lies beyond the display depth or path-search budget; an empty representative-path list is a
  presentation limitation, not No call path. Surface that limitation explicitly.
- [x] **Make run reuse and recovery status-aware.** Reuse only a valid completed run. Failed,
  stopped and abandoned queued/running runs must be eligible for an implicit retry. On startup,
  reconcile durable queued/running records that no longer have a live task or worker. Include the
  WALA version, algorithm/configuration, relevant settings and module-mapping inputs in the cache
  identity. Make cancellation and final-state updates race-safe so Stop cannot be overwritten by a
  late Running or Completed update.
- [x] **Bound the worker result presented to the parent JVM.** The worker heap limit does not
  protect SBOMscope if the worker serializes an unbounded graph and the parent deserializes it in
  full. Prefer computing bounded, per-module evidence inside the worker and returning only coverage,
  completeness and representative paths. Any retained interchange format also needs explicit size
  limits and rejection as an incomplete failed run rather than a negative result.
- [x] **Commit results atomically.** Module rows, evidence rows and the final Completed state must
  be written in one transaction, with Completed written only after all evidence succeeds. An insert
  failure must roll the run back or leave it Failed/incomplete, never Completed with missing or
  partial evidence.
- [x] **Add service/repository integration and adversarial regression coverage.** In addition to
  the existing engine/unit tests, pin the lifecycle, persistence and cross-module interactions
  listed below.

Exit criteria:

- a two-module fixture containing two versions of the same library reaches only the correct
  version in the correct module, without classpath leakage;
- a real path beyond the display-depth or search-budget cap still produces Reachable coverage,
  while the UI honestly reports that no representative path could be displayed;
- an out-of-memory failure followed by a heap-setting change retries, a stopped run can retry
  implicitly, startup reconciles abandoned runs, and cancellation cannot leave a permanent Running
  record;
- a successful worker cannot return an unbounded payload to the parent, and every timeout,
  output-limit or heap failure remains Failed/incomplete rather than Not reached; and
- an injected persistence failure rolls back module/evidence/final-status changes, leaving no
  partially populated Completed run.

### Stage 3c — Source-run release hardening (blocking patch set)

**Completed 2026-08-03, added after the public-release review.** SBOMscope currently has no binary
distribution; users clone the public repository, build it and run the same Spring Boot server on
their own machines. That removes binary packaging as a release concern, but it does not change the
runtime security boundary. This patch set is complete, so the workspace feature can be recommended
to public source-built users with its documented evidence limitations.

- [x] **Bind the unauthenticated local server to loopback by default.** `application.yml` now pins
  `server.address` to `127.0.0.1`, with a regression test and public warning. Any deliberate
  non-loopback deployment remains an explicit override that must supply its own access boundary;
  SBOMscope has no authentication or multi-user security boundary, and CORS is not access control.
- [x] **Contain every SBOM-derived Maven artifact path.** Maven group, name and version originate
  in an uploaded document. Discovery now rejects absolute, separator-bearing, invalid and traversal
  segments, then requires the normalized candidate to remain below the normalized configured
  read-only Maven repository. Rejected coordinates produce an incomplete missing-input result;
  Windows and Unix escape cases are pinned in tests.
- [x] **Include workspace outputs in class-ownership ambiguity.** Ownership now includes production
  and supporting workspace outputs as well as dependency JARs. A class-name-only WALA edge with
  more than one possible owner is reported as ambiguous/Needs review rather than attributed to an
  exact dependency version; workspace-output-versus-JAR collision is pinned in a regression test.
- [x] **Finish the parent-process resource boundary.** Reflection-marker discovery streams at most
  16 MiB per class and treats an oversized/unreadable file conservatively. Worker stdout is
  discarded; stderr is continuously drained but retained only to 64 KiB with a truncation marker,
  and the parent reads at most 8 KiB when surfacing a failure.
- [x] **Close source-release repository hygiene.** Ensure `ReachabilityWorkerResult.java`,
  `WorkspaceReachabilityRepositoryTest.java` and `WorkspaceReachabilityServiceTest.java` are tracked
  in the maintainer's commit. The first is required to compile; the latter two pin lifecycle and
  atomic persistence.
- [x] **Resolve or record the React Router audit result.** The current production audit reports
  GHSA-qwww-vcr4-c8h2. SBOMscope uses a static `BrowserRouter`, not the advisory's unstable RSC
  APIs, so the reviewed applicability is negative; nevertheless, prefer a patched compatible
  release when available, otherwise record the non-applicability explicitly so a public scanner
  alert is not left unexplained.

The dependency check has no patched compatible release as of 2026-08-03: the advisory names 8.3.0,
which is not published, and npm's suggested 7.11.0 downgrade reintroduces numerous broader router,
navigation and SSR advisories. SBOMscope therefore remains on 7.18.1. GHSA-qwww-vcr4-c8h2 applies
to unstable RSC action handling; SBOMscope is a static `BrowserRouter` SPA and uses neither RSC nor
React Router actions/data routes, so its applicability is reviewed as negative. Recheck when a
patched compatible release exists.

Release evidence already obtained and not open work:

- no secrets or developer-specific absolute paths were found in the public diff;
- the WALA dependency tree matches `THIRD_PARTY_NOTICES.md`, including EPL-2.0 source/licence links;
- the full clean build passed 285 backend and 28 frontend tests; and
- the WALA engine and isolated-worker tests passed on Java 21, the supported runtime floor.

### Stage 4 — Vulnerable-symbol enhancement

This stage is gated by structured local symbol data. The current Maven OSV archive has none.

When a supported source supplies symbols:

- retain source document/advisory and alias provenance;
- normalize owner type, method name and descriptor/signature without discarding ambiguity;
- distinguish absent symbol, unresolved signature and reached/not-reached symbol;
- report unmatched/ambiguous symbols rather than interpreting them as uncalled; and
- store the exact path to a reached vulnerable symbol.

Do not scrape method names from advisory prose for an automated negative verdict.

### Stage 5 — VEX Tier A: consume documents the user has

Define one normalized statement model before format adapters:

- source document hash, format/version, author, timestamp and document/product identity;
- vulnerability id plus aliases;
- subject product identity/version and optional affected component identity;
- status: affected, fixed, not affected or under investigation;
- not-affected justification;
- impact, mitigation/action and response text where supplied; and
- exact match, ambiguous match or unmatched state.

Implement adapters in this order:

1. **Embedded CycloneDX VEX compatibility.** During the existing SBOM upload, preserve and normalize any
   vulnerability `analysis` statements instead of discarding them. The statement's product is
   the uploaded BOM subject; affected component references must resolve inside that BOM. This is
   a low-cost compatibility path, not the expected source for SBOMscope's Maven-generated BOMs.
2. **Standalone CycloneDX VEX upload.** Reuse the same normalized adapter for a separate
   CycloneDX document and require an exact match to the analyzed BOM subject/version.
3. **OpenVEX upload.** Add a small JSON-LD adapter using the official schema and examples.
   `vexctl` may generate, merge and validate fixtures during development, but it is neither
   downloaded nor invoked by the shipped application.
4. **CSAF 2.0/2.1 upload.** Resolve the CSAF product tree and relationships before producing
   normalized statements. Use the official schema/test corpus plus a real supplier document;
   malformed or unresolved relationships stay unmatched rather than being guessed.

Use Jackson for these adapters, consistent with the existing CycloneDX parser. Do not add
`cyclonedx-core-java` merely for VEX: the roadmap already rejected its runtime dependency weight.
Reconsider only if the adapters demonstrate a validation or version-compatibility problem that
our narrow parsing cannot handle safely.

Implement the first adapter against an official or real supplier fixture, not a handwritten
example chosen only because it is easy. Keep original document bytes/hash and parser diagnostics.
Unmatched statements are counted and shown.

Matching requirements:

- product/SBOM identity and version are mandatory for an assessment lane;
- purl/component identity is preferred where the statement scopes itself to a component;
- vulnerability aliases use the same normalized alias group as findings;
- a CVE-only match with no product match is informative but cannot defer a finding; and
- statements for another version remain visible but inapplicable.

Tier A reads VEX; it does not author it and provides no text box or manual status selector.

### Stage 5b — VEX Tier B: measured bulk supplier feeds

After Tier A works with real documents, measure Red Hat's bulk CSAF VEX archive as the first feed
candidate. It fits the bulk-public-data boundary because an explicit download obtains the whole
archive without revealing which components the user has.

The implementation gate must settle:

- how `.tar.zst` is read without an unjustified dependency increase;
- detached-signature and SHA-256 verification, including key provenance and rotation;
- exact Red Hat product/build and purl matching, including Maven qualifiers;
- archive version, `changes.csv` and `deletions.csv` semantics;
- source staleness, licensing and Red Hat attribution in the UI/export; and
- measured coverage of the Maven/npm findings in the adversarial and SBOMscope fixtures.

Only exact matching Red Hat product/component identities may affect an assessment lane. Ordinary
upstream Maven coordinates that merely resemble a Red Hat middleware component remain unmatched.
Do not add per-CVE Red Hat API/file calls or generic supplier-document discovery. Additional bulk
feeds require the same product-scope, license, integrity, privacy and coverage evaluation.

### Stage 5c — optional evidence-backed VEX draft export

This is deliberately after VEX ingestion, matching and reachability. Review it as a separate
product decision before implementation.

- Export a **standalone** CycloneDX VEX document linked to the analyzed BOM and exact components;
  do not rewrite the uploaded inventory document.
- Include analyzer identity/version, workspace/build fingerprint, coverage, missing inputs,
  evidence timestamp and the human-readable limitations in `analysis.detail` or associated
  properties/evidence.
- Map only policy results that have an exact standard representation. A complete negative graph
  may propose `not_affected` / `code_not_reachable`; incomplete evidence remains in triage and
  never produces a not-affected assertion.
- Label the result **SBOMscope-generated draft — not supplier-attested**. SBOMscope does not hold
  signing identities or claim to be the product supplier.
- Let the user validate, review, sign/attest and publish it in their existing release/security
  pipeline. Do not add manual status or free-text judgment fields merely to turn SBOMscope into a
  VEX authoring system.
- A later re-import of the published/attested document is independent supplier evidence; do not
  overwrite the underlying reachability run or lose the distinction between them.

### Stage 6 — Assessment projection

Implement one pure, unit-tested assessment policy over:

- finding/component presence;
- reachability evidence and completeness;
- matching VEX statements and structural conflicts;
- KEV, EPSS and severity context; and
- remediation/rescan evidence.

The findings view and Excel export must consume the same projection. Do not derive the lane after
pagination in one endpoint and independently in the exporter. If filtering/counting by lane is
added later, the projection needs a queryable/materialized form with explicit invalidation rather
than a second implementation of the rules.

### Stage 7 — Minimal UI and export

The findings table is already dense. Replace the planned **Workspace usage** column with one
compact, sortable **Assessment** column rather than adding separate reachability and VEX columns.

- Badge: Actionable / Review / Deferrable / Resolved / Unassessed.
- Tooltip or accessible label: primary reason, never only a color.
- Inspector: full reachability paths, VEX source/author/status/justification, coverage, conflicts,
  stale inputs and all reason codes.
- Export: lane, reasons, reachability kind, direct/transitive path summary, analysis coverage,
  VEX source/status/justification/author/timestamp, KEV, EPSS and severity.

The first release keeps every lane visible. It does not silently suppress VEX-not-affected or
deferrable rows. After live use, a collapsed Deferrable/Resolved presentation can be considered
only with always-visible counts and one-step access to every row.

---

## 6. Verification strategy

### Policy tests

Pin every precedence edge, including:

- component reached with no VEX → Actionable;
- vulnerable symbol reached → Actionable;
- exact VEX affected plus negative analysis → Actionable;
- exact VEX not affected plus component reached → Deferrable unless structurally contradictory;
- `vulnerable_code_not_in_execute_path` plus symbol reached → Needs review/conflict;
- complete negative analysis with KEV → Needs review;
- complete negative analysis without stronger evidence → Deferrable;
- incomplete analysis → never Deferrable; and
- fixed/removed only after exact VEX or regenerated clean SBOM → Resolved.

### Persistence and query tests

- The same purl can be reached in one SBOM/module and not another.
- A workspace change invalidates only evidence derived from that workspace/build.
- VEX for version A never applies to version B.
- Unmatched VEX statements survive import and remain visible.
- View and export produce identical assessment lanes and reasons.
- Cancelling a run cannot leave a partial result marked complete.

### Live checks

- Run all four spike cases in the external multi-module workspace.
- Inspect call paths and missing-edge reporting rather than accepting booleans.
- Confirm no network traffic and no build/application code execution during analysis.
- Measure cold/warm duration and peak memory.
- Verify the Inspector and findings table in the running application, including console errors,
  dense-table layout and Excel output.

---

## 7. Decision status and remaining gates

1. [x] **JVM engine:** WALA 1.8.0, offline inside the bounded worker JVM; see the recorded decision
   and Stage 1/3 implementation.
2. [x] **Negative-result completeness:** missing output/JAR/module mapping, Spring/AOP/proxy or
   reflection evidence, ambiguous class ownership and bounded-analysis failures prevent Not reached.
3. [x] **Resolved JAR location:** exact SBOM coordinates below the explicitly configured read-only
   Maven local cache, with path containment; never build, fetch or use the probe repository.
4. [x] **Invalidation:** fingerprint exact production/supporting outputs, dependency JAR metadata,
   module mappings, engine/algorithm and relevant analysis settings; failed/stopped runs retry
   implicitly.
5. [ ] Which official or supplier CycloneDX VEX document becomes the first Tier A fixture?
6. [ ] What measured coverage does Red Hat's bulk feed provide for Maven/npm components we can match
   exactly, and which zstd/signature implementation clears the dependency-weight bar?
7. [ ] Should SBOMscope offer the Stage 5c unsigned, evidence-backed CycloneDX VEX draft export after
   the consumption path is proven, or leave all VEX authoring to external product-security tools?
8. [ ] Does the Assessment column sort need a fixed lane order only, or severity as a secondary key?
   Do not add compound-sort UI merely to answer this; the query can use a documented stable
   tiebreaker if live use demonstrates the need.

---

## 8. Completion criteria

This plan is complete when:

- the four-case multi-module workspace produces inspectable, module-correct paths offline;
- a missing/incomplete classpath yields Unknown, never a negative;
- component-boundary reachability works without vulnerable-method data;
- a real VEX document is normalized, matched with exact product/version scope and displayed with
  provenance;
- every finding receives one deterministic assessment lane and reason set from the shared policy;
- deferrable findings remain visible and exportable;
- stale or conflicting evidence automatically prevents unsafe deferral; and
- the running UI and Excel export agree on every lane and its evidence.
