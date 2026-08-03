# Third-party notices

SBOMscope is licensed under Apache-2.0. Its runnable distribution includes third-party
components. This file records the additional Phase 9 reachability-engine closure; the generated
CycloneDX SBOM remains the complete, versioned component inventory for each release.

## WALA reachability engine

SBOMscope uses **WALA 1.8.0**, including `com.ibm.wala.core`, `com.ibm.wala.util` and
`com.ibm.wala.shrike`, to construct JVM bytecode call graphs. WALA is licensed under the
Eclipse Public License 2.0 (EPL-2.0).

- Project and corresponding source: <https://github.com/wala/WALA/tree/v1.8.0>
- Licence text: <https://www.eclipse.org/legal/epl-2.0/>

SBOMscope does not modify WALA. Its own adapter code is separate from WALA and remains under the
SBOMscope licence. If a distributed version ever includes WALA modifications, the modified WALA
source must be made available under EPL-2.0.

## WALA 1.8.0 runtime dependencies

| Component | Licence | Source / notice |
|---|---|---|
| `com.google.guava:guava:33.6.0-jre` | Apache-2.0 | <https://github.com/google/guava> |
| `com.google.guava:failureaccess:1.0.3` | Apache-2.0 | <https://github.com/google/guava> |
| `com.google.guava:listenablefuture:9999.0-empty-to-avoid-conflict-with-guava` | Apache-2.0 | <https://github.com/google/guava> |
| `com.google.j2objc:j2objc-annotations:3.1` | Apache-2.0 | <https://github.com/google/j2objc> |
| `com.google.code.gson:gson:2.13.2` | Apache-2.0 | <https://github.com/google/gson> |
| `com.google.errorprone:error_prone_annotations:2.41.0` | Apache-2.0 | <https://github.com/google/error-prone> |
| `org.jspecify:jspecify:1.0.0` | Apache-2.0 | <https://github.com/jspecify/jspecify> |
| `org.json:json:20260522` | Public Domain | <https://github.com/stleary/JSON-java/tree/20260522> |

Apache-2.0 text is distributed as [LICENSE](LICENSE). The exact resolved closure, including any
version changes caused by dependency management, must be regenerated into SBOMscope's CycloneDX
SBOM and reviewed before each distribution.
