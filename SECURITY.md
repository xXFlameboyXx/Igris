# Security Policy and Threat Model

Igris will eventually process hostile binaries and hostile metadata. Phase 0
therefore establishes boundaries before implementing upload, parsing, analysis,
or sandbox execution.

## Environment Boundaries

Development environment:
The developer workstation used for writing code, running unit tests, and building
the project. It must use only benign synthetic test files. It must never execute
uploaded or suspicious binaries.

Igris application environment:
The API, frontend, workers, database, and storage services that coordinate analysis.
This environment may eventually store hostile files as inert data, but it must not
execute them.

Isolated analysis environment:
A future controlled environment for static parsers, feature extraction, and tools
that inspect samples as data. It must run with least privilege and constrained
resources because parsers can be exploitable.

Future sandbox environment:
A disposable, isolated environment for dynamic execution only. It must be separated
from the developer and application environments, deny access to secrets, constrain
network access, and be destroyed after each run.

## Non-Goals and Prohibited Work

- No endpoint security evasion.
- No persistence mechanisms.
- No credential theft.
- No real-world malware deployment.
- No execution of arbitrary uploaded binaries on developer or application hosts.

## Vulnerability Reporting

Report suspected vulnerabilities privately to the project maintainers. Include
affected component, reproduction steps, impact, and suggested mitigation when known.
Do not attach live malware or credential material.

## Threat Model

| Threat | Attacker | Asset | Attack Surface | Possible Impact | Mitigation | Residual Risk |
| --- | --- | --- | --- | --- | --- | --- |
| Malicious uploaded files | External user or compromised analyst account | Developer host, application host, storage | Future upload and storage paths | Code execution, data loss, service compromise | Treat samples as inert hostile data; never execute on developer or app host; isolate analysis | Parser bugs may still expose isolated analysis services |
| Malformed PE/ELF files | External user | Parser process, evidence integrity | Future static analysis parsers | Parser crash, memory corruption, false evidence | Run parsers with least privilege, timeouts, resource limits, and fuzzing | Third-party parser vulnerabilities remain possible |
| Resource exhaustion | External user | API availability, worker capacity, storage | Requests, uploads, queues | Denial of service and high cost | Request limits, file size caps, queue quotas, timeouts, rate limits | Distributed abuse may require upstream protection |
| Zip or decompression bombs | External user | Storage, CPU, parser process | Future archive intake | Disk exhaustion, CPU exhaustion | Archive expansion limits, nested depth limits, compression ratio checks | Sophisticated archive formats can bypass naive checks |
| Oversized files | External user | API and storage availability | Future upload endpoint | Memory pressure, storage exhaustion | Configured max size, streaming validation, object-store quotas | Limit tuning may be needed per deployment |
| Path traversal | External user | Filesystem and stored evidence | Filenames, archive entries, export paths | Overwrite or disclose files | Ignore user paths, generate storage IDs, normalize and confine paths | New export features need repeated review |
| Malicious filenames | External user | Logs, UI, analyst workstation | Upload metadata and reports | Log injection, UI confusion, unsafe downloads | Store original names as data, escape output, sanitize headers | Analyst tooling outside Igris may mishandle names |
| Malicious metadata | External user | Database, UI, reports | Parsed file metadata, user fields | XSS, report poisoning, query issues | Validate schemas, encode UI output, parameterize database access | Rich report formats need careful escaping |
| API abuse | External user | API availability and data | Public API endpoints | Denial of service, enumeration, unauthorized actions | Authentication, authorization, rate limits, request IDs, audit logs | Public deployments need edge controls |
| Unauthorized analysis access | External user or insider | Sample data and reports | API, frontend, database | Sensitive sample or report disclosure | RBAC, scoped tokens, tenant checks, audit logs | Authorization bugs remain high impact |
| Database injection | External user | Database integrity and confidentiality | Query parameters, filters | Data disclosure or mutation | Parameterized queries, ORM query builders, input validation | Raw SQL must be reviewed carefully |
| Unsafe command execution | External user or developer mistake | Host systems | Future tool orchestration | Code execution, host compromise | Avoid shell composition, use structured subprocess APIs, allowlist tools | Reverse engineering tools may need wrappers |
| Sandbox escape | Malicious sample | Host and network | Future dynamic execution | Host compromise, lateral movement | Disposable VMs or equivalent isolation, snapshots, no secrets, network controls | Sandbox escapes are plausible and must be assumed |
| Cross-analysis data leakage | External user or analyst | Other samples and tenants | Storage, sandbox reuse, caches | Confidentiality breach and evidence contamination | Per-analysis workspaces, cleanup, tenant isolation, cache boundaries | Cleanup bugs can leak derived artifacts |
| Secrets exposure | External user or insider | Credentials and signing keys | Env vars, logs, CI, reports | Credential theft, infrastructure compromise | Secret stores, redaction, no secrets in logs, least privilege | Operational mistakes remain possible |
| Log injection | External user | Logs and incident response workflows | Request IDs, filenames, metadata | Confusing audit trails or hiding activity | Sanitize request IDs, structured JSON logs, escape metadata | Downstream log viewers need safe rendering |

