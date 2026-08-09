# Detection Heuristics

Phase 3 heuristics combine Phase 2 evidence into deterministic findings. They do
not execute samples and they do not produce a final malware verdict.

## Implemented Heuristics

`HEUR-PERSISTENCE-001`: Persistence-like strings with interpreter indicator.
Triggers when registry-path strings co-occur with command/interpreter strings.
Contribution: `1.2 * confidence 0.68`.

`HEUR-PROC-001`: Process manipulation with memory management.
Triggers when process/thread manipulation capability co-occurs with
memory-management capability. Contribution: `1.4 * confidence 0.72`.

`HEUR-MEM-001`: Writable executable section.
Triggers when a section is both writable and executable. Contribution:
`1.0 * confidence 0.76`.

`HEUR-OBF-001`: Multiple possible packing indicators.
Triggers when at least two conservative packing indicators co-occur.
Contribution: `0.9 * confidence 0.66`.

`HEUR-SCRIPT-001`: Command or interpreter reference.
Triggers on command/interpreter strings. Contribution: `0.5 * confidence 0.60`.

`HEUR-NET-001`: Networking capability with network indicator.
Triggers when networking capability co-occurs with URL, domain, IPv4, or IPv6
strings. Contribution: `0.8 * confidence 0.64`.

`HEUR-PE-001`: Entry point in unusual section.
Triggers when Phase 2 observed an unusual PE entry-point section. Contribution:
`0.9 * confidence 0.68`.

## False-Positive Strategy

Heuristics are combination-focused. A single networking API or command string is
kept weak because benign updaters, administration tools, debuggers, installers,
security products, and development tools can legitimately contain these
capabilities.

Every heuristic explanation says why it fired and includes caveats where relevant.

