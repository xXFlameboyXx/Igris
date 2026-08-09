# Control Flow Graphs

Phase 4 builds per-function control-flow graphs for frontend visualization and
future explainability.

## Basic Blocks

Basic block boundaries are created from:

- function start
- direct jump targets inside the function
- fallthrough after terminal branch instructions

Each block records:

- block ID
- start address
- end address
- instruction addresses
- successors
- predecessors
- terminal instruction

## Edges

Edges are currently:

- `jump`
- `fallthrough`

The CFG is exported as JSON with blocks and edges. This keeps the backend output
stable for a future graph visualization frontend.

## Call Graph

The call graph distinguishes:

- internal function calls
- imported/API references inferred through static correlation

Indirect calls and dynamically resolved targets are not resolved in Phase 4.

