# Reverse Engineering Overview

Phase 4 introduces safe offline reverse engineering. It begins answering:

```text
What does this executable appear to do internally?
```

Igris still never executes uploaded samples. Reverse analysis operates on stored
bytes and Phase 1/2 metadata only.

## Architecture

Phase 4 runs after file intelligence and static analysis:

```text
Sample bytes
  -> file intelligence
  -> static analysis
  -> Capstone disassembly
  -> functions
  -> basic blocks
  -> CFGs
  -> call graph
  -> function evidence
```

Capstone is used as the disassembly backend. Igris does not reinvent instruction
decoding; it normalizes and correlates the output.

## Artifacts

The normalized schema includes:

- `Disassembly`
- `Function`
- `Instruction`
- `BasicBlock`
- `CFG`
- `CallGraph`
- `FunctionEvidence`
- `ReverseAnalysisResult`

Artifacts are cached on the sample record. The API is synchronous in Phase 4, but
the service boundary is designed so a future worker can run expensive analysis
asynchronously.

## Supported Scope

The initial implementation supports x86 and x86_64 PE/ELF code when entry point
and executable section mappings are available. Unsupported architectures return a
structured `unsupported` result instead of crashing.

## Limitations

This is not full decompilation. Function discovery is entry-point and direct-call
oriented. Indirect calls, packed code, obfuscation, stripped binaries, unsupported
architectures, and unusual file layouts may reduce coverage.

