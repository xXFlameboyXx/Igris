# Disassembly

Phase 4 uses Capstone for offline disassembly. Samples are never executed.

## Architecture Detection

Architecture comes from Phase 1 metadata:

- PE `x86` -> Capstone x86 32-bit mode
- PE/ELF `x86_64` -> Capstone x86 64-bit mode

Other architectures currently return `unsupported`.

## Function Discovery

Igris starts at the entry point and follows direct internal call targets where
they land in executable sections. This discovers entry-oriented function islands
without pretending to be a full recursive-descent reverse-engineering suite.

Each function records:

- function ID
- address
- size
- normalized instructions
- calls
- callers
- callees
- referenced strings
- referenced APIs
- basic-block count
- cyclomatic-style complexity
- function evidence

## Instruction Normalization

Instructions include address, mnemonic, operand string, size, hex bytes,
normalized text, call/jump flags, and direct targets where available.

## String And API Correlation

Phase 4 maps Phase 2 string offsets into virtual addresses. If an instruction
references one of those addresses, the string is attached to the function. If the
referenced string names an API observed by static analysis, the API is attached
to that function too.

This enables richer evidence such as:

```text
function references persistence-related string
and references sensitive API capability
```

The correlation is evidence, not proof of maliciousness.

