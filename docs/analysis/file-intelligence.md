# File Intelligence

Phase 1 answers: "What exactly is this file?" It accepts uploaded files as
hostile data, stores them under controlled internal references, and produces a
normalized JSON representation of foundational metadata.

## Supported Formats

- Windows PE: PE32 and PE32+ headers, COFF header, optional header, sections,
  and data-directory presence for imports, exports, and resources.
- Linux ELF: ELF32 and ELF64 headers, endianness, architecture, entry point,
  program headers, section headers, section names, sizes, and permissions.
- Empty, text, and unknown files.

Format detection is content-based. Igris does not trust filenames, extensions,
client-supplied MIME types, or embedded metadata.

## Hashing

Igris calculates SHA-256, SHA-1, and MD5 incrementally while streaming uploads to
temporary storage. SHA-256 is the canonical sample identifier returned by the API.
MD5 and SHA-1 are included for analyst interoperability, not as trust anchors.

## Entropy

Entropy is calculated with Shannon entropy over byte frequency. The value ranges
from 0 to 8 for byte data. Repeated or highly structured data has lower entropy;
compressed, encrypted, or packed data often has higher entropy.

High entropy is only an indicator. Igris does not label a file as malicious based
on entropy.

## PE Structure

The PE parser validates the DOS magic, PE signature, COFF header, optional header,
image base, entry point, subsystem, section count, and section table. Each section
includes name, virtual size, raw size, virtual address, raw offset,
characteristics, and entropy when raw bytes are present.

Imports, exports, and resources are represented with explicit status values. Phase
1 records whether the corresponding PE data directories are present, absent, or
failed to parse. Deep import/export/resource traversal is deferred.

## ELF Structure

The ELF parser validates the ELF magic, class, endianness, architecture, entry
point, program header table, and section header table. Section names are resolved
from the section-name string table when available. Permissions are derived from
ELF section and program header flags.

Dynamic libraries and symbols are represented with explicit status values. Deeper
dynamic-table and symbol-table extraction is deferred.

## Normalized JSON

The detailed endpoint returns a Phase 1 representation:

```json
{
  "sample": {
    "sample_id": "sha256...",
    "status": "completed"
  },
  "file": {
    "size_bytes": 1024,
    "detected_format": "pe",
    "architecture": "x86",
    "mime_type": "application/vnd.microsoft.portable-executable",
    "entropy": 0.42
  },
  "hashes": {
    "sha256": "...",
    "sha1": "...",
    "md5": "..."
  },
  "format": {
    "detected": "pe",
    "architecture": "x86",
    "mime_type": "application/vnd.microsoft.portable-executable"
  },
  "sections": [],
  "imports": [],
  "exports": [],
  "resources": []
}
```

## Security Controls

- Uploads are streamed; large files are not loaded entirely into memory.
- Configured file size limits are enforced during streaming.
- Temporary files use random internal names.
- Final sample storage uses internal references, not user filenames.
- Filenames are sanitized and never used as filesystem paths.
- Stored sample paths are not exposed through the API.
- No shell commands are constructed from uploaded filenames.
- Files are never executed.
- Parser failures are returned as structured metadata instead of crashing the API.

## Limitations

Phase 1 does not implement malware detection, dynamic execution, sandboxing,
similarity analysis, ML, full disassembly, deep PE import/export/resource parsing,
or full ELF dynamic/symbol parsing.
