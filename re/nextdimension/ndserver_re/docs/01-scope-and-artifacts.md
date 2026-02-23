# NDserver RE Scope And Artifacts

## Objective

Reverse engineer host-side NeXTdimension driver behavior from m68k `NDserver` binaries and their embedded payloads.

Primary goals:

- Recover host message protocol and command dispatch behavior.
- Map host responsibilities vs i860 firmware responsibilities.
- Track stable and changed behavior across NeXTSTEP 3.3 and OPENSTEP 4.2.

## Inputs

Expected external inputs (not committed):

- NeXTSTEP 3.3 m68k executable: `NDserver`
- OPENSTEP 4.2 m68k executable containing `__I860` payload

Optional supporting inputs:

- extracted i860 preload from OPENSTEP 4.2
- carved embedded m68k bundle from i860 payload (for contamination analysis)

## Canonical Artifact Classes

- `m68k host executable`:
  filetype `MH_EXECUTE`, includes `__I860` segment in known NDserver variants.
- `i860 preload payload`:
  filetype `MH_PRELOAD` / i860 Mach-O image loaded by host path.
- `embedded foreign Mach-O`:
  m68k/i386/SPARC objects embedded in i860 payload data region.

## Evidence Rules

- Always preserve SHA-256 for each extracted object.
- Record extraction offset and size, not only filename.
- Distinguish:
  - metadata window range
  - header-aligned Mach-O extraction range
- Mark truncated objects explicitly when load commands reference bytes beyond available range.
