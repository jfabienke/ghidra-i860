# Repository Guidelines

## Project Structure & Module Organization
This repository is currently documentation-first. Keep core planning material in `README.md` and the numbered references in `docs/` (for example, `docs/03-ghidra-sleigh-development-guide.md`).

Implementation files should follow the structure documented in `docs/03-ghidra-sleigh-development-guide.md`:
- `data/languages/` for `i860*.slaspec`, `.sinc`, `.ldefs`, `.pspec`, `.cspec`, `.opinion`
- `src/main/java/` for loader or integration Java code
- root metadata files such as `extension.properties` and `Module.manifest`

## Build, Test, and Development Commands
There is no checked-in build script yet, so day-to-day work is documentation and spec authoring.

- `rg --files docs` lists the documentation corpus quickly.
- `rg -n "delay slot|opcode|Phase" docs/` finds architecture rules and implementation status.
- `i860-disassembler --format json --show-addresses <firmware.bin> > golden.json` generates a golden disassembly reference (external tool from `../nextdimension/i860-disassembler/`).

When SLEIGH files are added, document the exact compile/package commands in this file and `README.md`.

## Coding Style & Naming Conventions
Use concise, technical Markdown with one `#` title per file and descriptive `##` sections. Keep the numbered doc naming pattern: `NN-topic-description.md`.

For language module files:
- use `i860`-prefixed names (`i860_le.slaspec`, `i860_fpu.sinc`)
- keep instruction mnemonics lowercase (`bc.t`, `pfadd.ss`)
- preserve clear alignment for token/register tables in SLEIGH and XML examples

## Testing Guidelines
Regression testing is based on comparing Ghidra output to the Rust disassembler golden output. Prioritize coverage for:
- Phase 1 integer/load-store/branch instructions
- delay-slot behavior (`bc.t`, `bnc.t`, `bla`)
- split-offset branch decoding (`bte`, `btne`, `bla`)

Use known binaries listed in `README.md` (for example `ND_i860_CLEAN.bin`, `BOOT.OUT`) and include comparison evidence in PRs.

## Commit & Pull Request Guidelines
This workspace snapshot does not include `.git` history, so use Conventional Commit style going forward:
- `docs: clarify bte split-offset encoding`
- `sleigh: add bc.t delay-slot semantics`

Keep commits focused and reviewable. PRs should include:
- purpose and affected instruction families/files
- linked issue or tracking note
- test evidence (golden comparison summary, sample disassembly output)
- screenshots only when UI/loader behavior is changed

## Security & Configuration Tips
Do not commit absolute local paths from personal environments. Treat firmware binaries as external artifacts unless redistribution rights are clear; prefer references, hashes, or extraction notes.
