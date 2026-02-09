# Lessons Learned — ghidra-i860

Complete catalog of lessons, gotchas, and hard-won rules from developing
the i860 Ghidra module and analyzing the NeXTdimension firmware.

## SLEIGH Language

1. Sub-constructors MUST use separate unattached `_zero` fields for constraints; attached fields for display/export.
2. `s>>` NOT available in disassembly `[]` sections — use `signed` field declarations instead.
3. Split-immediate: declare high field as `signed`, then `(hi << N) | lo` naturally sign-extends.
4. `pst.d` (0x0F) is disp+reg ONLY — no reg+reg form, unlike other load/store instructions.
5. PFMAM/PFMSM DPC 0xD/0xF produce identical mnemonics — use `_f` suffix to differentiate.
6. Context variables: use `<context_set>` NOT `<tracked_set>` in pspec — tracked_set causes "Bad register name" errors.
7. fpsize=0b11 alternate encoding: both 0b01 and 0b11 encode 4-byte FP ops (fld.l/fst.l/pfld.l) — must implement both.
8. Write-sink registers: define unused registers (r0_sink, f0_sink, fd0_sink) at offset 0x5000 for hardwired-zero write-discard via sub-constructors — avoids paired instruction constructors.
9. Display `^` gotcha: after `^SubTable^`, identifiers are operand refs, NOT literals — must quote: `:^DualPrefix^"fadd.ss"` not `:^DualPrefix^fadd.ss`.
10. ret/bri/calli unused fields: don't constrain src2/dest to zero — real binaries have non-zero values in unused fields.

## Ghidra Platform

11. Module install requires ALL files (.slaspec, .sinc, .sla, .ldefs, .pspec, .cspec, .opinion, Module.manifest) in `Ghidra/Processors/<name>/data/languages/` — missing any causes silent failures.
12. BinaryLoader creates byte data blocking disassembly — use custom script with `clearAll(false)` + `disassemble()` for linear sweep.
13. Delay slot instructions display with `_` prefix in `toString()` — standard Ghidra convention.
14. Mach-O loader cannot parse i860 LC_THREAD (flavor 0x4) — no entry point, 0 functions discovered; workaround: set entry point manually in preScript.
15. Delay-slot pcode warnings (`Program does not contain referenced instruction`) are harmless at code/data boundaries; fix with `fixOrphanDelaySlots()`.
16. i860 ISA decodes ANY 4 bytes as valid instructions — `0x00000000` decodes as `ld.b r0(r0),r0`, making linear sweep catastrophically contaminating.

## macOS Toolchain

17. macOS `sed -E` backrefs broken — `\1` in replacements fails; use `perl -pi -e` instead.
18. SLEIGH compiler: `/opt/homebrew/Cellar/ghidra/12.0.2/libexec/Ghidra/Features/Decompiler/os/mac_arm_64/sleigh`
19. Ghidra headless: `/opt/homebrew/Cellar/ghidra/12.0.2/libexec/support/analyzeHeadless`

## Firmware Analysis Strategy

20. The ND kernel binary is a fat container — bundles m68k host driver, x86 objects, ASCII resources, GNU Emacs ChangeLog padding.
21. Three embedded Mach-O objects: m68k at 0x017CB8 (FEEDFACE), x86 at 0x03DCB8 + 0x05DCB8 (CEFAEDFE).
22. 0x1B9F0 is m68k code (inside the m68k Mach-O), NOT an i860 dispatch table.
23. `__DATA` contains no dispatch tables — 56KB is TIFF images (27%), zero-fill BSS (15%), Emacs ChangeLog padding (58%).
24. Curated seed/range maps essential for contaminated binaries — hard-mask v3: 311 seeds, 43 deny ranges, 0 pcode errors.
25. Only recursive descent from known entry points produces reliable results — linear sweep creates 67% contamination.

## i860 Architecture & ND Firmware

26. Delay slots on: br, call, bc.t, bnc.t, bla, bri, calli — NOT on: bc, bnc, bte, btne, trap.
27. Two calling conventions: GCC (r2=sp, r3=fp, callee-saved r1-r15) vs SPEA (r28=fp, r29=sp, callee-saved r1, r16-r29).
28. PostScript threaded dispatch: token read via MMIO 0x401C -> hash resolution (`xorh 0x10c6`) -> type classification (`and 0xe827`) -> FP pipeline -> hardware sync.
29. r15 is the GState flags register — dominant pattern `orh 0x6514,r15,r31` (25 occurrences).
30. Known ND firmware runtime data zone: 0xF80B7C00-0xF80C4097.

## Phase 2: Static Analysis Ceiling

31. r7/r13/r18 are NOT persistent base pointers — 160-337 writes each, all ALU operations.
32. 566 of 586 unknown bri sites hit a branch boundary within 32 instructions — single-block backward slicing is insufficient.
33. Cross-block reverse CFG: 5,642 blocks, 5,984 edges; only 7 br edges.
34. Visit budget matters: 256 too small for 512 boundary sites — 2,048 needed (803 used).
35. Sequential fall-through edges not captured by branch-only CFG — must handle no_predecessors by scanning backward from block_entry - 4.
36. GCC callee-saved tracing past calls: 49 sites had caller-saved registers (r16-r31) destroyed — ABI-aware tracing essential but most bri targets use argument/temp registers.
37. Only resolved constant (0xd16 = 3350) is a data value, not a code address — 0 new code seeds.
38. Structural ceiling confirmed: 190 dynamic_entry + 75 trap_entry + 153 depth_exhausted = runtime-computed dispatch; emulation required.

## Ghidra Script Patterns

39. I860Import.java: 30 rounds of iterative seed discovery (call/br targets + flow following + delay-slot closure).
40. I860Analyze.java: collect all candidates once upfront, worklist with failure cache, delay-slot closure after each round.
41. RecoverRuntimeDispatchSeeds.java: register constant tracking + pointer store detection, scoring system (30+30+30+10+8) — has static override compile error, currently skipped.

## Rigor & Methodology

42. Treat BYTE_ACCOUNTING.txt, EMBEDDED_MACHO_HEADERS.txt, and sha256.txt as canonical ground truth; docs are secondary.
43. Always label metric scope by binary (clean_window 200,704 B vs __text 730,440 B vs full 795,464 B) to avoid cross-baseline confusion.
44. Keep __text section (730,440) distinct from __TEXT segment (737,280); that 6,840-byte delta matters in coverage math.
45. Branch-target math must track current SLEIGH, not mixed references: br/call (br26) vs split-branch (sbroff) formulas are different.
46. Delay-slot handling must be opcode-specific; a global "+8 block entry" rule is wrong.
47. Cross-block tracing needs memoization on (block_entry, reg, depth) plus visit budgets to prevent path explosion.
48. ABI must be explicit (gcc vs spea) for call-boundary tracing and clobber decisions; otherwise cross-call inferences are invalid.
49. "No dispatch table found" should be stated as "no static flat table found"; runtime-built BSS tables remain possible.
50. Heuristic architecture tagging can misclassify compressed data (e.g., TIFF/LZW as x86); require format-signature confirmation before conclusions.
51. Headless logs are first-class outputs: always check for skipped scripts/compile errors (e.g., RecoverRuntimeDispatchSeeds.java) before trusting metrics.
