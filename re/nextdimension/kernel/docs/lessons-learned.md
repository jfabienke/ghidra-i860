# Lessons Learned (Kernel RE + Emulator)

Durable rules promoted from working memory into repo-tracked docs.
Scope: NeXTdimension 3.3 kernel RE, i860 Ghidra tooling, and emulator trace pipeline.

## Ground Truth Discipline

1. Treat binary artifacts and machine-generated reports as canonical; prose is secondary.
2. Always label metric scope explicitly (`clean_window` vs `__text` section vs full file).
3. Keep `__text` section (`730,440`) distinct from `__TEXT` segment (`737,280`); the 6,840-byte delta matters.
4. For branch semantics, use current SLEIGH behavior and opcode-specific delay-slot rules; do not apply a global `+8` rule.
5. Check headless logs for skipped scripts/compile errors before trusting metrics.

## Static Analysis Boundaries

6. The 3.3 kernel binary is a contamination-heavy container, not a pure i860 image.
7. Single-block backward slicing is insufficient for most unknown `bri` targets; cross-block tracing confirms a static ceiling.
8. State findings as "no static flat dispatch table found" unless runtime-built tables are excluded by evidence.
9. In 3.3, no C-level PS name→handler registration table is proven in the shipped binary.
10. At clean-firmware offset `0x1FC00`, data may be structured, but in shipped 3.3 that offset is contamination-heavy and not a stable anchor.

## LLM / Swarm Hygiene

11. Validate and coerce recoverable schema issues (enum normalization, hex address coercion, trailing JSON text) instead of hard-rejecting.
12. Count tokens across all stages (intent, verifier, contrarian, synthesis); partial accounting is misleading.
13. Input quality dominates outcome quality: MMIO over-tagging can materially bias model verdicts.
14. MMIO tagging must be effective-address aware (`base + displacement`), not raw-immediate threshold matching.
15. Any LLM-claimed binary structure must be hex-dump verified before documentation.

## Emulator Rules

16. LC_UNIXTHREAD all-zero registers at kernel start are expected; do not treat zero-init as a bug by default.
17. `0xF8000000` in shipped 3.3 is Mach-O/container content; decode there can be misleading without proper load semantics.
18. i860 text load path must honor host XOR-4 text placement semantics (`LOADTEXT(addr ^ 4)` behavior).
19. MMIO read behavior is often the practical execution blocker; poll loops need stateful MMIO modeling.
20. Trace/closure success should be measured by reproducible deltas (`dynamic_added`, unique indirect targets, coverage), not single-run anecdotes.

## Current Known State (2026-02-13)

1. Static seed recovery remains capped (`dynamic_added=0` in current closure baselines).
2. Swarm pipeline is operational and useful for triage, but cannot replace runtime evidence for dispatch-heavy paths.
3. PS/operator claims are source-informed but must remain binary-scoped and version-scoped (2.0 vs 3.3).

