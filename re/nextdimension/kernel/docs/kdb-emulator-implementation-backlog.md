# KDB-to-Emulator Backlog (ROI/Risk Driven)

## Purpose
This backlog translates the `NextDimension-21/NDkernel/kdb` debugger implementation into concrete work for our Rust emulator (`nextdimension/emulator`) and analysis harness (`ghidra-i860/re/nextdimension/kernel/scripts`).

Goal: improve runtime observability and debug control in areas where static RE has plateaued (indirect dispatch, delay-slot control flow, weak unwindability).

## Scope Boundaries
- In scope:
  - i860 decode/disasm parity checks
  - breakpoint/step semantics (delay-slot correct)
  - stack/unwind heuristics for GCC and SPEA-like frames
  - deterministic register/memory dump formats
  - optional conditional breakpoint expressions
- Out of scope:
  - binary-perfect reproduction of 2.0 kdb UI
  - debugger command shell parity
  - host-side NeXTSTEP tooling recreation

## Reference Inputs
- `NextDimension-21/NDkernel/kdb/bits.c`
- `NextDimension-21/NDkernel/kdb/print.c`
- `NextDimension-21/NDkernel/kdb/runpcs.c`
- `NextDimension-21/NDkernel/kdb/stack.c`
- `NextDimension-21/NDkernel/kdb/format.c`
- `NextDimension-21/NDkernel/kdb/output.c`
- `NextDimension-21/NDkernel/kdb/expr.c`
- Existing Rust hooks: `i860-core/src/trace.rs`, `i860-core/src/handlers.rs`, `i860-core/examples/nd_trace.rs`, `i860-core/docs/emulator-hooks.md`

## Priority Matrix

| ID | Workstream | ROI | Risk | Why |
|---|---|---|---|---|
| P0-A | Decode/disasm differential parity | High | Low | Fast correctness wins; tightens instruction confidence |
| P0-B | Delay-slot-aware step/next/break | High | Medium | Directly impacts dispatch tracing and control-flow debugging |
| P1-C | Stack unwind heuristics | Medium | Medium | Better post-mortem traceability and function recovery |
| P1-D | Canonical dump/snapshot format | Medium | Low | Improves reproducibility and agent/human diff workflows |
| P2-E | Conditional break expressions | Medium | High | Powerful but parser/UX complexity |

## Execution Plan

## P0-A: Decode/Disasm Parity Harness
### Tasks
1. Build a kdb vector corpus from `bits.c` + known instruction words.
2. Add emulator-side parity tests in `i860-decoder` and `i860-core`.
3. Compare:
   - mnemonic family
   - operand extraction (regs/immediates)
   - branch target formula (`PC + (off << 2) + 4`)
4. Emit mismatch report (JSON + markdown summary).

### Acceptance Criteria
- New test target runs in CI.
- No mismatches on agreed corpus, or mismatches are tracked in a checked-in allowlist with rationale.

---

## P0-B: Delay-Slot-Correct Debug Controls
### Tasks
1. Add debug control API in `i860-core`:
   - `step_one()`
   - `next_over()`
   - `continue_until_break()`
2. Implement breakpoint types:
   - PC breakpoint
   - temporary breakpoint (for `next`)
   - hit-count breakpoint
3. Enforce delay-slot semantics:
   - stepping a delayed branch executes slot before redirection
   - `next` over call-like instructions lands at architectural return point
4. Add event annotations:
   - `branch_pending`
   - `delay_slot_executed`
   - `branch_committed`

### Acceptance Criteria
- Unit tests for delayed and non-delayed branch classes.
- Demonstrated control over at least one kernel path with repeated `bri` behavior.
- No regressions in existing trace output pipeline.

---

## P1-C: Stack/Frame Unwind Heuristics
### Tasks
1. Implement frame classifier:
   - GCC ABI pattern (`r2` stack pointer, `r3` frame pointer)
   - loose SPEA-like fallback (`r29` stack pointer, `r28` frame pointer)
2. Add unwind strategy modes:
   - strict prologue-based
   - heuristic scan-based
3. Add `traceback` API in emulator:
   - returns candidate frame chain with confidence per frame.
4. Integrate with observability events (`schema_version` payload extension).

### Acceptance Criteria
- Backtrace output produced for sampled kernel traces.
- Confidence-tagged frames; unresolved frames explicitly marked.
- No panic on malformed or data-contaminated code paths.

---

## P1-D: Canonical Dumps and Snapshots
### Tasks
1. Add stable register dump format (fixed order, hex width, ABI aliases).
2. Add memory dump formatter:
   - aligned blocks
   - endian-aware word view
   - optional ASCII gutter
3. Add snapshot export:
   - registers
   - control regs
   - selected memory ranges
   - recent instruction history
4. Add replay helper script in `ghidra-i860/re/nextdimension/kernel/scripts`.

### Acceptance Criteria
- Byte-for-byte stable output across repeated runs.
- Snapshot diff tooling usable in regression runs.
- Compatible with existing JSONL trace ingestion.

---

## P2-E: Conditional Breakpoint Expressions
### Tasks
1. Implement minimal expression grammar:
   - register refs (`r18`, `pc`)
   - constants
   - `== != < > <= >=`
   - bitwise `& | ^`
2. Bind expressions to breakpoints/watchpoints.
3. Add evaluation safety:
   - bounded execution
   - explicit parse errors
4. Add tests for precedence and malformed input.

### Acceptance Criteria
- Conditional breaks trigger deterministically in smoke traces.
- Parser rejects invalid expressions with clear diagnostics.

## Integration Hooks to Reuse
- Typed event bus (`obs`) and `schema_version`.
- Provenance fields from indirect branch events.
- Existing watch/range and trace controls in `nd_trace`.

## Milestones
1. M1 (P0 complete): parity harness + delay-slot debug controls.
2. M2 (P1 complete): unwind + canonical dumps integrated into analysis loop.
3. M3 (P2 optional): conditional expressions enabled for targeted deep-debug sessions.

## Handoff Checklist for Coding Agent
- Start with P0-A and P0-B only.
- Keep public JSON fields backward-compatible unless versioned.
- Add tests before wiring CLI switches.
- Document each new hook in `i860-core/docs/emulator-hooks.md`.
- Provide a one-page runbook per milestone with exact commands and expected artifacts.

