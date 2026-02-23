# Emulator Observability Architecture (Beyond MAME/QEMU)

This design builds on the existing hooks in `nextdimension/emulator/i860-core/docs/emulator-hooks.md` and turns the emulator into a reverse-engineering observability platform.

## Why This Is Different

MAME and QEMU are excellent for execution fidelity, but our bottleneck is analysis closure: converting runtime behavior (`bri/calli`, MMIO polling, state transitions) into reproducible evidence and seeds for Ghidra.  
The goal here is not just emulation; it is deterministic, queryable, scriptable insight.

## Existing Foundation (Already Implemented)

From `emulator-hooks.md` and current code:

- `nd_trace` stop reasons (`max_steps`, `trapped`, `decode_error`, etc.)
- JSON state injection (`registers`, `control_registers`, memory patches)
- MMIO stubs and per-address `mmio_sequences`
- runtime JSONL trace (`I860_TRACE_JSONL`)
- trace dedup and max event limits
- register provenance for indirect branches
- execution history and hotspot summaries
- post-run state dump (`I860_DUMP_STATE_JSON`)

This is the right base layer for a structured observability stack.

## Target Architecture

```text
CPU/MMU/MMIO execution
    -> Typed Event Bus
        -> Trace Sinks (JSONL + Parquet)
        -> Rule Engine (trigger/action)
        -> Snapshot Manager (checkpoint/replay)
        -> Semantic Lenses (ND mailbox/dispatch/GState)
        -> Seed Generator (Ghidra recovery map)
```

## Design Components

### 1. Typed Event Schema

Add a versioned schema for emitted events (not free-form lines):

- `ExecStep`
- `RegWrite`
- `MemAccess` (`space=ram|mmio|csr`)
- `IndirectBranch`
- `Exception`
- `MMIOTransition`
- `AnalysisSignal` (candidate seed, confidence, evidence)

Keep JSONL for compatibility, but validate against a schema and include `schema_version`.

### 2. Rule Engine (Trigger -> Action)

Rules are lightweight and deterministic. Examples:

- If `IndirectBranch.target == 0` for >N events at same site, enable deep tracing for 500 steps.
- If poll loop detected on mailbox status register, advance MMIO sequence phase.
- On first non-zero indirect target, snapshot + emit `AnalysisSignal`.

Actions:

- elevate trace detail
- force snapshot
- emit structured alert
- gate seed generation until confidence threshold is met

### 3. Snapshot and Counterfactual Replay

Define snapshot payload:

- CPU state (GPR/creg/freg, PC, delay-slot state)
- MMIO model state (stub map + sequence cursors)
- dirty memory pages

Replay from snapshot with alternate MMIO scripts to explore hidden dispatch paths without restarting full boot.

### 4. ND Semantic Lenses (Domain-Specific)

Pluggable analyzers for firmware semantics:

- Mailbox command lifecycle lens
- PostScript dispatch lens (`token/hash/classify -> bri`)
- GState lens (`r15`-centric state changes)
- Runtime table/pointer lens (load chain to executable targets)

These lenses produce typed `AnalysisSignal` events, not ad-hoc logs.

### 5. Seed Pipeline Contract

Extend `dynamic_trace_to_recovery_map.py` contract:

- Accept typed `IndirectBranch` + provenance chain
- Accept lens-derived `AnalysisSignal`
- Preserve confidence provenance (`direct_target`, `table_entry`, `mmio_derived`)
- Emit deterministic map diff (`added`, `rejected`, reasons)

## Implementation Plan

### Phase 1: Event Bus + Schema

- Add `i860-core/src/obs/event.rs` (event enums + serde schema version)
- Add `i860-core/src/obs/bus.rs` (fanout to sinks)
- Wrap current tracer writes through bus

Acceptance:

- Existing traces still work
- All events include `schema_version`

### Phase 2: Rule Engine + Alerts

- Add `i860-core/src/obs/rules.rs`
- YAML/JSON rule config loaded by `nd_trace`
- Emit alert events and trace-mode transitions

Acceptance:

- Poll-loop and zero-target rules trigger deterministically

### Phase 3: Snapshots + Replay

- Add snapshot capture/load API
- Add replay runner that can branch from snapshot with alternate MMIO profiles

Acceptance:

- Reproduce same trace from same snapshot + same config
- Run A/B MMIO scenarios from identical checkpoint

### Phase 4: ND Lenses + Seed Quality

- Implement mailbox and dispatch lenses
- Feed signals into converter with explicit confidence tiers

Acceptance:

- At least one iteration with `dynamic_added > 0` on current closure workflow, or explicit proof why blocked

## Operational Integration

Keep current script interfaces and layer new capability behind them:

- `run_emu_trace_seed_pass.sh`
- `run_emu_trace_seed_sweep.sh`
- `run_iterative_closure.sh`
- `dynamic_trace_to_recovery_map.py`

No workflow breakage; only richer artifacts and better convergence diagnostics.

## KPIs

- `% indirect branches with non-zero target`
- `% non-zero targets with provenance depth >= 2`
- `dynamic_added` per closure iteration
- `stop_reason_top` trend (`max_steps` should decrease as MMIO model improves)
- snapshot replay reproducibility rate

## Immediate Next Step

Implement Phase 1 only (typed event bus + schema versioning), keep all current env flags and CLI behavior unchanged. This gives structured data without destabilizing execution.

