# GaCK Source Architecture (NextDimension-21)

## Purpose
This document captures the architecture of the NeXTdimension GaCK software stack from primary source code in:

- `~/Development/re/NeXTDimension/NextDimension-21`

Scope is architecture and RE guidance, not binary equivalence claims. Our target firmware binary is from a later NeXTSTEP generation (3.3), while this source tree corresponds to the 2.0-era codebase.

## Executive Summary
GaCK on NeXTdimension is a split system, not a standalone monolithic OS:

1. Host NeXTSTEP kernel driver (`MachDriver`) owns hardware, interrupts, mapping, and host pager backing store.
2. Host client/runtime bridge (`libND`) boots i860 code, maps shared regions, and optionally bypasses kernel message path for fast sends.
3. i860 runtime (`NDkernel`) provides a lightweight board-local kernel-like environment: trap handling, VM wrappers, message queue transport, cooperative process scheduler, and pager daemon.

The i860 side looks Mach-like but is not a full host-equivalent Mach kernel.

## High-Level Component Diagram

```text
+--------------------------------------------------------------+
| Host NeXTSTEP                                                |
|                                                              |
|  User/Services -----> libND (boot/load/msg bridge)           |
|                        |                                     |
|                        v                                     |
|                 Mach IPC (MIG: ND.defs, ND_Kern.defs)        |
|                        |                                     |
|                        v                                     |
|               MachDriver (owner/map/interrupt/pager bridge)  |
+------------------------|-------------------------------------+
                         | NuBus / board mappings
                         v
+--------------------------------------------------------------+
| NeXTdimension Board (i860)                                   |
|                                                              |
|  Boot ROM -> NDkernel (locore + i860_init + kern_main)       |
|              |                |                              |
|              |                +-> pmap/vm_fault/vm_user      |
|              +-> messages + queue transport                  |
|              +-> trap/syscall + interrupt path               |
|              +-> cooperative proc scheduler (Spawn/Sleep)    |
+--------------------------------------------------------------+
```

## Build Topology
Source build graph confirms component boundaries:

- `MachDriver`, `libND`, `cmds`, `NDkernel`, `PSDriver`, `diag`, `ROM` in `~/Development/re/NeXTDimension/NextDimension-21/Makefile:5`

This is a complete stack for board bring-up, runtime, and tooling.

## Host Control Plane

### MIG Interfaces
Two interfaces define host<->board contracts:

- Device/runtime services in `~/Development/re/NeXTDimension/NextDimension-21/MachDriver/ND.defs`
  - Ownership/debug/console/port translation/reset/map routines, e.g. `SetOwner`, `ResetMessageSystem`, `MapHostToNDbuffer` (`ND.defs:31-148`)
- i860 kernel support services in `~/Development/re/NeXTDimension/NextDimension-21/MachDriver/ND_Kern.defs`
  - `vm_allocate`, `vm_deallocate`, `vm_protect`, `page_in`, `page_out`, `port_*` (`ND_Kern.defs:50-115`)

### Driver Lifecycle
Driver-side orchestration is visible in:

- `ND_SetOwner` / `ND_ResetMessageSystem` in `~/Development/re/NeXTDimension/NextDimension-21/MachDriver/ND_services.c:50` and `~/Development/re/NeXTDimension/NextDimension-21/MachDriver/ND_services.c:182`
- Interrupt wiring and arbitration in `~/Development/re/NeXTDimension/NextDimension-21/MachDriver/ND_intr.c:43-145`
- Hardware probe/attach and interrupt hookup in `~/Development/re/NeXTDimension/NextDimension-21/MachDriver/ND_server.c:126-268`
- Host↔board message forwarding threads in `~/Development/re/NeXTDimension/NextDimension-21/MachDriver/ND_msg_io.c:35-221`

### Pager Bridge
Host implements backing-store services used by i860 runtime:

- `ND_Kern_page_in`, `ND_Kern_page_out`, and `ND_vm_move` in `~/Development/re/NeXTDimension/NextDimension-21/MachDriver/ND_Kern_services.c:231-465`

## libND Bridge Layer

### Board Open + Mapping + Boot
Key entry points:

- `ND_Open` in `~/Development/re/NeXTDimension/NextDimension-21/libND/init.c:13`
- `ND_BootKernel` in `~/Development/re/NeXTDimension/NextDimension-21/libND/boot.c:9`

Boot flow:

1. Open/own board.
2. Map boot DRAM (`ND_MapBootDRAM`).
3. Assert reset (`NDCSR_RESET860`).
4. Load code.
5. Release reset / signal i860 (`ND_INT860` path).

### Loader Semantics
Mach-O load logic in `~/Development/re/NeXTDimension/NextDimension-21/libND/code.c`:

- i860 validation: `CPU_TYPE_I860` + `CPU_SUBTYPE_BIG_ENDIAN` (`code.c:138`)
- entrypoint extraction via `LC_THREAD` / `LC_UNIXTHREAD` (`code.c:185`)
- mixed write policy:
  - `LOADTEXT(addr,data)` writes to `addr ^ 4` (`code.c:45`, `code.c:48`)
  - `LOADDATA(addr,data)` writes directly (`code.c:44`, `code.c:47`)

This mixed-endian text/data behavior is directly relevant when reconciling source loader intent vs disassembly output.

### Fast Message Send Path
`NDmsg_send` uses shared queue + Lamport lock in `~/Development/re/NeXTDimension/NextDimension-21/libND/msg_send.c:15-150`.

Implication: some traffic bypasses ordinary host kernel message path assumptions; this matters for trace expectations.

## i860 Runtime (NDkernel)

### Boot/Bring-Up
Assembly startup in `~/Development/re/NeXTDimension/NextDimension-21/NDkernel/ND/locore.s`:

- `_start` sets PSR/EPSR/FSR and initial `dirbase` (`locore.s:99-127`)
- calls `_early_start` to build PDE/PTE structures (`locore.s:198`)
- enables ATE and transitions to virtual execution (`locore.s:204-211`)
- jumps to `_vstart`, then `i860_start` (`locore.s:219`, `locore.s:357`)

C-side early init in `~/Development/re/NeXTDimension/NextDimension-21/NDkernel/ND/i860_init.c`:

- DRAM bank probing and sizing (`i860_init.c:123-151`)
- returns directory for `dirbase` load (`i860_init.c:163`, `i860_init.c:203`)
- initializes messaging host interface (`InitMessages`) (`i860_init.c:286`)

### Process Model
`kern_main` in `~/Development/re/NeXTDimension/NextDimension-21/NDkernel/ND/kern_main.c:26-43`:

- Creates process 0 manually.
- Spawns `Messages` and `PageOutDaemon`.
- Spawns user `main` and enters scheduler.

This is a compact board runtime with kernel-like services, not general host OS parity.

### Message Runtime
`~/Development/re/NeXTDimension/NextDimension-21/NDkernel/ND/messages.c` implements queue transport and Mach-like send/recv/rpc wrappers:

- queue structures (`messages.c:21-57`)
- `Messages()` receive/dispatch loop (`messages.c:130-224`)
- `msg_send/msg_receive/msg_rpc` (`messages.c:377-553`)
- service reply-port serialization (`messages.c:517-542`)

Queue memory layout constants are in `~/Development/re/NeXTDimension/NextDimension-21/libND/NDmsg.h`:

- i860-side uncached queue base `ND_START_UNCACHEABLE_DRAM=0xF80C0000` (`NDmsg.h:105`)

### Trap/Syscall/Interrupt Path
`~/Development/re/NeXTDimension/NextDimension-21/NDkernel/ND/trap.c`:

- trap dispatcher and VM fault route (`trap.c:95-265`)
- syscall path (`trap.c:371-430`)
- hardware interrupt handling and `hardclock` invocation (`trap.c:604-670`)

### VM/Pmap/Pager
VM support is host-assisted:

- i860 wrapper calls in `~/Development/re/NeXTDimension/NextDimension-21/NDkernel/ND/vm_user.c:27-171`
- page fault path in `~/Development/re/NeXTDimension/NextDimension-21/NDkernel/ND/vm_fault.c` (calls into host page services)
- pmap and pageout logic in `~/Development/re/NeXTDimension/NextDimension-21/NDkernel/ND/pmap.c`:
  - translation validity (`pmap.c:123`)
  - map insert and cacheability decisions (`pmap.c:154-314`)
  - dirty page clean / host page_out batching (`pmap.c:595-724`)
  - `PageOutDaemon` (`pmap.c:781`)

### Scheduler Semantics
`~/Development/re/NeXTDimension/NextDimension-21/NDkernel/ND/switch.c` shows cooperative lightweight process mechanics:

- `SpawnProc` (`switch.c:42`)
- `Sleep` / `Wakeup` (`switch.c:247`, `switch.c:284`)
- no host-style preemptive task model here.

### Syscall Surface Reality
`~/Development/re/NeXTDimension/NextDimension-21/NDkernel/ND/init_sysent.c` is dominated by `nosys` entries (`init_sysent.c:31-220`).

This is strong evidence that i860 runtime is purpose-built and narrow, not a full UNIX syscall environment.

## Memory and Addressing Model

### Key VM Constants
`~/Development/re/NeXTDimension/NextDimension-21/include.i860/machine/vm_param.h`:

- user/kernel ranges (`vm_param.h:36-40`)
- PDE/PTE indexing and endian XOR rules (`vm_param.h:46-70`)
- PTE flags and cache/dirty semantics (`vm_param.h:97-114`)

### Hardware Map Primitives
`~/Development/re/NeXTDimension/NextDimension-21/libND/NDreg.h` includes board-local mappings used by i860 runtime:

- `ADDR_DRAM = 0xF8000000` (`NDreg.h` section under `#if defined(i860)`)
- CSR/DMA/video addresses in `0xFF80xxxx` / `0xFF801xxx` / `0xFF802xxx`
- trap vector constant `ADDR_TRAP_VECTOR = 0xFFFFFF00`

## What This Means for Our 3.3 Binary RE

### Stable Architectural Invariants (High confidence)

1. Split host/board architecture (MachDriver + libND + i860 runtime).
2. Message-queue-centered communication.
3. Host-assisted VM/page-in/page-out model.
4. Board-local lightweight scheduler/runtime.

### Likely Version-Sensitive Areas (Medium/low confidence)

1. Exact command IDs and operator dispatch tables.
2. MMIO sequencing details during boot and steady-state rendering.
3. Loader conventions in late releases vs 2.0-era source.
4. Precise PostScript operator-to-handler binding in 3.3 firmware.

### Practical RE Guidance

1. Treat this source as architecture ground truth, not byte-level truth.
2. Use it to prioritize trace instrumentation and emulator hooks:
   - mailbox/queue activity,
   - host-pager interactions,
   - indirect branch provenance around dispatch loops.
3. Avoid overfitting 3.3 binary claims to 2.0 symbols unless cross-validated by traces.

### Concrete Crosswalk Tasks

1. Build a 2.0 source -> 3.3 binary symbol-pattern matrix.
2. Tag emulator events by subsystem (`msg`, `vm`, `pager`, `trap`, `dispatch`).
3. Add MMIO scenario profiles modeled on queue/interrupt lifecycle rather than static constants.
4. Add callsite-level hypotheses in Ghidra notes: host-service wrappers vs board-local routines.

## Evidence Index

Primary source files used:

- `~/Development/re/NeXTDimension/NextDimension-21/Makefile`
- `~/Development/re/NeXTDimension/NextDimension-21/MachDriver/ND.defs`
- `~/Development/re/NeXTDimension/NextDimension-21/MachDriver/ND_Kern.defs`
- `~/Development/re/NeXTDimension/NextDimension-21/MachDriver/ND_services.c`
- `~/Development/re/NeXTDimension/NextDimension-21/MachDriver/ND_server.c`
- `~/Development/re/NeXTDimension/NextDimension-21/MachDriver/ND_intr.c`
- `~/Development/re/NeXTDimension/NextDimension-21/MachDriver/ND_msg_io.c`
- `~/Development/re/NeXTDimension/NextDimension-21/MachDriver/ND_Kern_services.c`
- `~/Development/re/NeXTDimension/NextDimension-21/libND/init.c`
- `~/Development/re/NeXTDimension/NextDimension-21/libND/boot.c`
- `~/Development/re/NeXTDimension/NextDimension-21/libND/code.c`
- `~/Development/re/NeXTDimension/NextDimension-21/libND/msg_send.c`
- `~/Development/re/NeXTDimension/NextDimension-21/libND/NDmsg.h`
- `~/Development/re/NeXTDimension/NextDimension-21/libND/NDreg.h`
- `~/Development/re/NeXTDimension/NextDimension-21/NDkernel/ND/locore.s`
- `~/Development/re/NeXTDimension/NextDimension-21/NDkernel/ND/i860_init.c`
- `~/Development/re/NeXTDimension/NextDimension-21/NDkernel/ND/kern_main.c`
- `~/Development/re/NeXTDimension/NextDimension-21/NDkernel/ND/messages.c`
- `~/Development/re/NeXTDimension/NextDimension-21/NDkernel/ND/trap.c`
- `~/Development/re/NeXTDimension/NextDimension-21/NDkernel/ND/vm_user.c`
- `~/Development/re/NeXTDimension/NextDimension-21/NDkernel/ND/pmap.c`
- `~/Development/re/NeXTDimension/NextDimension-21/NDkernel/ND/switch.c`
- `~/Development/re/NeXTDimension/NextDimension-21/NDkernel/ND/init_sysent.c`
- `~/Development/re/NeXTDimension/NextDimension-21/include.i860/machine/vm_param.h`
