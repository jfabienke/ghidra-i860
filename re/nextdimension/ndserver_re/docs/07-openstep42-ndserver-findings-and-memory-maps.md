# OPENSTEP 4.2 NDserver Findings And Memory Maps

## Scope

This is the consolidated findings snapshot for the OPENSTEP 4.2 NDserver extraction and m68k RE pass.

For the final 3.3-vs-4.2 protocol/offload/code-growth conclusion, see:

- `re/nextdimension/ndserver_re/docs/08-protocol-offload-and-code-growth-conclusion.md`

Primary artifacts:

- host m68k executable: `m68k_exec_i860seg_5aa8000.bin`
- embedded m68k bundle: `obj1_m68k_bundle_018000_60976.bin`
- i860 payload: extracted from host `__I860` segment

## Executive Findings

1. The 4.2 top-level m68k executable is close to 3.3 host NDserver behavior.
2. The 4.2 embedded m68k bundle is the richer RE target (more functions, fuller ND logic).
3. 4.2 i860 payload carries stronger embedded foreign-object pollution than 3.3 (`44.09%` vs `30.7%`).
4. The makePublic dispatch path resolves slot `33` to a statically seeded descriptor/handler chain.
5. No runtime writes were found for slot-table globals (`0x7000c028`, `0x7000c0ac`, `0x7000c324`) in this binary.

## Artifact Identity

- 4.2 host exec
  - path: `/private/tmp/openstep42_carved2/m68k_exec_i860seg_5aa8000.bin`
  - filetype: `MH_EXECUTE`
  - size: `1,007,616` (`0xF6000`)
  - sha256: `e32ee7c7d2a35943a7c4f81131fb8d12424358d036d7b94c06efda14355a8a20`
- 4.2 i860 payload
  - path: `re/nextdimension/ndserver_re/artifacts/extracted/os42/i860_payload.bin`
  - size: `974,848` (`0xEE000`)
  - sha256: `d6f6dada31a9bb7af198e79ef0fcd0f6794f994ead93e57d1907fe4da996efcf`
- 4.2 embedded m68k bundle
  - path: `re/nextdimension/ndserver_re/artifacts/extracted/os42/i860_scan/obj_02_off_018000_m68k_bundle_60976.bin`
  - filetype: `MH_BUNDLE`
  - offset in i860 payload: `0x18000`
  - size: `60,976` (`0xEE30`)
  - sha256: `b41b0e755a6da40568d33cfb22e9cb906a751341473147470cf0bc0760c59bf2`

## Functional Findings

- 4.2 host exec stats:
  - `function_total: 66`
  - `instruction_total: 4490`
  - `interesting_strings_total: 56`
- 4.2 embedded bundle stats:
  - `function_total: 190`
  - `instruction_total: 8050`
  - `interesting_strings_total: 32`
- 3.3 host stats (for context):
  - `function_total: 88`
  - `instruction_total: 4939`
  - `interesting_strings_total: 62`

Recovered 4.2 bundle anchors:

- `NDDriver_ProbeAndInitBoards` (`0x7000210a`)
- `NDServer_StartAndAttach` (`0x700025bc`)
- `ND_LoadMachDriverViaKernLoader` (`0x7000998e`)
- `ND_EnsureKernLoaderConfHasMachDriver` (`0x70009be8`)
- `ND_PortCheckIn` (`0x70009d14`)
- `ND_MakePublicDispatchRpc` (`0x700031b4`)
- `ND_MakePublicSlot33Handler` (`0x70002ea0`)
- `ND_PsServerRpc67_Attach` (`0x7000621e`)
- `ND_PsServerRpc68_MakePublic` (`0x70006322`)
- `ND_LookupPsServerPort` (`0x7000889e`)

## Binary Delta (3.3 host -> 4.2 host)

- size delta: `+172,032` (`0x2A000`)
- `__TEXT,__text` similarity: `0.9519447`
- `__I860` segment growth accounts for the main size delta
- CLI cstring delta:
  - 3.3: `Usage: %s [-s Slot]`
  - 4.2: `Usage: %s [-NDSlot Slot]`

## Pollution Findings (i860 Payload)

- 4.2 foreign bytes: `429,856` (`44.09%`)
- 3.3 foreign bytes: `246,468` (`30.7%`)

4.2 foreign object classes:

- m68k bundle x1
- i386 execute x2
- sparc execute x3

## ASCII Memory Maps

### 1) 4.2 Host Executable File Layout

```text
File: m68k_exec_i860seg_5aa8000.bin (0x00000000 .. 0x000F5FFF)

0x00000000  +-----------------------------------------------------------+
            | Mach-O header + load commands                             |
0x00000D08  | __TEXT,__text (size 0x48EC)                               |
            | __TEXT other sections (__fvmlib_init0/__cstring/__const)  |
0x00006000  +-----------------------------------------------------------+
            | __DATA segment (fileoff 0x6000, size 0x2000)              |
0x00008000  +-----------------------------------------------------------+
            | __I860 segment (fileoff 0x8000, size 0xEE000)             |
            |   contains i860 preload + embedded foreign Mach-Os         |
0x000F6000  +-----------------------------------------------------------+
```

### 2) 4.2 Host Executable VM Segment Layout

```text
VM map (from load commands)

0x00000000  [__PAGEZERO  vmsize 0x00002000]
0x00002000  [__TEXT      vmsize 0x00006000]
0x00008000  [__DATA      vmsize 0x00002000]
0x0000A000  [__I860      vmsize 0x000EE000]
0x000F8000  [__LINKEDIT  vmsize 0x00000000]
```

### 3) 4.2 i860 Payload Embedded Object Map

```text
Payload: i860_payload.bin (0x000000 .. 0x0EDFFF), size 0xEE000

0x000000  +-------------------------------------------------------------+
          | obj1 i860 preload (size 0xEC348, primary)                   |
          |   NOTE: foreign objects below are embedded inside this blob  |
0x018000  |  obj2 m68k bundle   size 0x0EE30  end 0x026E30              |
0x040000  |  obj3 sparc execute size 0x0E3C8  end 0x04E3C8              |
0x088000  |  obj4 i386 execute  size 0x0C000  end 0x094000              |
0x0A4000  |  obj5 sparc execute size 0x12BA4  end 0x0B6BA4              |
0x0BE000  |  obj6 i386 execute  size 0x1287C  end 0x0D087C              |
0x0D2000  |  obj7 sparc execute size 0x1A908  end 0x0EC908              |
0x0EC348  +-------------------------------------------------------------+
          | trailing bytes not covered by obj1 estimate                 |
0x0EE000  +-------------------------------------------------------------+
```

### 4) Embedded m68k Bundle VM Layout

```text
Bundle: obj1_m68k_bundle_018000_60976.bin

0x70000000  [__TEXT      vmsize 0x0000C000, fileoff 0x0000, filesize 0xC000]
0x7000C000  [__DATA      vmsize 0x00002000, fileoff 0xC000, filesize 0x2000]
0x7000E000  [__LINKEDIT  vmsize 0x00000E30, fileoff 0xE000, filesize 0x0E30]

Key __DATA sections:
  __data          0x7000C000 size 0x010C
  __const         0x7000C114 size 0x0118
  __la_symbol_ptr 0x7000C22C size 0x00F0
  __nl_symbol_ptr 0x7000C31C size 0x002C
  __bss           0x7000C348 size 0x002C
```

### 5) Slot 33 Dispatch/Callback Wiring

```text
Dispatch base: DAT_7000c028
Slot index:    33 (0x21)

DAT_7000c028 + (33 * 4) = 0x7000c0ac
0x7000c0ac -> 0x7000c06c   (descriptor pointer)

descriptor @ 0x7000c06c:
  ...
  +0x3c @ 0x7000c0a8 -> 0x70002ea0 (ND_MakePublicSlot33Handler)

Runtime paths:
  ND_MakePublicDispatchRpc:
    handler = (*(DAT_7000c028 + local_34*4))->func_at_0x3c

  NDServer_StartAndAttach:
    handler = (*PTR_DAT_7000c324)->func_at_0x3c
    PTR_DAT_7000c324 == 0x7000c06c in static data
```

## Renamed Function Inventory (4.2 Bundle)

Current map (`18` entries):

- `0x7000210a` `NDDriver_ProbeAndInitBoards` (high)
- `0x700025bc` `NDServer_StartAndAttach` (high)
- `0x70002b38` `ND_InternalMsgError` (high)
- `0x70002ea0` `ND_MakePublicSlot33Handler` (medium)
- `0x700031b4` `ND_MakePublicDispatchRpc` (high)
- `0x7000621e` `ND_PsServerRpc67_Attach` (medium)
- `0x70006322` `ND_PsServerRpc68_MakePublic` (medium)
- `0x7000889e` `ND_LookupPsServerPort` (high)
- `0x70003ba6` `ND_StartVideo_FindWindowBag` (high)
- `0x70003c9a` `ND_StartVideo` (high)
- `0x70004514` `ND_ResumeRecording` (high)
- `0x70005bf4` `ND_BuildCieTable` (medium)
- `0x70009402` `ND_GetBoardList` (medium)
- `0x7000998e` `ND_LoadMachDriverViaKernLoader` (high)
- `0x70009b0e` `ND_UnloadMachDriver` (medium)
- `0x70009be8` `ND_EnsureKernLoaderConfHasMachDriver` (high)
- `0x70009d14` `ND_PortCheckIn` (high)
- `0x700048fa` `ND_FinalizeBoardInitialization` (low)

## Confidence Notes

- High confidence:
  - loader/kern_loader paths
  - slot33 descriptor/handler mapping
  - startup attach path structure
- Medium confidence:
  - semantic names for RPC helpers `0x67` / `0x68`
- Open pivot:
  - `DAT_7000c03c` appears to gate an alternate notify path; static default is zero.

## Evidence Pointers

- `re/nextdimension/ndserver_re/reports/ndserver_42_exec_m68k_summary.txt`
- `re/nextdimension/ndserver_re/reports/ndserver_42_bundle_m68k_summary.txt`
- `re/nextdimension/ndserver_re/reports/ndserver_42_bundle_rename_apply.txt`
- `re/nextdimension/ndserver_re/reports/ndserver_42_bundle_ipc_dispatch.txt`
- `re/nextdimension/ndserver_re/reports/ndserver_42_bundle_global_refs.txt`
- `re/nextdimension/ndserver_re/reports/ndserver_42_bundle_registration_chain.txt`
- `re/nextdimension/ndserver_re/reports/ndserver_33_vs_42_exec_compare.json`
- `re/nextdimension/ndserver_re/artifacts/extracted/os42/i860_scan/manifest.json`
- `re/nextdimension/ndserver_re/artifacts/extracted/nd33/i860_scan/manifest.json`
