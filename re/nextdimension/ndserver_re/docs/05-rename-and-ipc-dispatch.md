# 4.2 Bundle Rename And IPC Dispatch Notes

## Rename Map Output

First-pass function rename map:

- `re/nextdimension/ndserver_re/docs/04-ndserver-42-bundle-rename-map.csv`

Application report:

- `re/nextdimension/ndserver_re/reports/ndserver_42_bundle_rename_apply.txt`

Current map size:

- `18` function renames

Key renamed anchors:

- `0x7000210a` -> `NDDriver_ProbeAndInitBoards`
- `0x700025bc` -> `NDServer_StartAndAttach`
- `0x700031b4` -> `ND_MakePublicDispatchRpc`
- `0x7000998e` -> `ND_LoadMachDriverViaKernLoader`
- `0x70009be8` -> `ND_EnsureKernLoaderConfHasMachDriver`
- `0x70009d14` -> `ND_PortCheckIn`

IPC-related rename added from dispatch extraction:

- `0x70002ea0` -> `ND_MakePublicSlot33Handler`
- `0x7000621e` -> `ND_PsServerRpc67_Attach`
- `0x70006322` -> `ND_PsServerRpc68_MakePublic`
- `0x7000889e` -> `ND_LookupPsServerPort`

## IPC Dispatch Extraction

Dispatcher evidence report:

- `re/nextdimension/ndserver_re/reports/ndserver_42_bundle_ipc_dispatch.txt`

Configured dispatcher center:

- function: `ND_MakePublicDispatchRpc` at `0x700031b4`
- dispatch table base: `0x7000c028`

Decoded dispatch edges:

- `local_34` index `33` -> descriptor `0x7000c06c` -> handler `ND_MakePublicSlot33Handler` (`0x70002ea0`)

Caller graph observations:

- direct callers of `ND_MakePublicDispatchRpc`: none (likely callback/indirect invocation path)
- direct callers of `ND_MakePublicSlot33Handler`: `NDServer_StartAndAttach` call site at `0x700027c4`

Operational behavior from decomp:

- dispatcher performs `makePublic` `msg_send`/`msg_receive`, then indirect-calls handler via table entry:
  `(**(code **)(*(int *)(&DAT_7000c028 + local_34 * 4) + 0x3c))(...)`
- reply message id field is patched from `local_34` high word (`*(undefined2 *)(iVar1 + 0xc) = local_34._2_2_`)

## RE Implication

- The `makePublic` RPC path appears to expose one currently decoded message slot (`33`) with a dedicated handler.
- The dispatcher has no direct code xrefs, so callback registration or runtime vector setup should be treated as the next pivot.

Follow-on trace result:

- `re/nextdimension/ndserver_re/docs/06-slot33-callback-trace.md`
  confirms slot `33` is statically seeded in `__DATA` and consumed by runtime attach/dispatch paths.
- `re/nextdimension/ndserver_re/docs/07-openstep42-ndserver-findings-and-memory-maps.md`
  consolidates all 4.2 findings with ASCII memory maps.
