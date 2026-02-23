# Slot 33 Callback Registration Trace (4.2 Bundle)

## Scope

Trace where the `ND_MakePublicDispatchRpc` callback target comes from and how slot `33` is reached.

Inputs:

- `re/nextdimension/ndserver_re/reports/ndserver_42_bundle_registration_chain.txt`
- `re/nextdimension/ndserver_re/reports/ndserver_42_bundle_global_refs.txt`

## Key Finding

Slot `33` is not populated by runtime writes in the analyzed bundle. It is statically initialized in `__DATA` and then consumed by runtime attach/dispatch code.

## Static Data Evidence

From `ndserver_42_bundle_global_refs.txt`:

- `0x7000c0ac` contains `0x7000c06c` (slot `33` entry points to descriptor at `0x7000c06c`)
- `0x7000c324` contains `0x7000c06c` (active descriptor pointer used by startup call path)
- `0x7000c028` is dispatch table base used by `ND_MakePublicDispatchRpc`

Reference class summary:

- `0x7000c028`: refs only from `ND_MakePublicDispatchRpc` (data reads)
- `0x7000c0ac`: refs only from `ND_MakePublicSlot33Handler` (reads)
- `0x7000c324`: refs are reads only (no writes found)

No write xrefs to these addresses were found in the bundle.

## Runtime Call Chain

From `ndserver_42_bundle_registration_chain.txt`:

1. `NDServer_StartAndAttach` (`0x700025bc`)
   - looks up `ps_server` via `ND_LookupPsServerPort` (`0x7000889e`)
   - performs startup RPC via `ND_PsServerRpc67_Attach` (`0x7000621e`, message id `0x67`)
   - executes callback entry via:
     - `pcVar1 = *(code **)(PTR_DAT_7000c324 + 0x3c);`
     - `uVar7 = (*pcVar1)();`
2. `PTR_DAT_7000c324` resolves to descriptor `0x7000c06c`, so `+0x3c` resolves to `0x7000c0a8`, which points to `ND_MakePublicSlot33Handler` (`0x70002ea0`)
3. `ND_MakePublicSlot33Handler`
   - allocates/frames response object using `DAT_7000c0ac`
   - calls `ND_PsServerRpc68_MakePublic` (`0x70006322`, message id `0x68`)
4. `ND_MakePublicDispatchRpc` (`0x700031b4`)
   - dispatches through:
     - `(**(code **)(*(int *)(&DAT_7000c028 + local_34 * 4) + 0x3c))(...)`
   - for `local_34 == 33`, table slot points to descriptor `0x7000c06c`, yielding the same slot handler.

## Conclusion

- The slot-`33` mapping is statically seeded (`0x7000c0ac -> 0x7000c06c`).
- Runtime code performs attach/handshake and then uses descriptor function pointers to execute the mapped callback path.
- No runtime table population of slot `33` was observed in this binary.

## Follow-up Pivot

- `DAT_7000c03c`/`PTR_DAT_7000c320` appear to gate an alternate notify path (`FUN_70002e52` -> `FUN_7000615e`), but default `DAT_7000c03c` value is zero in static data.
