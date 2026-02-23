# Protocol, Offload, And Code-Growth Conclusion (2026-02-14)

## Questions Answered

1. Did host `<->` ND protocol behavior materially change between 3.3 and 4.2?
2. Does OPENSTEP 4.2 offload more DPS/primitives to the ND board?
3. If not, where does the m68k code-size increase come from?

## Overall Conclusion

- No material protocol redesign was recovered in active host-side paths between 3.3 and 4.2.
- No strong evidence was found that 4.2 offloads more DPS/primitives in active code paths.
- Most size growth in the embedded m68k artifact is format/linkage/container overhead, with a smaller logic delta mostly in RPC wrapper/helper expansion.

## Protocol Parity Findings

Recovered attach/makePublic chain remains structurally consistent:

- attach request/reply pair:
  - request `0x67`, expected reply `0xcb`
- makePublic request/reply pair:
  - request `0x68`, expected reply `0xcc`
- same makePublic dispatcher pattern and slot dispatch semantics remain present.

Evidence:

- `re/nextdimension/ndserver_re/reports/nd33_obj_protocol_funcs.txt`
- `re/nextdimension/ndserver_re/reports/ndserver_42_bundle_registration_chain.txt`
- `re/nextdimension/ndserver_re/reports/ndserver_42_bundle_ipc_dispatch.txt`

## DPS / Primitive Offload Surface

Known ND/DPS-facing strings and associated flows are largely shared across 3.3 embedded object and 4.2 embedded bundle:

- `nd_start_video`
- `nd_resumerecording`
- `nd ps driver: can't build CIE table`
- `makePublic` / `mark_msg_send`

Evidence:

- `re/nextdimension/ndserver_re/reports/nd33_obj_m68k_summary.txt`
- `re/nextdimension/ndserver_re/reports/ndserver_42_bundle_m68k_summary.txt`

## Code Growth Accounting (Embedded m68k: 3.3 object vs 4.2 bundle)

Comparison basis:

- 3.3: `obj_02_off_018000_m68k_object_49860.bin`
- 4.2: `obj_02_off_018000_m68k_bundle_60976.bin`

Measured delta:

- total size delta: `+11,116` bytes
- `__TEXT,__text` delta: `+2,946` bytes
- non-`__text` delta: `+8,170` bytes

Interpretation:

- about `73.5%` of total delta is non-`__text` container/linkage growth
- about `26.5%` is `__text` growth

Evidence:

- `re/nextdimension/ndserver_re/reports/nd33_obj_vs_os42_bundle_compare.md`
- `re/nextdimension/ndserver_re/reports/nd33_obj_vs_os42_bundle_compare.json`

### Why Non-Text Grew

4.2 embedded artifact is a bundle-style dynamic object (`MH_BUNDLE`) rather than a plain object-like input (`MH_OBJECT`) and carries extra dynamic-link sections/load commands.

Observed additions include:

- `__picsymbol_stub`
- `__dyld`
- `__la_symbol_ptr`
- `__nl_symbol_ptr`

Evidence:

- `re/nextdimension/ndserver_re/reports/nd33_obj_vs_os42_bundle_compare.json`

## What The Smaller Executable Delta Contains

Semantic core functions changed only modestly in size when paired by role (startup/attach, RPC67/RPC68, video, resume, CIE, loader/check-in), totaling roughly `+212` bytes across those paired anchors.

Evidence:

- `re/nextdimension/ndserver_re/reports/nd33_obj_semantic_funcs.txt`
- `re/nextdimension/ndserver_re/reports/os42_bundle_semantic_funcs.txt`

Additional `__text` delta is concentrated in wrapper/helper families:

- `0x6c..0x74` / `0xd0..0xd8` style RPC wrappers are present in both, with modest per-function expansion in 4.2.
- a `0x88 -> 0xec` wrapper exists in both 3.3 and 4.2.
- a `0x89 -> 0xed` wrapper appears in 4.2 and was not observed in 3.3.

Evidence:

- `re/nextdimension/ndserver_re/reports/nd33_obj_token_scan_rpcids_precise.txt`
- `re/nextdimension/ndserver_re/reports/os42_bundle_token_scan_rpcids_precise.txt`
- `re/nextdimension/ndserver_re/reports/nd33_obj_token_scan_81_89.txt`
- `re/nextdimension/ndserver_re/reports/os42_bundle_token_scan_81_89.txt`
- `re/nextdimension/ndserver_re/reports/os42_bundle_rpc_wrappers_candidate.txt`
- `re/nextdimension/ndserver_re/reports/nd33_obj_rpc88_neighborhood.txt`

## Inactive / Unreferenced Deltas

Current static pass found no direct refs to:

- 4.2 `0x89 -> 0xed` wrapper entry (`FUN_7000793c`)
- `DevOptSetBMCompression` cstring

This suggests at least part of the new surface may be dormant, optional, or invoked only via runtime paths not visible in this static slice.

Evidence:

- `re/nextdimension/ndserver_re/reports/os42_rpc89_refs.txt`
- `re/nextdimension/ndserver_re/reports/ndserver_42_devopt_refs.txt`

## RE Implication

Prioritize compatibility-focused protocol recovery:

- treat 4.2 as a largely protocol-compatible evolution of 3.3 host logic
- focus active RE effort on already-referenced paths (`0x67/0x68` attach/makePublic chain, loader path, video/resume/CIE)
- treat `0x89/0xed` and `DevOptSetBMCompression` as secondary pivots pending runtime evidence
