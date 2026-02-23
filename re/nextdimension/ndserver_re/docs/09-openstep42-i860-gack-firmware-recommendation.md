# OPENSTEP 4.2 i860 GaCK Firmware Recommendation (2026-02-14)

## Scope

Decision note for whether OPENSTEP 4.2 i860 firmware should be the primary next target for GaCK RE.

Compared artifacts:

- 3.3 baseline: `re/nextdimension/kernel/i860_kernel.bin`
- 4.2 preload: `re/nextdimension/ndserver_re/artifacts/extracted/os42/i860_scan/obj_01_off_000000_i860_preload_967496.bin`
- 4.2 payload: `re/nextdimension/ndserver_re/artifacts/extracted/os42/i860_payload.bin`

Primary analysis outputs:

- `re/nextdimension/kernel/reports/factpack/20260209-162613/meta.json`
- `re/nextdimension/kernel/reports/factpack/openstep42_20260214-004032/meta.json`
- `re/nextdimension/kernel/reports/i860_kernel_report.txt`
- `re/nextdimension/kernel/reports/factpack/swarm_openstep42_opus4-6_20260213/run_summary.json`
- `re/nextdimension/kernel/reports/factpack/swarm_proven_opus46_full_20260213/claims.db`
- `re/nextdimension/kernel/reports/factpack/swarm_openstep42_opus4-6_20260213/claims.db`

## Quantitative Delta (3.3 -> 4.2)

- decoded instructions: `2,536` -> `15,054` (`+12,518`)
- functions: `60` -> `63` (`+3`)
- code bytes: `10,144` -> `60,216`
- foreign embedded bytes (from mapped objects): `246,468` (`30.70%`) -> `359,680` (`40.06%`)

Important caveat: these are conservative recursive-descent outputs, not total executable budget.
For 3.3, the clean i860 window is `200,704` bytes (`50,176` instruction slots), so `1,344` function-tagged instructions is a lower bound (~`2.68%` of that clean-window instruction budget), not a claim that GaCK only contains ~1.3k i860 instructions.

But most 4.2 increase is orphan decode, not stable function logic:

- 3.3 instructions with `func_entry`: `1,344 / 2,536` (`53.00%`)
- 4.2 instructions with `func_entry`: `1,297 / 15,054` (`8.62%`)
- 3.3 instructions without `func_entry`: `1,192 / 2,536` (`47.00%`)
- 4.2 instructions without `func_entry`: `13,757 / 15,054` (`91.38%`)

Function-associated instruction bytes are slightly lower in 4.2 (`1,297 * 4 = 5,188`) than 3.3 (`1,344 * 4 = 5,376`), so executable core did not expand in this pass.

## Orphan Decode Concentration

4.2 no-function blocks are dominated by a few large ranges in allow-only regions (not denied by the hard mask):

- `0xf802d7e8..0xf8033457`: `5,916` insns
- `0xf8029f18..0xf802b7ff`: `1,594` insns
- `0xf8035d30..0xf8036613`: `569` insns

These top 3 blocks account for `8,079 / 13,757` (`58.73%`) of all orphan instructions in 4.2.

By contrast, the largest 3.3 orphan block is `87` insns; top 3 total is only `184`.

## Opus 4.6 Swarm Result

Run: `re/nextdimension/kernel/reports/factpack/swarm_openstep42_opus4-6_20260213/run_summary.json`

- claims: `63`
- verify accept: `47`
- verify revise: `15`
- gatekeeper passed: `62`

Interpretation of accepted/revised intents is dominated by "non-executable/misidentified/unknown" classifications:

- heuristic count of unknown-like primary intents: `45 / 63`
- most 4.2-only functions (`24` entries) are also classified as non-code or low-confidence fragments

Candidate dispatch-like fragments remain, but mostly low-to-moderate confidence and unresolved-branch-heavy:

- `0xf800c4bc`, `0xf8008dd4`, `0xf800bc68`, `0xf800842c`, `0xf800c458`, `0xf800f77c`

## Match Against Older Speculative RE

Shared function IDs between 3.3 and 4.2 sets: `39`.

The old speculative interpretation (threaded PS/MMIO dispatch hints) partially overlaps, but remains unstable:

- some former speculative dispatch candidates downgrade to "unknown/non-code" in 4.2 (`0xf8009270`, `0xf800a1c8`, `0xf800b9e0`, `0xf800c630`, `0xf800df78`)
- some candidates stay dispatch-like but still revised/low confidence (`0xf8008dd4`, `0xf800bc68`, `0xf800842c`)

Net: 4.2 does not provide a clearly better anchor set for validating older speculative claims.

## Recommendation

Do not switch primary GaCK RE to OPENSTEP 4.2 i860 firmware.

Use 4.2 as a secondary comparative corpus only:

1. keep 3.3 proven-function set as the primary executable baseline
2. use 4.2 to test whether a hypothesis survives version drift
3. promote only cross-version claims that are supported by:
   - function-associated code in both versions
   - coherent control flow (not orphan decode)
   - consistent MMIO/dispatch behavior across both binaries

In short: 4.2 is useful for negative filtering and compatibility checks, not as the main source of new trustworthy GaCK logic.
