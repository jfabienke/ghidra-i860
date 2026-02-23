# Layered Intent Rules (Generic + Compiler)

## Rule Naming

Base layer (`GENERIC_*`) and compiler overlay (`COMPILER_*`):

- `GENERIC_NO_MMIO_SIDE_EFFECTS`: Function has zero MMIO-tagged instructions.
- `GENERIC_NO_STRING_REFS`: Function has zero recovered string references.
- `GENERIC_NO_UNRESOLVED_BRI`: Function is not flagged with unresolved computed branch.
- `GENERIC_COMPACT_BODY_LE_64_INSNS`: Function body is compact (<= 64 decoded instructions).
- `COMPILER_DELAY_SLOT_NOP_PATTERN`: At least one delayed control-transfer instruction has a canonical NOP delay slot.
- `COMPILER_ORH_OR_CONST_BUILD`: Contains GCC-style 32-bit constant materialization (`orh` then `or` on same destination).
- `COMPILER_SHL_SHRA_SIGNEXT_PAIR`: Contains `shl` -> `shra` immediate pair consistent with backend sign-extension idioms.
- `COMPILER_FP_ESCAPE_PRESENT`: Contains at least one FP escape opcode (op6=0x12).
- `COMPILER_FP_SAVE_RESTORE_SHELL`: Contains FP save/restore shell shape (`fst.q` + `fld.q` + `ret`).

## Compiler Generation Likelihood

- Bin: `same-lineage`
- Delta score: `6`
- Confidence: `low`
- Reasons:
  - `strong_rule_delta=0`
  - `weak_rule_delta=1`
  - `runtime_const_mismatch=False`
  - `normalized_rate_delta=0.0175`
  - `evidence_strength=1.50`

## NeXTSTEP 3.3

- Factpack: `re/nextdimension/kernel/reports/factpack/20260209-162613`
- Binary: `re/nextdimension/kernel/i860_kernel.bin`
- Functions evaluated: `60`
- Class counts: `{"likely_product_or_dispatch": 58, "mixed_compiler_signal_in_product_code": 2}`

### Runtime860 Constant Probe
- `COMPILER_RUNTIME860_DIVMOD_CONST_BLOCK_PRESENT`: `False`
- Full-block offset: `None`
- Subpattern hits: `{"onepluseps": 0, "two52": 0, "two52two31": 0}`

### Rule Hit Counts
- `COMPILER_DELAY_SLOT_NOP_PATTERN`: `0`
- `COMPILER_FP_ESCAPE_PRESENT`: `2`
- `COMPILER_FP_SAVE_RESTORE_SHELL`: `0`
- `COMPILER_ORH_OR_CONST_BUILD`: `0`
- `COMPILER_SHL_SHRA_SIGNEXT_PAIR`: `0`
- `GENERIC_COMPACT_BODY_LE_64_INSNS`: `57`
- `GENERIC_NO_MMIO_SIDE_EFFECTS`: `17`
- `GENERIC_NO_STRING_REFS`: `60`
- `GENERIC_NO_UNRESOLVED_BRI`: `52`

### Layered Top Candidates

| Entry | Score | Class | Generic | Compiler | MMIO | Strings |
|-------|------:|-------|--------:|---------:|-----:|--------:|
| `0xf807ee1c` | 4 | mixed_compiler_signal_in_product_code | 3 | 1 | 3 | 0 |
| `0xf800f80c` | 4 | likely_product_or_dispatch | 4 | 0 | 0 | 0 |
| `0xf800f4d4` | 4 | likely_product_or_dispatch | 4 | 0 | 0 | 0 |
| `0xf800db54` | 4 | likely_product_or_dispatch | 4 | 0 | 0 | 0 |
| `0xf800cc00` | 4 | likely_product_or_dispatch | 4 | 0 | 0 | 0 |
| `0xf800c458` | 4 | likely_product_or_dispatch | 4 | 0 | 0 | 0 |
| `0xf800c194` | 4 | likely_product_or_dispatch | 4 | 0 | 0 | 0 |
| `0xf800bd9c` | 4 | likely_product_or_dispatch | 4 | 0 | 0 | 0 |
| `0xf800bb60` | 4 | likely_product_or_dispatch | 4 | 0 | 0 | 0 |
| `0xf800b9e0` | 4 | likely_product_or_dispatch | 4 | 0 | 0 | 0 |
| `0xf800b504` | 4 | likely_product_or_dispatch | 4 | 0 | 0 | 0 |
| `0xf800a1c8` | 4 | likely_product_or_dispatch | 4 | 0 | 0 | 0 |
| `0xf8008e20` | 4 | likely_product_or_dispatch | 4 | 0 | 0 | 0 |
| `0xf8008dd4` | 4 | likely_product_or_dispatch | 4 | 0 | 0 | 0 |
| `0xf8004e44` | 4 | likely_product_or_dispatch | 4 | 0 | 0 | 0 |
| `0xf80017cc` | 4 | likely_product_or_dispatch | 4 | 0 | 0 | 0 |
| `0xf8000348` | 4 | likely_product_or_dispatch | 4 | 0 | 0 | 0 |
| `0xf8021a20` | 3 | mixed_compiler_signal_in_product_code | 2 | 1 | 1 | 0 |
| `0xf800cb9c` | 3 | likely_product_or_dispatch | 3 | 0 | 0 | 0 |
| `0xf800df78` | 3 | likely_product_or_dispatch | 3 | 0 | 1 | 0 |

## OPENSTEP 4.2

- Factpack: `re/nextdimension/kernel/reports/factpack/openstep42_20260214-004032`
- Binary: `re/nextdimension/ndserver_re/artifacts/extracted/os42/i860_scan/obj_01_off_000000_i860_preload_967496.bin`
- Functions evaluated: `63`
- Class counts: `{"likely_product_or_dispatch": 62, "mixed_compiler_signal_in_product_code": 1}`

### Runtime860 Constant Probe
- `COMPILER_RUNTIME860_DIVMOD_CONST_BLOCK_PRESENT`: `False`
- Full-block offset: `None`
- Subpattern hits: `{"onepluseps": 0, "two52": 0, "two52two31": 0}`

### Rule Hit Counts
- `COMPILER_DELAY_SLOT_NOP_PATTERN`: `0`
- `COMPILER_FP_ESCAPE_PRESENT`: `1`
- `COMPILER_FP_SAVE_RESTORE_SHELL`: `0`
- `COMPILER_ORH_OR_CONST_BUILD`: `0`
- `COMPILER_SHL_SHRA_SIGNEXT_PAIR`: `0`
- `GENERIC_COMPACT_BODY_LE_64_INSNS`: `62`
- `GENERIC_NO_MMIO_SIDE_EFFECTS`: `50`
- `GENERIC_NO_STRING_REFS`: `63`
- `GENERIC_NO_UNRESOLVED_BRI`: `47`

### Layered Top Candidates

| Entry | Score | Class | Generic | Compiler | MMIO | Strings |
|-------|------:|-------|--------:|---------:|-----:|--------:|
| `0xf806ea64` | 5 | mixed_compiler_signal_in_product_code | 4 | 1 | 0 | 0 |
| `0xf806f76c` | 4 | likely_product_or_dispatch | 4 | 0 | 0 | 0 |
| `0xf8012388` | 4 | likely_product_or_dispatch | 4 | 0 | 0 | 0 |
| `0xf800f80c` | 4 | likely_product_or_dispatch | 4 | 0 | 0 | 0 |
| `0xf800f4d4` | 4 | likely_product_or_dispatch | 4 | 0 | 0 | 0 |
| `0xf800df78` | 4 | likely_product_or_dispatch | 4 | 0 | 0 | 0 |
| `0xf800dc18` | 4 | likely_product_or_dispatch | 4 | 0 | 0 | 0 |
| `0xf800d804` | 4 | likely_product_or_dispatch | 4 | 0 | 0 | 0 |
| `0xf800d0ec` | 4 | likely_product_or_dispatch | 4 | 0 | 0 | 0 |
| `0xf800cf8c` | 4 | likely_product_or_dispatch | 4 | 0 | 0 | 0 |
| `0xf800cb1c` | 4 | likely_product_or_dispatch | 4 | 0 | 0 | 0 |
| `0xf800c79c` | 4 | likely_product_or_dispatch | 4 | 0 | 0 | 0 |
| `0xf800c694` | 4 | likely_product_or_dispatch | 4 | 0 | 0 | 0 |
| `0xf800c630` | 4 | likely_product_or_dispatch | 4 | 0 | 0 | 0 |
| `0xf800c584` | 4 | likely_product_or_dispatch | 4 | 0 | 0 | 0 |
| `0xf800c520` | 4 | likely_product_or_dispatch | 4 | 0 | 0 | 0 |
| `0xf800c2a4` | 4 | likely_product_or_dispatch | 4 | 0 | 0 | 0 |
| `0xf800c194` | 4 | likely_product_or_dispatch | 4 | 0 | 0 | 0 |
| `0xf800c01c` | 4 | likely_product_or_dispatch | 4 | 0 | 0 | 0 |
| `0xf800bd9c` | 4 | likely_product_or_dispatch | 4 | 0 | 0 | 0 |
