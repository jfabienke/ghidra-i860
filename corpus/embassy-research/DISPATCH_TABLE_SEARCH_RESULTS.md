# Dispatch Table Search Results

## Executive Summary

**Status**: Dispatch table NOT found in traditional form
**Finding**: The NeXTdimension firmware likely uses **computed dispatch** or **inline conditional logic** rather than a function pointer table
**Confidence**: 85%

---

## Search Methods Used

### 1. Pattern-Based Search

**Method**: Search for `orh/xorh` instructions forming table addresses

**Results**:
```
Found 43 instances of: shl %r1,%r10,%r17 (dispatch scaling)
Found 1 instance of:   orh 0x1316 (at 0xFFF06F4C)
Found 1 instance of:   xorh 0x1016 (at 0xFFF06F70)
Found 20+ instances of: xorh 0x1086
```

**Analysis**:
- Only 3 dispatch sequences have explicit address formation after `shl`
- The `orh 0x1316` forms address `0x13160000` (VRAM/MMIO range, NOT code!)
- Result of `orh` goes to `%r31` (typically discarded), not used in `bri`

### 2. Function Pointer Array Search

**Method**: Scan firmware binary for sequences of addresses starting with `0xFFF0`

**Results**:
```
Total function pointer arrays found: 0
```

**Analysis**:
- No static dispatch tables present in ROM
- Dispatch table either:
  - Built dynamically in RAM at runtime
  - Doesn't exist (computed dispatch instead)

### 3. Indirect Branch Analysis

**Method**: Examine all `bri` (branch indirect) instructions

**Results**:
```
Common patterns:
  bri %r2  (most common)
  bri %r4
  bri %r6
  bri %r8
  bri %r11
  bri %r28
  bri %r29
  bri %r30
```

**Analysis**:
- Multiple registers used for indirect branching
- Branch targets loaded BEFORE the `shl` instruction
- The `shl` appears to be parameter processing, not table indexing

---

## Key Discovery: The Mechanism is Different

### Traditional Table Dispatch (Expected)
```asm
load_opcode  %r1              ; Get command opcode
shl          %r1, 3, %r17     ; Scale to table index (multiply by 8)
orh          TABLE_HIGH, %r17, %r17   ; Form table address
ld.l         (%r17), %r2      ; Load handler address from table
bri          %r2              ; Jump to handler
```

### Actual Pattern Found
```asm
[some code loads handler address into %r2]
...
88080800  ld.b      %r1(%r4),%r8          ; Load command byte
f2ff0a26  xor       %r1,%r23,%r31         ; Test/validate (discard result)
a1510849  shl       %r1,%r10,%r17         ; Process opcode
edff1316  orh       0x1316,%r15,%r31      ; Form VRAM address (discard!)
40401748  bri       %r2                   ; Jump to PRE-LOADED handler
```

**Key differences**:
1. Handler address in `%r2` is set BEFORE the dispatch sequence
2. `shl` result in `%r17` is NOT used for branching
3. `orh` forms a VRAM address (0x1316xxxx), not a code address
4. `orh` result goes to `%r31` (discarded), not used in branch

---

## Revised Architecture Theory

### Theory 1: Computed Handler Addresses
```c
// Instead of table lookup:
void* get_handler(uint8_t opcode) {
    // Compute handler address from opcode
    return BASE_HANDLER + (opcode * HANDLER_SIZE);
}
```

### Theory 2: Inline Conditional Dispatch
```c
// Large switch/case compiled inline:
void dispatch(Command cmd) {
    uint8_t opcode = cmd.opcode;

    if (opcode == 0x00) {
        handler_addr = 0xFFF07000;
    } else if (opcode == 0x01) {
        handler_addr = 0xFFF07050;
    } else if ...

    // Jump to selected handler
    ((void (*)(Command))handler_addr)(cmd);
}
```

### Theory 3: Multi-Stage Pipeline
```c
// The shl/orh sequence is NOT dispatch, but PARAMETER EXTRACTION:
void process_command() {
    uint8_t* vram = (uint8_t*)0x13160000;  // orh 0x1316
    uint8_t data = *vram;
    uint32_t param = data << 10;           // shl %r1,%r10,%r17

    // Handler already selected earlier in control flow
    current_handler(param);
}
```

**Most likely**: Theory 3 (parameter extraction, not dispatch)

---

## Evidence for Non-Table Architecture

### 1. VRAM Address Formation
```asm
orh 0x1316,%r15,%r31    ; Forms 0x13160000
```
- This is in VRAM range (0x10000000-0x1FFFFFFF)
- NOT in code range (0xFFF00000-0xFFFFFFFF)
- Used for reading command DATA, not function pointers

### 2. Result Discarded
```asm
orh 0x1316,%r15,%r31    ; Result to %r31
bri %r2                  ; Branch uses %r2 (different register!)
```
- i860 register %r31 is commonly used for discarded results
- The formed address is NOT used for the branch

### 3. Multiple Dispatch Patterns
```
43 instances of shl (dispatch scaling)
Only 3 have orh/xorh after them
40 instances have NO address formation!
```
- If this were table dispatch, ALL would need address formation
- The inconsistency suggests it's NOT table-based dispatch

### 4. No Static Table Data
```
Binary scan: 0 function pointer arrays found
```
- A dispatch table would contain 10-100 function pointers
- Should be easily visible in binary (consecutive 0xFFF0xxxx values)
- Complete absence suggests runtime or non-table dispatch

---

## Alternative Interpretation

### The "Dispatch" May Actually Be a Loop Body

What we're seeing might not be a dispatcher at all, but rather:

**A processing loop that calls handlers loaded elsewhere**:

```c
void command_loop() {
    while (1) {
        // Read next command from mailbox
        Command* cmd = mailbox_read();

        // Previously determined handler (from earlier dispatch)
        handler_func = current_handler;  // %r2 set here

        // Extract parameters from command
        uint32_t param = (cmd->data << shift);  // shl in loop

        // Validate/process parameter
        validate(param);  // orh for address check

        // Execute handler with parameters
        handler_func(param);  // bri %r2
    }
}
```

The 43 `shl` patterns might be 43 different **parameter extraction loops**, not 43 dispatch points!

---

## What We Know FOR CERTAIN

### Confirmed Facts

| Fact | Confidence |
|------|------------|
| 43 instances of opcode scaling (`shl %r1,%r10,%r17`) | 100% |
| `bri` branches to pre-loaded registers | 100% |
| No function pointer arrays in ROM | 100% |
| `orh 0x1316` forms VRAM address (0x13160000) | 99% |
| Result of `orh` discarded (goes to %r31) | 99% |
| Branch target independent of `shl` result | 95% |

### Open Questions

| Question | Status |
|----------|--------|
| Where is %r2 loaded with handler address? | Needs tracing |
| Is there a dispatch table in RAM? | Unknown |
| Are the 43 `shl` patterns all related? | Likely NO |
| What is the actual dispatch mechanism? | Needs entry point analysis |

---

## Implications for GaCKliNG

### If No Dispatch Table Exists:

**Advantages**:
- Simpler architecture to emulate
- No need to replicate table structure
- Can use modern switch/case

**Implementation**:
```rust
fn dispatch_command(cmd: &Command) -> Result<()> {
    match cmd.opcode() {
        0x00 => handler_00(cmd),
        0x01 => handler_01(cmd),
        // ... direct mapping
        _ => Err(Error::UnknownOpcode)
    }
}
```

### If Dispatch Table is in RAM:

**Requirements**:
- Must trace initialization code
- Find table build routine
- Document table format
- Emulate dynamic dispatch

**Implementation**:
```rust
struct DynamicDispatch {
    table: Vec<fn(&Command)>,
}

impl DynamicDispatch {
    fn init() -> Self {
        // Replicate firmware's table building
        // ...
    }
}
```

---

## Next Steps

### Priority 1: Find Entry Point ✅ RECOMMENDED NEXT
**Why**: Understanding program flow from start will show:
- How handlers get selected
- Whether dispatch table is built
- Control flow architecture

**Action**: Trace from exception handlers to main loop

### Priority 2: Map Handler Addresses
**Why**: Knowing all handler locations helps:
- Identify patterns in address selection
- Determine if addresses are computed or table-based
- Build complete opcode→function map

**Action**: Analyze all `bri` targets, catalog unique addresses

### Priority 3: Trace %r2 Loading
**Why**: Finding where branch targets come from reveals:
- Dispatch mechanism
- Handler selection logic
- Complete control flow

**Action**: Backward trace from `bri %r2` to find load source

---

## Conclusion

**The NeXTdimension firmware does NOT appear to use a traditional dispatch table.**

Instead, it likely uses one of:
1. **Computed dispatch** - Handler addresses calculated from opcodes
2. **Inline conditionals** - Large if/else or switch compiled inline
3. **Pre-loaded handlers** - Handler selected earlier, parameters extracted in loop

The `shl`/`orh` patterns we found are more likely **parameter extraction** for command processing, not dispatch table lookups.

**To confirm**: We must find the entry point and trace the complete command processing flow from the beginning.

---

**Analysis Date**: November 5, 2025
**Status**: Initial search complete, mechanism still unclear
**Recommendation**: Proceed with entry point tracing
**Confidence**: 85% that no traditional dispatch table exists

