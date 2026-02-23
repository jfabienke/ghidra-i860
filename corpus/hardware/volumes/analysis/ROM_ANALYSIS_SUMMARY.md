# ROM v3.3 Analysis Summary

**Date:** 2025-11-14
**Purpose:** Extract NBIC register details for Volume I, Part 3 documentation

---

## Key Findings

### 1. NBIC/System Control Registers Identified

| Address | Name | Access | Primary Function |
|---------|------|--------|------------------|
| **0x0200C000** | System ID Register | Read | Hardware type detection (bits 23-20) |
| **0x0200D000** | System Control Register | R/W | Memory reset (bit 0), bank enables (bits 16-23), status (bit 10) |
| **0x02007000** | Interrupt Status Register | Read | 32-bit interrupt source status |
| **0x02007800** | MMIO Base 2 | R/W | Purpose unclear (stored but not directly accessed) |
| **0x0200E000** | Hardware Sequencer | R/W | DMA/hardware control with busy/ready flags |

### 2. Memory Subsystem Reset Timing

**Register:** 0x0200D000, bit 0
**Sequence:**
1. Assert reset (set bit 0) → Wait 120ms
2. Deassert reset (clear bit 0) → Wait 120ms
3. Repeat N times (parameter-driven)
4. Final 120ms delay

**Total time per cycle:** 240ms
**Purpose:** DRAM initialization with timing spec compliance

### 3. Memory Bank Architecture

**Register:** 0x0200D000, bits 16-23 (two bits per bank)

| Bank | Base Address | Enable Bits | Bit Mask |
|------|-------------|-------------|----------|
| 0 | 0x04000000 | 16, 20 | 0x00110000 |
| 1 | 0x05000000 | 17, 21 | 0x00220000 |
| 2 | 0x06000000 | 18, 22 | 0x00440000 |
| 3 | 0x07000000 | 19, 23 | 0x00880000 |

**Discovery process:** ROM enables each bank, tests for memory response, determines SIMM type, disables if no memory present.

### 4. Interrupt Status Register (0x02007000)

**Confirmed interrupt sources:**

| Bit | Mask | Source | ROM Evidence |
|-----|------|--------|--------------|
| 31 | 0x80000000 | Critical system event | Line 4351 - highest priority handler |
| 30 | 0x40000000 | System event | Line 4375 - high priority handler |
| 13 | 0x00002000 | Device (floppy?) | Line 12917 - writes to 0x02118180 |
| 12 | 0x00001000 | Device callback | Line 12871 - calls function at hardware_info+0x302 |

**Usage pattern:** Read-only status register, software polls bits, each bit triggers specific handler.

### 5. Hardware Info Structure

ROM stores system state and register bases in a **hardware info structure**:

**Key offsets:**
- **+0x19C:** Interrupt status register base (= 0x02007000)
- **+0x1A0:** MMIO base 2 (= 0x02007800)
- **+0x194:** Hardware type ID (compared to 0x139)
- **+0x302:** Device interrupt handler function pointer
- **+0x306:** Device interrupt handler argument
- **+0x3B2:** Hardware register base pointer

### 6. Hardware Sequencer (0x0200E000)

**Bit fields:**
- **Bit 7 (+0x0):** Busy flag (hardware operation in progress)
- **Bit 6 (+0x2):** Completion/ready flag (wait for clear)
- **Bit 5 (+0x0):** Hardware enable/control
- **Bit 23 (+0x0):** High-level subsystem enable (0x00800000)

**Access pattern:** Requires interrupt disable, test busy flag, wait for ready, set enable.
**Purpose:** DMA or hardware sequencer control with completion signaling.

### 7. System Control Status (0x0200D000)

**Additional findings:**
- **Bit 10 (0x400):** Status flag tested at ROM line 16918
- **Bit 15:** Hardware-specific, cleared for hardware type 0x139 (line 10986)

---

## ROM Initialization Sequence

### Phase 1: Hardware Detection (ROM 3260-3270)
1. Read system ID from 0x0200C000
2. Extract hardware type from bits 23-20
3. If type 0x4, read alternate config from 0x02200000
4. Store MMIO bases in hardware_info (+0x19C, +0x1A0)

### Phase 2: Memory Reset (ROM 5896-5928)
1. Callable function with iteration parameter
2. Each iteration: Toggle bit 0 with 120ms delays (240ms total)
3. Final 120ms delay after all iterations
4. Total configurable based on memory type

### Phase 3: Bank Discovery (ROM 6779-6828)
1. Calculate bank base address (0x04000000 + N×0x01000000)
2. Enable bank (set bits 16+N and 20+N in 0x0200D000)
3. Test memory response (quick test)
4. Run detailed test if quick test passes
5. Determine SIMM configuration
6. Disable bank if tests fail

---

## Evidence-Based Conclusions

**What we know with confidence:**
1. ✅ **5 NBIC/system control registers mapped** with specific functions
2. ✅ **Memory reset timing:** 120ms delays, DRAM spec compliance
3. ✅ **Memory bank architecture:** 4 banks, dual-bit enables, 0x04000000 base
4. ✅ **Interrupt status register:** 32-bit read-only, bit-per-source
5. ✅ **Hardware info structure:** Stores bases at +0x19C and +0x1A0

**What needs more analysis:**
1. ⚠️ **Complete interrupt bit mapping:** Only 4 of 32 bits identified
2. ⚠️ **0x02007800 purpose:** Stored but not directly accessed in analyzed sections
3. ⚠️ **0x0200E000 full protocol:** Multi-byte structure needs complete mapping
4. ⚠️ **Timeout/bus error config:** Not found in NBIC registers (may be elsewhere)
5. ⚠️ **Bits 10, 15 of 0x0200D000:** Status flags with unclear specific purpose

---

## Next Steps for Volume I Part 3

**Ready to document:**
- Chapter 11: Register map with confirmed functions
- Chapter 12: Memory initialization sequence with timing diagrams
- Chapter 13: Memory bank architecture and discovery algorithm
- Chapter 14: Interrupt status register and polling mechanism

**Needs more RE before documenting:**
- Complete interrupt bit assignments (need to trace all 32 bits)
- Timeout/bus error configuration (need to find where this lives)
- Full hardware sequencer protocol (0x0200E000 multi-byte structure)
- Complete hardware_info structure map (all 1KB+ of offsets)

---

## Recommendation

**Proceed with Part 3 documentation** using confirmed findings, with clear annotations where information is incomplete. The evidence base is strong enough for accurate technical documentation of the known functionality.

Mark sections as "Analysis in progress" where bit assignments or register purposes are not yet fully determined. This maintains documentation integrity while advancing the publication.

---

**Source:** `nextcube_rom_v3.3_disassembly.asm`
**Method:** Systematic grep for 0x0200xxxx patterns, context analysis
**Quality:** High confidence on core findings, medium on peripheral details
**Completeness:** ~60% of NBIC functionality mapped
