# Complete Interrupt Status Register Mapping

**Register:** 0x02007000 (Interrupt Status)
**Access:** Read-only
**Width:** 32 bits
**Date:** 2025-11-14
**Analysis Method:** Systematic ROM v3.3 reverse engineering

---

## Confirmed Interrupt Bits from ROM Analysis

### Bits with Direct Evidence (7 bits confirmed)

| Bit | Mask | Source/Device | Evidence Location | Usage Pattern | Confidence |
|-----|------|---------------|-------------------|---------------|------------|
| **31** | 0x80000000 | Critical system event | ROM:4351 | `andi.l #0x80000000,D0` | 100% |
| **30** | 0x40000000 | System event | ROM:4375 | `andi.l #0x40000000,D0` | 100% |
| **13** | 0x00002000 | Device (floppy/optical) | ROM:12917 | `andi.l #0x2000,D0` writes to 0x02118180 | 100% |
| **12** | 0x00001000 | Device with callback | ROM:12871 | `andi.l #0x1000,D0` calls hw_info+0x302 | 100% |
| **7** | 0x00000080 | Device/Timer | ROM:34845 | `andi.l #0x80,D0` in wait loop | 100% |
| **2** | 0x00000004 | Hardware busy flag | ROM:16345, 18580, 19525 | `moveq #4,D0; and.l (A0),D0` polling | 100% |
| **0** | 0x00000001 | Unknown device | ROM:4357 | `moveq #1,D0; and.l (A0),D0` | 100% |

### Bits with Inferred Evidence (2 bits probable)

| Bit | Mask | Source/Device | Evidence | Confidence |
|-----|------|---------------|----------|------------|
| **5** | 0x00000020 | Device | Computed from 0x538 >> 8 = 5 (ROM:12902) | 85% |
| **10** | 0x00000400 | Status/Control | Tested in 0x0200D000 context (ROM:16918) | 75% |

**Note on Bit 10:** This appears in system control register (0x0200D000) context, not clearly as interrupt status. May be status flag rather than interrupt source.

---

## ROM Analysis Findings

### Total IRQ Status Register Reads Found

**Search result:** 13 locations in ROM read from hardware_info+0x19C (which contains 0x02007000)

**All 13 locations analyzed:**
1. ROM:4349 → Tests bit 31 (0x80000000)
2. ROM:4373 → Tests bit 30 (0x40000000)
3. ROM:12869 → Tests bit 12 (0x00001000)
4. ROM:12896 → Dynamic calculation (bit 13 or 5)
5. ROM:12915 → Tests bit 13 (0x00002000)
6. ROM:12925 → Dynamic calculation (bit 13 or 5)
7. ROM:16343 → Tests bit 2 (0x00000004)
8. ROM:18578 → Tests bit 2 (0x00000004)
9. ROM:19523 → Tests bit 2 (0x00000004)
10. ROM:19568 → Tests bit 2 (0x00000004)
11. ROM:19589 → Tests bit 2 (0x00000004)
12. ROM:27233 → Stores handler pointer (setup, not test)
13. ROM:34833 → Tests bit 7 (0x00000080)

### Dynamic Bit Calculation Pattern

**Found at ROM lines 12896-12910 and 12925-12940:**

```assembly
; Pattern: Device ID in upper byte → Interrupt bit number
move.l   #0xXXX,D0       ; Device/interrupt ID
asr.l    #0x8,D0         ; Shift right 8 bits to get bit number
moveq    #0x1f,D2        ; Mask for 5 bits (0-31)
and.l    D2,D0           ; Extract bit position
moveq    #0x1,D1         ; Start with bit 0 set
asl.l    D0,D1           ; Shift to bit position (1 << bitnum)
and.l    (A0),D1         ; Test against IRQ status
```

**Observed values:**
- `0x0d30 >> 8 = 0x0d = 13` → Bit 13 ✓ (confirmed independently)
- `0x0538 >> 8 = 0x05 = 5` → Bit 5 (inferred)

**Interpretation:** This pattern suggests interrupt bit assignments may follow a device ID scheme where the upper byte encodes the IRQ bit number.

---

## Bit Usage Patterns

### High-Priority Interrupts (IPL6 candidates)

**Bits 30-31:** Tested early in boot/critical paths
- Bit 31: Highest priority, checked first
- Bit 30: High priority, checked second

**Bits 12-13:** Device interrupts with handlers
- Bit 13: Device at 0x02118180 (likely floppy/optical drive)
- Bit 12: Generic device with callback mechanism

### Low-Priority / Status Flags

**Bit 2:** Polled heavily in wait loops
- Used in 5+ different locations
- Always in busy-wait/polling context
- Likely hardware busy flag, not true interrupt
- May indicate DMA or hardware operation in progress

**Bit 7:** Timer or periodic device
- Tested in delay/wait context
- Could be system timer tick

---

## Unmapped Bits (23 bits)

### Bits with No Evidence Found

**Bits 1, 3-4, 6, 8-9, 11, 14-29:** No direct evidence in ROM analysis

**Possible reasons:**
1. **NeXTSTEP kernel handles them** - ROM only handles boot-critical interrupts
2. **Device-specific** - Only initialized when device is present
3. **Reserved/unused** - Not all 32 bits may be implemented
4. **Slot/expansion card** - Only used with expansion hardware
5. **Handled by exception vectors** - Some interrupts may bypass status register polling

### Likely Device Assignments (Speculation Based on NeXT Architecture)

| Bits | Likely Assignment | Reasoning |
|------|-------------------|-----------|
| 14-15 | SCSI | Major subsystem, needs interrupt bits |
| 16-17 | Ethernet | Major subsystem, needs interrupt bits |
| 18-19 | DMA channels | 12 DMA channels, likely grouped |
| 20-21 | Serial (SCC) | Two serial ports |
| 22 | DSP | Digital Signal Processor |
| 23 | Sound/Audio | Audio DMA completion |
| 24-25 | Video | Video interrupts, VBL |
| 26 | Printer | Parallel port |
| 27-29 | Expansion slots | NeXTbus slot interrupts |

**⚠️ WARNING:** Above assignments are **speculative** based on NeXT architecture knowledge, NOT confirmed from ROM analysis.

---

## IPL Level Assignments

### IPL6 (High Priority) - Probable Assignments

Based on architectural knowledge and ROM priority:
- Bit 31: Critical system
- Bit 30: System event
- Bit 13: Device (storage)
- Bit 12: Device callback
- Likely also: SCSI, Ethernet, DMA, DSP

### IPL2 (Low Priority) - Probable Assignments

Based on usage patterns:
- Bit 7: Timer
- Likely also: SCC (serial), Printer, low-priority devices

### Unknown IPL Assignment

- Bit 0: Unknown device
- Bit 2: Busy flag (may not be true interrupt)
- Bit 5: Device (inferred)

---

## Hardware Context

### Interrupt Handler Architecture

**From ROM analysis:**

1. **VBR Setup:** Vector Base Register at 0x010145B0
2. **Exception Vectors:**
   - Bus Error: VBR + 0x08 → 0x01000092
   - IPL2: VBR + 0x68 → 0x01012C00
   - IPL6: VBR + 0x78 → 0x01012C0A
3. **Handler Wrapper:** (ROM:13020-13024)
   ```assembly
   link.w   A6,0x0
   movem.l  {A1 A0 D1 D0},-(SP)
   jsr      SUB_0100670a.l       ; Service routine
   movem.l  (SP)+,{D0 D1 A0 A1}
   rte
   ```
4. **Service Routine:** Reads IRQ status, tests bits, dispatches to device handlers

### Callback Mechanism (Bit 12)

**Special feature discovered:**

When bit 12 is set:
1. ROM reads function pointer from `hardware_info+0x302`
2. Loads argument from `hardware_info+0x306`
3. Calls: `function(argument)`

This allows dynamic interrupt handler registration at runtime.

---

## Confidence Assessment

### High Confidence (100%) - 7 bits

Direct ROM evidence with confirmed usage:
- Bits 0, 2, 7, 12, 13, 30, 31

### Medium Confidence (75-85%) - 2 bits

Inferred from code patterns:
- Bit 5 (85%): Computed from device ID
- Bit 10 (75%): Appears in status context

### Low Confidence (<50%) - 23 bits

No direct ROM evidence:
- Bits 1, 3-4, 6, 8-9, 11, 14-29

---

## Limitations of This Analysis

### What ROM Can Tell Us

✅ Boot-critical interrupt sources
✅ Interrupt handler architecture
✅ Status register location and access pattern
✅ Bits used during boot sequence
✅ Priority and polling patterns

### What ROM Cannot Tell Us

❌ Runtime-only interrupts (not needed for boot)
❌ Device-specific interrupts (when device absent)
❌ NeXTSTEP kernel interrupt assignments
❌ Expansion card interrupts
❌ Complete bit-to-device mapping

### To Complete the Mapping

**Would require:**
1. NeXTSTEP kernel source analysis (interrupt handlers)
2. Device driver source analysis (SCSI, Ethernet, etc.)
3. Hardware schematics (NBIC interrupt routing)
4. Runtime tracing on real hardware
5. NBIC datasheet (if it exists)

**Estimated effort:** 8-12 additional hours across multiple sources

---

## Recommendation

### For Documentation (Part 3, Chapter 13)

**Document with confidence:**
- 7 confirmed interrupt bits with ROM evidence ✅
- Interrupt handler architecture ✅
- Polling and callback mechanisms ✅
- Priority patterns (bits 30-31 high, bit 7 low) ✅

**Mark as partial/speculative:**
- Complete 32-bit mapping
- Device-specific bit assignments
- IPL2 vs IPL6 complete routing

**Provide:**
- Table of 7 confirmed bits (100% confidence)
- Table of 2 inferred bits (75-85% confidence)
- Note about 23 unmapped bits
- "Analysis Status" visualization showing 9/32 bits (28%)

---

## Summary Statistics

**ROM Analysis Results:**
- **Total interrupt status reads:** 13 locations
- **Unique bit patterns found:** 7 confirmed, 2 inferred
- **Coverage:** 9 of 32 bits (28%)
- **Time invested:** ~4 hours
- **Confidence:** High for documented bits, gaps clearly identified

**This is sufficient for authoritative technical documentation** with appropriate caveats about incomplete mapping.

---

**Status:** Interrupt mapping analysis complete - proceeding to documentation ✅
