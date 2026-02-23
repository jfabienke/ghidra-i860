# Timeout Configuration Search Strategy

**Goal:** Find NBIC timeout configuration register for Chapter 14 completion

**Current Status:** Chapter 14 is 65% complete - missing timeout configuration location and duration

---

## What We're Looking For

**Target Information:**
1. NBIC timeout configuration register address
2. Timeout duration value (in CPU cycles, microseconds, or ticks)
3. Any differences between slot space vs board space timeouts
4. Initialization code that sets timeout value

**Expected Pattern:**
```assembly
; Hypothetical timeout configuration
movea.l  #0x0200XXXX,A0    ; Timeout config register
move.l   #TIMEOUT_VALUE,(A0); Set timeout duration
```

---

## Search Strategy

### Strategy 1: Analyze All NBIC Register Accesses

**Known NBIC Registers:**

From ROM grep results, we have these NBIC register accesses:

| Address | Occurrences | Known Function | Lines |
|---------|-------------|----------------|-------|
| 0x0200C000 | ~4 | System ID Register | 3260, 6967, 6061 |
| 0x0200D000 | ~10 | System Control (Memory) | 5900, 6779, 10973, 16757, 16875, 20820, 23010 |
| 0x0200E000 | ~9 | Hardware Sequencer | 9093, 9104, 11240, 11388, 19334, 19522, 19626, 19875, 19906 |
| 0x02007000 | 1 | Interrupt Status | 3270 |
| 0x02007800 | 1 | Interrupt Mask | 3269 |

**Missing Registers to Investigate:**

Based on typical ASIC design, likely candidates:

| Address Range | Hypothesis | Priority |
|---------------|------------|----------|
| 0x0200F000 | Timer/Timeout config | **HIGH** |
| 0x0200B000 | Bus control | HIGH |
| 0x02008000 | DSP control (known) | Low |
| 0x02009000 | Unknown | Medium |
| 0x0200A000 | Unknown | Medium |

**Action Items:**

1. ✅ Search ROM for 0x0200[89ABCDEF]xxx patterns
2. Read ROM sections that access 0x0200E000 (Hardware Sequencer)
3. Check if timeout is part of System Control (0x0200D000)

### Strategy 2: Analyze Hardware Sequencer (0x0200E000)

**Evidence:** 9 accesses to 0x0200E000 in ROM

**Hypothesis:** Timeout configuration might be in Hardware Sequencer register set

**Action Items:**

1. Read ROM lines: 9093, 9104, 11240, 11388, 19334, 19522, 19626, 19875, 19906
2. Look for bit fields or offsets related to timeout
3. Check for writes immediately after system initialization

**Sample to analyze:**
```
Line 9093: movea.l #0x200e000,A0
Line 9104: movea.l #0x200e000,A0
```

Need to see what operations follow these loads.

### Strategy 3: Analyze System Control Register (0x0200D000)

**Known Functions:**
- Bit 0: Memory reset
- Bits 16-23: Memory bank enables
- Bit 10: Status flag
- Bit 15: Hardware flag

**Hypothesis:** Timeout might be additional bits in this register

**Action Items:**

1. Read complete initialization sequence for 0x0200D000
2. Look for bit manipulations we haven't identified
3. Check bits 24-31 (upper byte) for timeout config

### Strategy 4: Search for Timeout-Related Constants

**Look for suspicious constants that might be timeout values:**

**At 25 MHz (40ns per cycle):**
- 1µs = 25 cycles = 0x19
- 2µs = 50 cycles = 0x32
- 5µs = 125 cycles = 0x7D
- 10µs = 250 cycles = 0xFA

**Action Items:**

1. Search ROM for: `#0x19`, `#0x32`, `#0x7D`, `#0xFA` near NBIC register writes
2. Look for division/shift operations that might compute timeout from clock frequency
3. Check hardware_info structure for timeout values

### Strategy 5: Examine Previous Emulator Source

**Check Previous emulator for timeout simulation:**

Files to check:
- `src/nbic.c` or similar NBIC emulation
- `src/sysReg.c` (already analyzed for interrupts)
- `src/ioMemTabNEXT.c` (IO memory handlers)

**Search patterns:**
```bash
grep -r "timeout" src/
grep -r "TIMEOUT" src/
grep -r "0x0200" src/ | grep -v "0x02007" | grep -v "0x0200C" | grep -v "0x0200D" | grep -v "0x0200E"
```

### Strategy 6: Check NuBus Documentation

**Research approach:**

NuBus (Apple's similar bus) timeout documentation might provide clues:

1. Standard NuBus timeout: ~1µs (confirmed in literature)
2. NeXTbus likely similar
3. Configuration register pattern might follow NuBus conventions

**Action:** Compare NeXTbus vs NuBus register maps

### Strategy 7: Cross-Reference with NeXTdimension

**Hypothesis:** NeXTdimension documentation might mention timeout

Files to check:
- `/Users/jvindahl/Development/previous/docs/hardware/nextdimension-*`
- NeXTdimension firmware might configure timeout
- i860 might need specific timeout for board space access

---

## Prioritized Action Plan

### Phase 1: Quick Wins (30 minutes)

1. **Search Previous emulator for timeout implementation**
   ```bash
   cd /Users/jvindahl/Development/previous/src
   grep -rn "timeout" . | grep -i "bus\|nbic\|slot"
   grep -rn "0x0200" . | grep -v "0x02007\|0x0200[CDE]"
   ```

2. **Read Hardware Sequencer usage in ROM**
   - Extract ROM lines around 9093, 9104, 11240
   - Look for initialization patterns

3. **Check for 0x0200F000 register**
   ```bash
   grep -n "0x200f" nextcube_rom_v3.3_disassembly.asm
   ```

### Phase 2: Deep Analysis (1-2 hours)

4. **Analyze complete System Control register initialization**
   - Read ROM lines 5896-5928 (memory reset sequence)
   - Look for additional control bits

5. **Examine all unknown 0x0200xxxx accesses**
   - Any register we haven't identified yet
   - Check offsets from known base addresses

6. **Disassemble Hardware Sequencer access patterns**
   - Full context for all 9 accesses
   - Look for multi-byte structures

### Phase 3: External Resources (1 hour)

7. **Check NeXT hardware documentation**
   - Any NBIC datasheets
   - NeXTbus specification
   - NuBus comparison

8. **Examine NeXTdimension firmware**
   - Might configure different timeouts
   - i860 boot code might show timeout setup

---

## Success Criteria

**We've found timeout configuration when we can document:**

1. ✅ Register address (e.g., 0x0200Fxxx)
2. ✅ Bit fields or value range
3. ✅ Initialization code in ROM
4. ✅ Actual timeout duration (in µs or cycles)

**Acceptable outcomes:**

- **Best:** Find exact register and value
- **Good:** Find register, estimate value from context
- **Acceptable:** Determine timeout is fixed in hardware (no software config)
- **Document:** If not found after Phase 1-3, document search attempts

---

## Current Leads

### Lead 1: Hardware Sequencer (0x0200E000)

**Evidence:**
- 9 accesses in ROM
- Named "Hardware Sequencer" from previous analysis
- Has busy/ready flags (bits 6-7)
- Has enable bit (bit 5)
- Has high-level enable (bit 23)

**Hypothesis:** Timeout might be additional bits in this register

**Next:** Read ROM context around all 9 accesses

### Lead 2: Undiscovered Register (0x0200F000?)

**Evidence:**
- No accesses found yet
- Typical ASIC has contiguous register block
- 0x0200C/D/E are known, F is next logical address

**Next:** Explicit search for 0x200F

### Lead 3: System Control Upper Bits

**Evidence:**
- Only analyzed bits 0, 10, 15, 16-23
- Bits 24-31 not yet examined
- Could contain timeout configuration

**Next:** Analyze complete bit patterns written to 0x0200D000

---

## Tools and Commands

**Search ROM for specific address:**
```bash
grep -n "#0x200f" nextcube_rom_v3.3_disassembly.asm
```

**Extract context around ROM line:**
```bash
sed -n '9090,9110p' nextcube_rom_v3.3_disassembly.asm
```

**Search Previous emulator:**
```bash
cd /Users/jvindahl/Development/previous/src
rg -i "timeout" -A 3 -B 3
```

**Search for specific constant:**
```bash
grep -n "#0x[0-9a-f]*19\|#0x[0-9a-f]*32" nextcube_rom_v3.3_disassembly.asm
```

---

## Timeline

**Estimated effort for each phase:**
- Phase 1 (Quick Wins): 30 minutes
- Phase 2 (Deep Analysis): 1-2 hours
- Phase 3 (External Resources): 1 hour

**Total: 2.5-3.5 hours to exhaustively search**

If not found after Phase 3:
- Document search attempts
- Mark as "likely fixed in hardware"
- Estimate based on NuBus standard (~1µs)
- Maintain Chapter 14 at current state with clear annotation

---

**Status:** Ready to execute Phase 1
**Next Action:** Search Previous emulator for timeout implementation
