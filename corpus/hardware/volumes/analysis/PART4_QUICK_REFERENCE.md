# Part 4 DMA Quick Reference Card

**Purpose:** Fast lookup of key facts during Part 4 writing
**Date:** 2025-11-14

---

## DMA Basics

**ISP (Integrated Channel Processor):**
- 12 independent channels
- 128 bytes internal buffer per channel (emulator uses 16 for SCSI/MO)
- Channels: SCSI, Sound Out, Disk, Sound In, Printer, SCC, DSP, EN TX, EN RX, Video, M2R, R2M

**Base Address:** 0x02000000 (per-channel registers)

---

## Register Structure (Per Channel)

```
Offset    Register      Description
------    --------      -----------
+0x10     CSR           Control/Status Register (byte on 030, long on 040)
+0x4000   Next          Current transfer pointer
+0x4004   Limit         Transfer limit (may have flags for Ethernet)
+0x4008   Start         Chaining start address
+0x400C   Stop          Chaining stop address
+0x4010   Init          Initialize + offset
+0x3FF0   Saved Next    Saved pointer (after transfer)
+0x3FF4   Saved Limit   Saved limit (actual end)
+0x3FF8   Saved Start   Saved start
+0x3FFC   Saved Stop    Saved stop
```

**Source:** `dma.c:40-52`, `dma.c:164-345`

---

## CSR Bits (68030 NeXTcube)

**Read (Status):**
- `0x01` DMA_ENABLE - Transfer active
- `0x02` DMA_SUPDATE - Chaining active
- `0x08` DMA_COMPLETE - Transfer done
- `0x10` DMA_BUSEXC - Bus error occurred

**Write (Commands):**
- `0x01` DMA_SETENABLE - Start transfer
- `0x02` DMA_SETSUPDATE - Enable chaining
- `0x04` DMA_DEV2M - Direction: device to memory (0x00 = M2DEV)
- `0x08` DMA_CLRCOMPLETE - Clear complete flag
- `0x10` DMA_RESET - Clear complete, supdate, enable
- `0x20` DMA_INITBUF - Initialize internal FIFO

**68040 Difference:** CSR is 32-bit with bits shifted (divide by 0x10000 to convert)

**Source:** `dma.c:69-102`

---

## Ethernet Descriptors (Flag-Based)

**NO memory descriptors!** Ethernet uses limit register flags:

```c
#define EN_EOP      0x80000000  /* end of packet */
#define EN_BOP      0x40000000  /* beginning of packet */
#define ENADDR(x)   ((x)&~(EN_EOP|EN_BOP))
```

**Transmit:**
- Write `limit = buffer_end | EN_EOP` to mark packet boundary
- Hardware transfers to `ENADDR(limit)`, then checks `limit & EN_EOP` for interrupt

**Receive:**
- Write `limit = buffer_end` (no flags)
- When packet complete, hardware sets `next |= EN_BOP` to mark boundary
- Read `saved_limit` to get actual packet end address

**Confidence:** 95% (emulator explicit + "word-pumped DMA" docs match)

**Source:** `dma.c:796-798`, `dma.c:820-882`, `EMULATOR_DMA_DEEP_DIVE.md §2`

---

## Ring Buffer Wrap Protocol

**Key Insight:** Wrap happens **on interrupt**, not automatically

**Setup:**
1. Write `start` = ring buffer base
2. Write `stop` = ring buffer end
3. Write `next` = current position
4. Write `limit` = first transfer end
5. Write CSR = `DMA_SETENABLE | DMA_SETSUPDATE` (0x03)

**On Interrupt (when next == limit):**
```c
if (csr & DMA_SUPDATE) {  // Chaining mode?
    next = start;         // ← WRAP to ring base
    limit = stop;         // Reset limit to ring end
    csr &= ~DMA_SUPDATE;  // Clear chaining flag (2nd buffer now active)
    csr |= DMA_COMPLETE;  // Set completion flag
}
```

**Continuation:**
- Software writes CSR = `DMA_SETSUPDATE | DMA_CLRCOMPLETE` (0x0A)
- This re-enables chaining for next wrap

**Saved Limit Usage:**
- `saved_limit` contains actual address where transfer stopped
- Used for partial transfers and packet boundary detection

**Confidence:** 90% (emulator logic, no ROM validation)

**Source:** `dma.c:370-390`, `EMULATOR_DMA_DEEP_DIVE.md §3`

---

## Sound "One Ahead" Pattern

**Audio DMA runs one buffer ahead of consumption:**

```
Timeline:
1. Buffer N completes → interrupt fires
2. Handler calls do_dma_sndout_intr() (notify software of N done)
3. Handler fetches buffer N+1 via dma_sndout_read_memory()
4. Hardware plays buffer N+1 while software prepares N+2
```

**Underrun Detection:**
- If `dma_sndout_read_memory()` returns `len=0`, pipeline starved
- Handler calls `kms_sndout_underrun()` and retries in 100µs

**Timing:**
- Check every 8µs (at 44.1kHz, sample period = 22.7µs → 3x margin)

**Confidence:** 100% (explicit emulator implementation with comments)

**Source:** `snd.c:158-197`, `EMULATOR_DMA_DEEP_DIVE.md §4`

---

## FIFO Behavior (SCSI/MO)

**16-byte internal FIFO per channel** (SCSI, MO confirmed)

**Fill-Then-Drain Protocol:**
1. **Fill phase:** Device writes bytes into FIFO until 16 bytes accumulated
2. **Drain phase:** Once FIFO full, write 16 bytes to memory as longwords
3. **Residual handling:** Partial FIFO requires explicit flush command

**Alignment:**
- `next` must be longword-aligned (% 4 == 0)
- `limit` must be 16-byte aligned (% 16 == 0)
- Violation → emulator `abort()` (fatal)

**Flush Command:**
- Writes residual FIFO contents (< 16 bytes) to memory
- Used when device stops mid-FIFO (e.g., last sector not 16-byte aligned)

**Confidence:** 95% (SCSI/MO consistent implementation)

**Source:** `dma.c:410-567`, `EMULATOR_DMA_DEEP_DIVE.md §5`

---

## Bus Error Handling

**On Bus Error During DMA:**
```c
dma[channel].csr &= ~DMA_ENABLE;             // Stop transfer
dma[channel].csr |= (DMA_COMPLETE | DMA_BUSEXC);  // Set flags
set_interrupt(interrupt, SET_INT);           // Notify software
```

**Recovery:**
1. Read CSR to check `DMA_BUSEXC` bit (0x10)
2. Handle error (log, abort, retry)
3. Write CSR with `DMA_RESET` (0x10) to clear flags

**Per-Channel:**
- **SCSI/MO:** `abort()` on alignment errors, stop+flag on bus errors
- **Ethernet:** Stop+flag only (no abort)
- **Sound:** No error checking (assumes valid buffers)

**Confidence:** 90% (emulator behavior; real hardware timing may differ)

**Source:** `dma.c:455-459`, `EMULATOR_DMA_DEEP_DIVE.md §6`

---

## Alignment Requirements

**Strict (SCSI, MO):**
- `next` must be % 4 == 0 (longword)
- `limit` must be % 16 == 0 (burst)
- Violation → fatal error

**Relaxed (Ethernet):**
- `next` and `limit` must be % 16 == 0
- BUT transfers happen **byte-by-byte** (unaligned packet data)

**None (Sound, Video):**
- Assumed longword-aligned by driver
- No runtime checks

**Confidence:** 95% (explicit enforcement in emulator)

**Source:** `dma.c:404-408`, `EMULATOR_DMA_DEEP_DIVE.md §7`

---

## Channel Interrupts (from Part 3)

**DMA Interrupts on NBIC:**
- INT_SCSI_DMA (IPL3, bit 11)
- INT_SND_OUT_DMA (IPL3, bit 13)
- INT_DISK_DMA (IPL3, bit 12)
- INT_SND_IN_DMA (IPL3, bit 14)
- INT_PRINTER_DMA (IPL3, bit 15)
- INT_SCC_DMA (IPL4, bit 16)
- INT_DSP_DMA (IPL4, bit 17)
- INT_EN_TX_DMA (IPL3, bit 9)
- INT_EN_RX_DMA (IPL3, bit 8)
- INT_VIDEO (IPL4, bit 18)
- INT_M2R_DMA (IPL3, bit 24)
- INT_R2M_DMA (IPL3, bit 23)

**Source:** Part 3 Chapter 13 (Complete Interrupt Mapping)

---

## DMA Config Registers (NeXTcube Only)

**Cube-Specific Registers:**
- `0x02020000` - DMA Mode register
- `0x02020004` - DMA Enable register

**ROM Usage (NeXTcube during SCSI init):**
```assembly
move.l  #0x80000000, 0x02020004  ; Bit 31 = Enable
move.l  #0x08000000, 0x02020000  ; Bit 27 = Mode
```

**NeXTstation:**
- Does NOT use these registers (different DMA architecture)
- ROM conditionally skips based on board config (3 = Station)

**Confidence:** 85% (register addresses 100%, bit meanings 80-85%)

**Source:** `DEEP_DIVE_MYSTERIES_RESOLVED.md`, `EMULATOR_DMA_DEEP_DIVE.md §10`

---

## Memory-to-Memory DMA

**Special Channels:** M2R (Memory→Register), R2M (Register→Memory)

**Activation:**
- Write both M2R and R2M CSR with `DMA_SETENABLE`
- Both channels must be enabled for transfer to proceed
- If `next == limit` on enable, channel disabled immediately (already done)

**Polling Pattern:**
- Emulator checks every 4 cycles: `CycInt_AddRelativeInterruptCycles(4, INTERRUPT_M2M_IO)`
- Real hardware may have different latency

**Confidence:** 85% (emulator timing approximate)

**Source:** `dma.c:223-229`, `dma.c:890-897`, `EMULATOR_DMA_DEEP_DIVE.md §9`

---

## Evidence Tiers for Part 4

**Tier 1 (95%+ confidence):**
- Ethernet flag-based descriptors
- 16-byte FIFO burst behavior
- Alignment requirements
- Sound "one ahead" pattern

**Tier 2 (85-94% confidence):**
- Ring buffer wrap-on-interrupt
- Chaining protocol
- Bus error recovery
- DMA config registers (addresses only)

**Tier 3 (70-84% confidence):**
- Interrupt timing (emulator immediate)
- M2M background polling (4 cycles)
- DMA config bit meanings

**Tier 4 (< 70% confidence):**
- Cache coherency protocol (not modeled)
- Bus arbitration latency (not modeled)
- NeXTstation DMA specifics (partial)

**Use explicit tier markers in chapter text!**

---

## Common Driver Patterns

**Single Transfer:**
1. Write `next` = buffer start
2. Write `limit` = buffer end
3. Write CSR = `DMA_SETENABLE` + direction (0x01 or 0x05)
4. Wait for interrupt (`DMA_COMPLETE` set)

**Chaining (Continuous):**
1. Write `start` = ring base
2. Write `stop` = ring end
3. Write `next` = current position
4. Write `limit` = first buffer end
5. Write CSR = `DMA_SETENABLE | DMA_SETSUPDATE` + direction (0x03 or 0x07)
6. On each interrupt:
   - Check `DMA_COMPLETE` → buffer done
   - Check `DMA_BUSEXC` → error occurred
   - Write CSR = `DMA_SETSUPDATE | DMA_CLRCOMPLETE` (0x0A) to continue

**Ethernet Packet:**
1. Write `next` = packet buffer
2. Write `limit = buffer_end | EN_EOP` (0x80000000)
3. Write CSR = `DMA_SETENABLE` + direction
4. Wait for interrupt when `limit & EN_EOP` reached

**Confidence:** 90% (derived from emulator implementation)

**Source:** `dma.c:185-236`, `EMULATOR_DMA_DEEP_DIVE.md §8`

---

## Writing Guidelines (from Part 3)

**Evidence Attribution:**
- Add "Evidence Attribution" section to each chapter
- Cite source with line numbers (e.g., `dma.c:796`)
- Mark confidence tier for each claim

**Narrative Techniques:**
- Forward-looking hooks (questions for next chapter)
- Backward-looking callbacks (building on previous)
- Story arc framing (purpose → mechanisms → concrete)
- Mystery and discovery framing where appropriate

**Gap Notation:**
- Transparent "What We Don't Know" sections
- Hardware validation procedures for future work
- Confidence levels clearly stated

**Quality Target:** 85% confidence (matches Part 3)

---

## Files to Reference

**Analysis:**
- `EMULATOR_DMA_DEEP_DIVE.md` - Complete implementation details
- `PART4_DMA_READINESS_ASSESSMENT.md` - Gap analysis and status
- `DEEP_DIVE_MYSTERIES_RESOLVED.md` - ROM DMA config
- `PART3_COMPLETION_SUMMARY.md` - Quality standards model

**Source Code:**
- `src/dma.c` - Core DMA (lines 40-390, 693-882)
- `src/ethernet.c` - Packet handling (lines 454-714)
- `src/snd.c` - Audio loop (lines 156-220)
- `src/includes/dma.h` - Channel definitions
- `src/includes/ethernet.h` - Buffer structures

**Part 3 Reference:**
- Chapter 13 (Interrupt Model) - DMA interrupt mapping
- Chapter 12 (Slot vs Board) - Board space usage for DMA
- Chapter 14 (Bus Errors) - DMA bus error handling

---

## Chapter Roadmap

**Chapter 16: DMA Philosophy** (95% ready)
- Mainframe DMA concepts
- NeXT's ISP architecture
- Why 12 channels + internal buffers
- Comparison to contemporary systems

**Chapter 17: DMA Engine Behavior** (90% ready)
- Register structure and CSR bits
- FIFO fill/drain protocol
- Transfer modes (single, chaining)
- Bus error handling

**Chapter 18: Descriptors and Ring Buffers** (95% ready)
- Ethernet flag-based "descriptors"
- Ring buffer wrap-on-interrupt
- Saved pointer mechanics
- Chaining continuation protocol

**Chapter 19: Bus Arbitration and Priority** (65% ready)
- M2M special case
- Priority among channels (gaps here)
- Cache coherency (gaps here)
- Board space vs slot space for DMA

**Chapter 20: NeXTcube vs NeXTstation** (90% ready)
- DMA config registers (Cube only)
- Architectural differences
- ROM conditional initialization
- Emulator bTurbo branches

---

**Quick Reference Complete** ✅

**Use this for fast fact lookup during writing!**

**For deep dives, refer to:** `EMULATOR_DMA_DEEP_DIVE.md`
