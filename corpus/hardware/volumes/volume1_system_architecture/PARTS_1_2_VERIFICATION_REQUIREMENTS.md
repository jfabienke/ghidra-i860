# Parts 1-2 Verification Requirements

**Date:** 2025-11-15
**Purpose:** Define what's needed to bring Parts 1-2 to the same publication standard as Parts 3-5
**Current Status:** Unverified (44,152 words exist, but not reviewed with Parts 3-5 rigor)

---

## Executive Summary

**What we have:**
- 10 chapters (Chapters 1-10) totaling 44,152 words
- Well-written, conceptually aligned content
- Good narrative flow and structure
- Written BEFORE Parts 3-5 deep dives (early in project)

**What we need:**
- Evidence attribution (ROM/emulator references like Parts 3-5)
- Confidence levels per chapter (like Parts 3-5: 85-100%)
- Cross-references to later parts (forward/backward links)
- Verification that content is still accurate after ROM/emulator discoveries
- Consistent terminology and narrative style

**Effort:** 20-40 hours across 3 passes
**Goal:** Raise Parts 1-2 to 85-90% average confidence (publication-ready)

---

## Current State Assessment

### Part 1: The NeXT Hardware Model (Chapters 1-3, 13,731 words)

| Chapter | Title | Words | Current State | Likely Issues |
|---------|-------|-------|---------------|---------------|
| **1** | Design Philosophy | 3,900 | Well-written, conceptual | Needs ROM examples for "channel-based I/O" claims |
| **2** | ASIC-as-HAL Concept | 5,904 | Solid framework | Needs connection to Part 3 discoveries (NBIC) |
| **3** | ROM in Hardware Abstraction | 3,927 | Good overview | Needs ROM v3.3 line numbers for initialization sequences |

**Strengths:**
- Strong narrative arc (mainframe techniques → NeXT philosophy)
- Clear contrast with contemporary designs (Sun, Apollo, SGI)
- Steve Jobs' vision properly contextualized

**Potential gaps:**
- Written before ROM v3.3 deep analysis (may lack specific evidence)
- May not reference Parts 3-5 discoveries (NBIC, DMA, interrupts)
- Confidence levels unknown (no explicit evidence attribution)

### Part 2: Global Memory Architecture (Chapters 4-10, 30,421 words)

| Chapter | Title | Words | Current State | Likely Issues |
|---------|-------|-------|---------------|---------------|
| **4** | Global Memory Architecture | 4,211 | Overview chapter | May overlap with Ch 7, needs de-duplication check |
| **5** | The NBIC Architecture | 4,224 | Overview only | Part 3 (Ch 11-15) is definitive, needs forward refs |
| **6** | 68K Addressing Model | 3,953 | Technical reference | Likely accurate, needs confidence rating |
| **7** | Global Memory Map | 5,833 | Detailed, well-structured | Needs ROM/emulator evidence for address ranges |
| **8** | Bank and SIMM Architecture | 4,634 | Memory organization | Needs ROM memory detection code references |
| **9** | Cacheability and Burst | 4,313 | Technical specs | Needs 68040 datasheet references |
| **10** | Device Windows Aliasing | 3,253 | Address decode | Needs connection to Ch 12 (Slot vs Board) |

**Strengths:**
- Comprehensive memory architecture coverage
- Good technical depth (Chapter 7 memory map is excellent)
- Clear explanations of burst modes, cacheability, aliasing

**Potential gaps:**
- Written before Part 3 (NBIC Deep Dive) — may have inconsistencies
- May not reflect ROM v3.3 memory detection algorithms
- Missing explicit evidence attribution (emulator source, ROM lines)
- No confidence levels marked

---

## Three-Pass Verification Plan

### Pass 1: Skim & Consistency Check (2-3 hours)

**Goal:** Ensure Parts 1-2 don't contradict Parts 3-5, identify major gaps

**Tasks:**
1. **Read all 10 chapters quickly** (skim mode, ~15-20 min per chapter)
2. **Flag contradictions** with Parts 3-5 discoveries
   - Example: If Ch 5 says NBIC has 8 slots, but Part 3 says 12, flag it
   - Example: If Ch 7 memory map differs from emulator implementation, flag it
3. **Assess structural alignment**
   - Does Part 1 properly introduce concepts developed in Parts 3-5?
   - Does Part 2 provide foundation for Part 3 (NBIC)?
4. **Identify major gaps**
   - Chapters with zero ROM/emulator references
   - Claims without evidence
   - Missing cross-references to later parts

**Deliverables:**
- **Gap report**: List of contradictions, missing evidence, structural issues
- **Priority ranking**: Which chapters need most work (high/medium/low)
- **Confidence estimate**: Rough guess at current confidence per chapter (50-80%?)

**Time:** 2-3 hours total

---

### Pass 2: Evidence Attribution (10-20 hours)

**Goal:** Add ROM/emulator references, mark confidence levels, document evidence quality

**Tasks per chapter:**

#### 1. Add ROM References (where applicable)

**Example transformation:**

**Before (Chapter 3, no evidence):**
```markdown
The ROM initializes SCSI controller during boot by writing to the
NCR 53C90 command register.
```

**After (with ROM evidence):**
```markdown
The ROM initializes the SCSI controller during boot by writing to the
NCR 53C90 command register (ROM v3.3 lines 10630-10704, 15-step sequence).

**Evidence:** ROM v3.3 `scsi_init()` function writes exactly one value
(0x88 = RESET | DMA) to the NCR 53C90 command register at 0x02012000,
then waits for the ASIC to complete initialization.

**Confidence:** 95% (directly observable in ROM disassembly)
```

**ROM sources to reference:**
- ROM v3.3 disassembly (line numbers)
- Memory detection sequences
- Device initialization (SCSI, Ethernet, Video)
- Interrupt setup (IPL configuration)
- DMA channel configuration

#### 2. Add Emulator References (where applicable)

**Example transformation:**

**Before (Chapter 7, no evidence):**
```markdown
DRAM base address is 0x00000000, with a maximum size of 128 MB.
```

**After (with emulator evidence):**
```markdown
DRAM base address is 0x00000000, with a maximum size of 128 MB
(hardware decodes bits [26:0] for DRAM region).

**Evidence:** Previous emulator (`src/memory.c:234-267`) maps DRAM at
base 0x00000000 with configurable size (8/16/32/64 MB based on SIMM
configuration register at 0x02000010).

**Cross-reference:** See Chapter 8 (Bank and SIMM Architecture) for
memory detection algorithm.

**Confidence:** 98% (emulator behavior + ROM detection code aligned)
```

**Emulator sources to reference:**
- `src/memory.c`: Memory map, DRAM sizing
- `src/nbic.c`: NBIC address decode, slot/board windowing
- `src/dma.c`: DMA channel configuration
- `src/sysReg.c`: MMIO register behavior
- `src/ethernet.c`, `src/scsi.c`: Device implementations

#### 3. Add Part 3-5 Cross-References

**Example transformation:**

**Before (Chapter 5, no forward reference):**
```markdown
The NBIC handles slot-based addressing for expansion cards.
```

**After (with forward reference):**
```markdown
The NBIC handles slot-based addressing for expansion cards.

**Note:** This chapter provides a high-level overview. For complete
NBIC architecture, see **Part 3: NBIC Deep Dive (Chapters 11-15)**,
particularly:
- Chapter 12: Slot-Space vs Board-Space Addressing (95% confidence)
- Chapter 13: Interrupt Model (100% confidence, GOLD STANDARD)
- Chapter 15: Address Decode Walkthroughs (100% confidence, GOLD STANDARD)

Part 3 provides complete NBIC decode logic, interrupt priority encoder
algorithm (Verilog + C), and 42 emulator call sites with zero conflicts.
```

**Forward reference targets:**
- Part 3 (NBIC): Reference from Part 2 chapters (especially Ch 4-5, 7, 10)
- Part 4 (DMA): Reference from Part 1 chapter 1 (mainframe techniques)
- Part 5 (Timing): Reference from Part 2 chapter 9 (burst modes)

#### 4. Mark Confidence Levels

**For each chapter, add confidence assessment:**

```markdown
**Confidence:** 🟢 **90%** - Complete ROM + emulator evidence, zero conflicts

OR

**Confidence:** 🟡 **85%** - Strong emulator evidence, minor gaps in ROM sequences

OR

**Confidence:** 🟡 **75%** - Conceptually sound, but lacks direct ROM/emulator validation
```

**Confidence criteria (based on Parts 3-5 standards):**
- **100% (GOLD STANDARD):** Behavior reproduced in emulator/ROM, zero conflicts, no gaps
- **95-99%:** Complete evidence, minor unknowns
- **90-94%:** Strong evidence, minor gaps documented
- **85-89%:** Good evidence, some logical inference
- **80-84%:** Solid conceptual foundation, some gaps
- **75-79%:** Reasonable but incomplete evidence
- **< 75%:** Significant gaps, needs more work

#### 5. Document Evidence Quality

**Add evidence quality assessment to each chapter:**

```markdown
**Evidence Base:**
- ROM v3.3 lines 10630-10704 (SCSI initialization)
- Previous emulator `src/scsi.c` lines 423-508
- NCR 53C90A Product Brief (timing specifications)
- 68040 User's Manual (cache behavior)

**Evidence Quality:**
- 15 ROM call sites analyzed
- 89 emulator lines validated
- 0 conflicts between ROM and emulator
- 2 minor gaps: DMA burst timing (inferred), selection timeout (typical value)
```

**Deliverables (per chapter):**
- ROM/emulator references added (line numbers, file paths)
- Confidence level marked (percentage + color)
- Evidence quality documented
- Forward/backward cross-references added
- Gaps and unknowns flagged

**Time:** 10-20 hours total (1-2 hours per chapter × 10 chapters)

---

### Pass 3: Narrative Enhancement (8-15 hours)

**Goal:** Integrate Parts 1-2 with Parts 3-5 for volume cohesion, apply narrative techniques

**Tasks:**

#### 1. Add Chapter Introductions/Conclusions

**Apply Part 3 narrative style to Part 1-2 chapters:**

**Example (Chapter 7 introduction enhancement):**

**Before:**
```markdown
# Chapter 7: Global Memory Map

The NeXT memory map reflects a sophisticated balance between competing
design goals...
```

**After:**
```markdown
# Chapter 7: Global Memory Map

**The Complete NeXT Address Space**

*Where every byte lives in the 4 GB address space, and why it's there*

---

**What This Chapter Covers:**

The NeXT memory map is not just a list of addresses — it's a **window
into NeXT's design philosophy**. Why does ROM start at 0x01000000, not
0x00000000? Why does VRAM occupy 16 MB when displays use only 2-4 MB?
Why do device windows alias every 256 bytes?

This chapter maps the complete 32-bit address space, explaining:
- Where each region lives and why
- How address decode works (sparse vs dense)
- Why certain regions are cached, others aren't
- How the NBIC enforces memory map boundaries

**Prerequisites:**
- Chapter 5: NBIC Architecture (slot vs board addressing)
- Chapter 6: 68K Addressing Model (burst alignment, cacheability)

**Cross-references:**
- Part 3, Chapter 12: Complete NBIC decode logic (95% confidence)
- Part 3, Chapter 14: Bus error semantics (85% confidence)

**Confidence:** 90% - Complete memory map validated in emulator + ROM

---
```

#### 2. Ensure Consistent Terminology

**Align Parts 1-2 terminology with Parts 3-5:**

| Inconsistent Term | Standard Term (Parts 3-5) | Where to Fix |
|-------------------|---------------------------|--------------|
| "ASIC controller" | "NBIC (NeXT Bus Interface Controller)" | Ch 2, 4, 5 |
| "Expansion slot" | "Slot space" vs "Board space" | Ch 5, 7, 10 |
| "DMA engine" | "DMA channel" (11 channels total) | Ch 1, 4 |
| "Interrupt priority" | "IPL (Interrupt Priority Level)" | Ch 5 |

**Create terminology index** (optional but helpful):
- NBIC = NeXT Bus Interface Controller
- IPL = Interrupt Priority Level (7 levels: IPL1-IPL7)
- DMA = Direct Memory Access (11 channels on NeXT)
- MMIO = Memory-Mapped I/O
- Slot space = 0x04000000-0x0FFFFFFF (NBIC-mediated)
- Board space = 0x10000000-0xFFFFFFFF (direct decode)

#### 3. Apply Narrative Arc Techniques

**From Part 3's success:**

**Technique 1: "Why this matters" sections**
- Add to Chapters 1-3 (philosophy chapters)
- Explain real-world impact of design decisions

**Technique 2: "Implementation notes" sections**
- Add to Chapters 6-10 (technical chapters)
- Provide emulator/FPGA guidance

**Technique 3: "Historical context" sections**
- Add to Chapter 1-2 (comparing to Sun, Apollo, SGI)
- Show evolution from 1988 to today

**Technique 4: Worked examples**
- Chapter 7: Memory map lookup walkthrough
- Chapter 10: Address aliasing calculation example

#### 4. Add Visual Consistency

**Ensure all chapters have:**
- Chapter title + subtitle (like Parts 3-5)
- Prerequisites section (if dependencies exist)
- Evidence base section (ROM/emulator sources)
- Confidence rating (percentage + explanation)
- Cross-references section (to other chapters)

**Deliverables:**
- Enhanced chapter intros/outros (narrative flow)
- Consistent terminology throughout Parts 1-2
- Visual/structural consistency with Parts 3-5
- Worked examples added where helpful
- Complete cross-reference network

**Time:** 8-15 hours total (~1 hour per chapter + overall polish)

---

## Evidence Sources Available

### ROM v3.3 Disassembly

**What's available:**
- Complete ROM v3.3 disassembly with line numbers
- Annotated initialization sequences
- Memory detection algorithms
- Device initialization (SCSI, Ethernet, Video, Sound)
- Interrupt configuration
- DMA channel setup

**Key ROM sections to reference:**

| ROM Function | Lines | Relevant Chapters |
|--------------|-------|-------------------|
| Memory detection | ~500-800 | Ch 8 (Bank and SIMM) |
| NBIC setup | ~1200-1500 | Ch 5 (NBIC Architecture) |
| SCSI initialization | 10630-10704 | Ch 3 (ROM abstraction) |
| DMA configuration | ~8000-8500 | Ch 4 (Global memory) |
| Interrupt setup | ~3200-3600 | Ch 5 (NBIC), forward ref to Part 3 Ch 13 |

### Previous Emulator Source

**What's available:**
- Complete emulator implementation (`src/` directory)
- Memory map implementation (`src/memory.c`)
- NBIC address decode (`src/nbic.c`)
- DMA engine (`src/dma.c`)
- Device implementations (SCSI, Ethernet, Video)
- Interrupt handling (`src/sysReg.c`)

**Key emulator files to reference:**

| File | Lines | Relevant Chapters |
|------|-------|-------------------|
| `src/memory.c` | ~1200 lines | Ch 7 (Memory map), Ch 8 (DRAM sizing) |
| `src/nbic.c` | ~800 lines | Ch 5 (NBIC), Ch 10 (Device windows) |
| `src/m68k_ops.c` | ~15000 lines | Ch 6 (68K addressing) |
| `src/dma.c` | ~600 lines | Ch 4 (Global memory), forward ref to Part 4 |
| `src/sysReg.c` | ~500 lines | Ch 5 (NBIC), forward ref to Part 3 Ch 13 |

### Published Datasheets

**What's available:**
- 68040 User's Manual (cache, burst modes, addressing)
- NCR 53C90A Product Brief (SCSI timing)
- MACE Ethernet Controller datasheet (if available)
- Memory controller specs (if available)

**Where to use:**
- Ch 6: 68K addressing → 68040 User's Manual
- Ch 9: Cacheability and burst → 68040 cache specifications
- Ch 3: ROM abstraction → NCR 53C90A (SCSI example)

### Parts 3-5 (Cross-Reference Targets)

**Available for forward references:**
- Part 3, Chapters 11-15: NBIC Deep Dive (85-100% confidence)
- Part 4, Chapters 16-20: DMA Architecture (92-97% confidence)
- Part 5, Chapters 21-24: Timing & Interrupts (90-100% confidence)

---

## Expected Outcomes After Verification

### Confidence Targets

**Part 1 (The NeXT Hardware Model):**

| Chapter | Target Confidence | Rationale |
|---------|-------------------|-----------|
| **1** | 85-90% | Conceptual framework validated by Parts 3-5 discoveries |
| **2** | 90-95% | ASIC-as-HAL proven by NBIC analysis (Part 3) |
| **3** | 90-95% | ROM abstraction validated by ROM v3.3 analysis |

**Part 1 Overall:** 88-93% weighted average

**Part 2 (Global Memory Architecture):**

| Chapter | Target Confidence | Rationale |
|---------|-------------------|-----------|
| **4** | 85-90% | Overview chapter, validated by emulator |
| **5** | 90-95% | NBIC overview, forward ref to Part 3 (100% GOLD STANDARD) |
| **6** | 95-98% | 68K addressing from 68040 manual (definitive) |
| **7** | 90-95% | Memory map validated in emulator + ROM |
| **8** | 90-95% | SIMM detection from ROM memory probe code |
| **9** | 95-98% | Cache/burst from 68040 manual (definitive) |
| **10** | 90-95% | Aliasing validated in emulator address decode |

**Part 2 Overall:** 90-95% weighted average

**Volume I Overall After Verification:**

| Metric | Current | After Verification | Change |
|--------|---------|-------------------|--------|
| **Total Words** | 141,574 | ~145,000 | +3,426 (evidence sections) |
| **Verified Content** | 86,405 (61%) | 130,557 (90%) | +44,152 words |
| **Weighted Confidence** | 90% (Parts 3-5 only) | 90% (all parts) | Maintained |
| **Publication Status** | Parts 3-5 ready | All parts ready | ✅ Complete |

---

## Verification Workflow

### Step-by-Step Process

**Week 1: Pass 1 (2-3 hours)**
1. Read Chapters 1-3 (Part 1), take notes
2. Read Chapters 4-10 (Part 2), take notes
3. Create gap report (contradictions, missing evidence)
4. Prioritize chapters (high/medium/low effort)

**Week 2-3: Pass 2 (10-20 hours)**
1. High-priority chapters first (likely Ch 5, 7, 8)
2. Add ROM/emulator references (1-2 hours per chapter)
3. Mark confidence levels
4. Document evidence quality
5. Add cross-references to Parts 3-5

**Week 4: Pass 3 (8-15 hours)**
1. Enhance chapter intros/conclusions
2. Ensure terminology consistency
3. Apply narrative techniques (worked examples, "why this matters")
4. Final polish (visual consistency, cross-reference network)

**Total Time:** 20-40 hours over 4 weeks (5-10 hours per week)

---

## Tools and Resources Needed

### Required

1. **ROM v3.3 disassembly** (already available)
   - Line-numbered disassembly
   - Annotated with function names
   - Cross-referenced to emulator

2. **Previous emulator source code** (already available)
   - `src/` directory with all implementation files
   - Comments and documentation
   - Git history (if available) for design decisions

3. **Parts 3-5 chapters** (already complete, 86,405 words)
   - For cross-referencing
   - For terminology consistency
   - For narrative style examples

### Helpful (Optional)

4. **68040 User's Manual** (public, available online)
   - For Chapter 6 (addressing modes)
   - For Chapter 9 (cache, burst modes)

5. **NCR 53C90A Product Brief** (already obtained)
   - For Chapter 3 (ROM abstraction example)

6. **NeXT Technical Documentation** (if available)
   - NeXT Developer Documentation
   - NeXT Hardware Reference (if exists)
   - For validating memory map, MMIO registers

---

## Success Criteria

**Parts 1-2 will be considered "verified" and "publication-ready" when:**

1. ✅ **Evidence attribution complete**
   - Every technical claim has ROM/emulator reference OR datasheet citation
   - Confidence level marked for each chapter (85-98% target range)
   - Evidence quality documented (X ROM lines, Y emulator lines, 0 conflicts)

2. ✅ **Cross-references complete**
   - Forward references to Parts 3-5 where applicable
   - Backward references from Parts 3-5 to Parts 1-2 (if needed)
   - Consistent terminology across all parts

3. ✅ **No contradictions**
   - Zero conflicts between Parts 1-2 and Parts 3-5
   - Memory map consistent with emulator implementation
   - NBIC architecture consistent with Part 3 deep dive
   - DMA architecture consistent with Part 4 analysis

4. ✅ **Narrative consistency**
   - Chapter intros/conclusions match Parts 3-5 style
   - Worked examples where helpful
   - "Why this matters" sections for key concepts
   - Visual/structural consistency

5. ✅ **Confidence targets met**
   - Part 1: 88-93% average (target: 90%)
   - Part 2: 90-95% average (target: 92%)
   - Volume I overall: 90% weighted average (maintained)

**When these criteria are met, Volume I can be considered publication-ready in its entirety (141,574+ words, 24 chapters, 90% confidence).**

---

## Next Steps

**To begin verification:**

1. **Decide priority**: Do you want to verify Parts 1-2 now, or focus on other work first?

2. **If yes, start with Pass 1** (2-3 hours):
   - Read all 10 chapters
   - Create gap report
   - Identify contradictions with Parts 3-5
   - Estimate current confidence per chapter

3. **If not now, document status**:
   - Parts 1-2 remain at "unverified" status
   - Can be verified later when time permits
   - Parts 3-5 remain publication-ready (86,405 words, 90% confidence)

**Recommendation:** Given that Parts 3-5 are already publication-ready at 90% confidence and represent 61% of Volume I, you could:
- **Option A:** Publish Parts 3-5 as "Volume I, Parts 3-5" (standalone, publication-ready now)
- **Option B:** Verify Parts 1-2 first (20-40 hours), then publish complete Volume I
- **Option C:** Defer Parts 1-2 verification, continue with other work (Parts 6-8, emulator, etc.)

**Question for you:** Which option sounds most useful?
