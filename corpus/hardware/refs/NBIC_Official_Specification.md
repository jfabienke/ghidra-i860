# NBIC Official Specification

**Source:** NeXT Computer, Inc. - "NextBus Interface Chip™ Specification"
**Date:** Unknown (circa 1988-1990, for 68030-based NeXTcube/NeXTstation)
**Extracted:** 2025-11-15
**Purpose:** Reference documentation for NBIC ASIC validation

---

## Document Overview

This document contains excerpts from the official NeXT NBIC specification, extracted to validate and enhance Volume I: System Architecture documentation. The NBIC (NextBus Interface Chip) is used in NeXTbus expansion boards to interface with the host system.

**Note:** This specification was written for the original 68030-based NeXTcube/NeXTstation systems. The NBIC chip is believed to be the same or highly compatible across NeXT hardware generations (68030 → 68040).

---

## Table of Contents (from Original Spec)

**Chapter 1: Overview**
- NBIC Features
- NextBus Interface
- Local Bus Interface
- NBIC and the NextBus
- NBIC and the Local Bus
- NBIC Registers
- Addressing the NBIC
- NBIC Transactions
- Implementation Notes

**Chapter 2: NBIC Functional Description**
- NBIC Functional Blocks
- NextBus Master/Local Slave
- Local Bus Clocks
- Local Master/NextBus Slave
- NBIC Timeout Logic
- Reset Logic
- NextBus Transactions
- NextBus Byte Ordering
- NextBus Single-Word Transactions
- NextBus Burst Transactions
- Local Bus Transactions
- Store and Forward Write Operations
- NBIC as Local Bus Master
- Transaction Types
- Transaction Termination
- NBIC as Local Bus Slave
- Transfers Not Supported by the NextBus

**Chapter 4: NBIC Registers**
- Five programmable registers
- Register locations and access modes

**Chapter 6: NBIC Transaction Timing**
- Timing diagrams with cycle counts

---

## 1. NBIC Registers

### 1.1 Register Overview (Page 4-1)

The NBIC contains **five programmable registers:**

1. **NBIC ID register**
2. **NBIC Control register**
3. **Configuration register**
4. **Interrupt register**
5. **Interrupt Mask register**

---

### 1.2 ID Register

**Location:** NextBus Slot Space at addresses **FsFFFFF0h to FsFFFFFCh** (Page 4-3, Figure 4-3)
- LSB at `FsFFFFFCh`
- Where `Fs` = slot-relative address (F = top nibble, s = slot ID)

**Access:**
- **Write:** Local bus master can write to this register (Page 4-3)
- **Read:** Any NextBus master can read over the NextBus (Page 4-3)

**Special Configuration:**
- If the ID register is located **off** the NBIC (external to chip), bit 23 in the Configuration register (`EXIDREGEN`) must be set to 1 (Page 4-4)

**Power-Up Requirement (Page 4-11):**
> "During the power on sequence, software must do the following:
> 1. Write a value to the **NBIC ID register** and set the **VALID bit**. This places a board ID value into the register. When the VALID bit is set, it indicates that the ID is now valid."

---

### 1.3 Control Register

**Location:** Address **0h** in the NBIC address space on the local bus (Page 4-1)

**Access:** Read/Write by devices on the local bus (Page 4-1)

**Bit Field Layout (Page 4-5, Figure 4-4):**

| Bits | Name | Description |
|------|------|-------------|
| 31-29 | Reserved | |
| 28 | **IGNSID0** | Ignore Slot ID 0. Controls how much NextBus address space a board uses. If set to 1, the board uses addresses for two slots (512 Mbytes). |
| 27 | **STFWD** | Store Forward. Control bit for Store and Forward write transactions. **Enabled (set to 1) at power up.** |
| 26 | **RMCOL** | Read Modify Cycle Collision. Used for 68030 RMC cycles. If set to 1, issues a Bus Error instead of a Retry error on RMC deadlock. |
| 25-0 | Reserved | |

**Power-Up State:** Control register bits are **set by software during power up** (Page 4-1)

**Optional Configuration (Page 4-11):**
> "If the store and forward write function should be disabled, set the **Store and Forward Write bit (27)** in the **NBIC Control register to 0**."

---

### 1.4 Configuration Register

**Access:** Read/Write by devices on the local bus (Page 4-1)

**Behavior:**
- **Latches** board location (slot ID) and mode selection at power up
- Values **do not change** during operation (Page 4-1)
- Set at power-up by pullups on the local bus; **non-programmable** (Page 4-6)

**Power-Up Latching (Page 4-11):**
> "When PON is enabled at power up, the values of **LAD bits 31 through 23 are latched into the NBIC Configuration register**. These bits contain the **slot ID (SID)** values, select the mode of operation, and tell whether the NBIC ID register is located in the NBIC chip or on the board."

**Bit Field Layout (Page 4-6, Figure 4-5):**

| Bits | Name | Description |
|------|------|-------------|
| 31-28 | **SID[31:28]** | Slot ID. Identifies the slot location of the board. Latched when PON is asserted. |
| 27 | **DISRMCERR** | Disable RMC Collision Error. Selects whether NBIC issues Retry or Bus Error on RMC deadlock. **Default value is 0**. |
| 26 | **SINTEN** | Slave Interrupt Enable. Controls `GSLAVE*/SINT*` signal usage. If 1, asserts `GINT*` when local `SINT*` is asserted. |
| 25 | **LBG/EXSEL** | Local Bus Grant/External Select. Selects between asserting the Local Bus Grant (`LBG`) or External Select (`EXSEL`) signal. |
| 24 | **SSDECODE** | Slot Space Decode. Enables or disables accesses to the board slot space (`FsOOOOOOh` to `FsFFFFE4h`). |
| 23 | **EXIDREGEN** | External ID Register Enable. Enables or disables the NBIC internal ID register logic. If 1, ID register access is passed to the local bus. |
| 22-0 | Reserved | |

---

### 1.5 Interrupt Register

**Location:** Read-only at address **FsFFFFFE8h** (Page 4-8)

**Function (Page 4-3):**
> "The Interrupt register merely holds the status of **one bit**, which is controlled by the **SINT\* signal** from board logic."

**Access:** Read-only by NextBus master (Page 4-3)

---

### 1.6 Interrupt Mask Register

**Location:** Read/Write at address **FsFFFFFECh** (Page 4-8)

**Function (Page 4-3, 4-8):**
- Used to **mask interrupts**
- When mask register value is 1 and NBIC asserts `GSLAVE*/SINT*` (and SINTEN is set), it generates `GINT*` on the NextBus

**Access:** Read and write by NextBus master (Page 4-3)

**Interrupt Logic (Page 4-9, Figure 4-7):**
- Incoming `SINT*` signal (from board logic) and incoming `GAD7*` signal (from other NBICs/boards) are OR-ed with the state of the Interrupt Mask Register to generate `GINT*`

---

## 2. Transaction Timing

### 2.1 NextBus Single-Word Read Transaction

**Source:** Page 6-1, Figure 6-1; Page 6-2 description

**Cycle-by-Cycle Breakdown:**

1. **Start Cycle (D(1) to S(1)):** One clock period
   - Master asserts `START*`
   - Master drives Address and `TM[1:0]*`

2. **Intermediate Stop (D(2) to S(2)):** One clock period
   - Master stops driving AD/TM lines
   - Master deasserts `START*`
   - Master waits for acknowledge

3. **Acknowledge Cycle (D(n) to S(n)):** Variable latency
   - Slave asserts `ACK*`
   - Slave places status on `TM[1:0]*`
   - Slave drives data onto `AD[31:0]*`

4. **Completion (D(n+1)):**
   - Slave stops driving data/status

**Total Minimum Cycles:** **3-4 clock periods** for a single-word read (Start + Stop + Acknowledge + Finish)

**At 12.5 MHz MCLK:** 3-4 cycles × 80ns/cycle = **240-320ns** minimum latency

---

### 2.2 NextBus Burst Read Transaction

**Source:** Page 6-2, Figure 6-2; Page 6-3 description

**NBIC Burst Limitation (Page 2-13):**
> "Although NextBus burst transfers can be 4, 8, 16, or 32 words, the **NBIC only supports four-word burst transfers**."

**Data Size (Page 2-13):**
> "In burst mode, the NBIC performs only **word transfers**."

**Cycle-by-Cycle Breakdown:**

1. **Start Cycle (D1 to S1):** One clock period
   - Master asserts `START*`
   - Master sets mode
   - Master asserts `DRQ*` (flow control)
   - Master sets address

2. **Data Cycles (Dn to Sn):** One cycle per word (4 cycles total)
   - Slave asserts `TMO*`
   - Slave drives data on `AD[31:0]*` every major clock cycle
   - Master asserts `DRQ*` to indicate it can receive four words

3. **Termination:** Acknowledge cycle
   - `ACK*` and status on `TM[1:0]*` may occur in cycle after last data word

**Total Cycles for 4-Word Burst:** Approximately **6 major clock cycles** minimum
- 1 (Start) + 4 (Data) + 1 (Acknowledge) = 6 cycles

**At 12.5 MHz MCLK:** 6 cycles × 80ns/cycle = **480ns** minimum for 4-word burst

**Alignment Requirement (Page 2-8):**
> "All burst transfers are aligned to begin on **even boundaries of the burst size**."

**Burst Size Encoding (Page 2-8):**
- Burst size encoded on `GAD[6:2]*` during NextBus start cycle

---

### 2.3 Bus Timeout

**Timeout Value (Page 2-5):**
> "If a NextBus transaction times out (**255 MCLK cycles without `GACK*`**), the NBIC issues a **Bus Timeout Error** and **asserts `GACK*` at cycle 256**."

**Calculated Timeout:**
- 255 cycles × 80ns/cycle (@ 12.5 MHz) = **20.4 microseconds**
- Error asserted at cycle 256

**Timeout Behavior:** NBIC asserts `GACK*` with error status after 256 cycles of waiting

---

## 3. Interrupt Architecture

### 3.1 Simple 1-Bit Design

**From Page 4-3:**
> "The Interrupt register merely holds the status of **one bit**, which is controlled by the **SINT\* signal** from board logic."

**Signal Flow:**
1. Local device asserts `SINT*` signal
2. `SINT*` updates Interrupt Register (1 bit)
3. If Interrupt Mask is enabled (unmasked), `GINT*` asserted on NextBus

**No Complex Vector Table:**
- NBIC does not contain priority encoding or interrupt vector table
- Single interrupt output: `GINT*` (Global Interrupt)

---

### 3.2 Inter-Board Interrupt Aggregation

**From Page 4-9, Figure 4-7:**

Interrupt logic shows:
- Incoming `SINT*` signal (from board logic)
- Incoming `GAD7*` signal (from other NBICs/boards)
- Both OR-ed together, gated by Interrupt Mask Register
- Result drives `GINT*` output to NextBus

**Configuration Control (Page 4-7):**
- **SINTEN** bit (Configuration Register bit 26): Controls `GSLAVE*/SINT*` signal usage
- If SINTEN = 1, asserts `GINT*` when local `SINT*` is asserted

---

### 3.3 Priority and Arbitration

**From specification:** The NBIC does not define IPL (Interrupt Priority Level) system or fixed priority encoding within the chip.

**Output Signal (Page 3-6, Table 3-1):**
- Sole interrupt output: **`GINT*`** (Global Interrupt)
- No IPL signals documented in NBIC spec

**Assertion Rule (Page 3-6):**
- If local bus asserts `SINT*` AND Interrupt Mask is enabled → `GINT*` asserted to NextBus

---

## 4. Memory Address Translation

### 4.1 NextBus Address Space Format

**From Page 1-7, Figure 1-8:**

The 32-bit NextBus address space is divided into **16 sections (slots)**, each allocated **256 Mbytes** of board address space.

**Slot Space:**
- Top 256 Mbytes of 4 Gbyte space divided into 16 sections for slot identification
- Board's slot ID (`s`) determines base address: **`sXXXXXXXh`**
- Each slot: 256 MB of address space

**Board Space:**
- Top 256 Mbytes further divided into sixteen sections for slot identification (Page 1-7)
- Each board allocated **16 Mbytes** at address **`FsXXXXXXh`**, where `s` = slot ID

---

### 4.2 Address Translation Rules

**Slot Space Access (NBIC as NextBus Slave):**
- NextBus address `sXXXXXXXh` (s = slot ID)
- NBIC translates to local board address
- NBIC routes transaction to device in slot `s`
- Top 4 bits select slot, remaining bits are local offset

**Board Space Access (NBIC is transparent):**
- NextBus address `FsXXXXXXXh` (s = slot ID)
- NBIC passes address **transparently** to local bus
- Local board devices decode their own addresses

**From Page 1-7:**
> "From the NextBus, the NBIC for each board is addressed through that board's slot space addresses."

---

### 4.3 Sample NextBus Slot Address Space

**From Figure 1-9 (Page 1-9):**

ID Register mapping within slot space:
- ID Register LSB: `FsFFFFFCh`
- ID Register MSB: `FsFFFFF0h`

**Implication:** For Slot Space access, NBIC uses top 4 bits (`s`) to select physical slot, remaining bits (`XXXXXXh`) as local address offset.

---

## 5. Bus Protocol

### 5.1 Transaction Types

**From Page 2-12, 2-15:**

NBIC supports:
- **NextBus Single-Word Transactions** (byte, halfword, word)
- **NextBus Burst Transactions** (4-word only)
- **Read-Modify-Write Transactions** (RMC cycles for 68030)

---

### 5.2 Store and Forward Write Operations

**From Page 2-5:**

**NextBus Master/Local Slave FIFO:**
- Can store addresses and data for **two transactions** (word or burst)
- During burst transfer, one transaction can contain **four words**
- Total buffer capacity: **up to eight words** (two 4-word bursts)

**From Page 2-6, Figure 2-2:**
- FIFO can hold "up to **two transactions**"
- Supports store-and-forward capability for efficient DMA-like transfers

**Control (Page 4-5):**
- **STFWD bit** (Control Register bit 27): Enabled (set to 1) at power up
- Software may disable by clearing STFWD bit

---

### 5.3 Slot Space vs Board Space Behavior

**Slot Space Access (Page 1-3, Figure 1-3):**
1. NextBus master initiates transaction
2. NBIC receives via **NextBus Slave Logic**
3. NBIC passes to **Local Bus Master Logic** to fetch/store data on local bus
4. Slower access, NBIC-mediated, timeout-enforced

**Board Space Access (Page 1-4, Figure 1-4):**
1. NextBus master initiates transaction
2. Address starts with Board ID (top 4 bits `FxxxxxxxH`)
3. NBIC passes address **directly** to local bus without slot decode
4. Local board decodes its own address
5. Faster access, NBIC is transparent

---

### 5.4 Burst Transaction Constraints

**4-Word Burst Limit (Page 2-13):**
> "Although NextBus burst transfers can be 4, 8, 16, or 32 words, the **NBIC only supports four-word burst transfers**."

**Word-Only Bursts (Page 2-13):**
> "In burst mode, the NBIC performs only **word transfers**."

**Alignment (Page 2-8):**
> "All burst transfers are aligned to begin on **even boundaries of the burst size**."

---

## 6. Error Handling

### 6.1 Bus Timeout

**Timeout Value (Page 2-5):**
- **255 MCLK cycles** without `GACK*`
- NBIC issues **Bus Timeout Error**
- NBIC asserts `GACK*` at **cycle 256**

**At 12.5 MHz:** 255 × 80ns = **20.4 microseconds** (error at cycle 256)

---

### 6.2 Error Termination Types

**From Page 3-10, Chapter 2:**

**NextBus Errors:**
- NBIC passes errors from local bus (`BERR*`) onto NextBus as `BERR*`

**Local Bus Termination:**
- **Normal Termination (32-bit):** Local slave asserts `STERM*` on last cycle (Page 3-10)
- **Exception Termination:** Local slave asserts `DSACK[1:0]*` (Page 3-9)
  - Used for size indication or misaligned transfer correction
  - `DSACK1*` indicates error for non-supported transfer type (Page 2-19)

---

### 6.3 RMC (Read-Modify-Write) Deadlock Handling

**From Page 4-9, 4-10:**

**Local Bus Error Types:**
1. **Retry** - for deadlock condition between two NextBus masters
2. **Bus Error** - for Bus timeout or Deadlock during RMC transaction

**Deadlock Handling:**

**Non-RMC Deadlock:**
- NBIC asserts `BERR*` and `HALT*` simultaneously
- Sends **Retry** to local master

**RMC Deadlock:**
- NBIC issues **Bus Error**
- Sets **RMCOL bit** (Control Register, bit 26) to 1
- Prevents 68030 from perpetuating deadlock by retrying RMC cycle

**NBIC Retry Behavior (Page 2-15):**
- If NBIC receives Retry termination when acting as local bus master
- **Does not attempt to retry operations**
- Generates NextBus error acknowledgement instead

---

## 7. Power-Up Sequence

**From Page 4-11:**

### 7.1 Hardware Initialization

> "When PON is enabled at power up, the values of **LAD bits 31 through 23 are latched into the NBIC Configuration register**."

**What Gets Latched:**
- Slot ID (SID) values
- Mode selection
- Whether NBIC ID register is located in NBIC chip or on board

---

### 7.2 Software Initialization

**Required Steps (Page 4-11):**

> "During the power on sequence, software must do the following:
>
> 1. Write a value to the **NBIC ID register** and set the **VALID bit**. This places a board ID value into the register. When the VALID bit is set, it indicates that the ID is now valid.
>
> 2. If the store and forward write function should be disabled, set the **Store and Forward Write bit (27)** in the **NBIC Control register to 0**."

---

### 7.3 Power-Up Default States

**Control Register (Page 4-1, 4-5):**
- STFWD bit (bit 27): **Enabled (set to 1) at power up**
- Other bits: Set by software during power up

**Configuration Register (Page 4-6):**
- Set at power-up by **pullups on local bus**
- Non-programmable, values do not change during operation
- DISRMCERR default: **0**

---

## 8. Additional Technical Details

### 8.1 Reset Logic

**From Page 2-6:**

**Reset Signals:**
- `GRESET*` - Global reset (NextBus-wide)
- `LRESET*` - Local reset (board-local)

**Signal Characteristics:**
- Both are **negative edge sensitive**

---

### 8.2 DMA and Bus Mastering

**NBIC Role:**
- Acts as **bridge** for DMA transfers, not a complete DMA controller
- Facilitates DMA by acting as Bus Master/Slave for NextBus
- Allows external devices (SCSI, Ethernet) to use bus

**NextBus Arbitration (Page 2-5):**
- NBIC arbitrates on behalf of local masters that want NextBus ownership
- Local bus arbitration determines which local master gets to drive NextBus

---

### 8.3 Memory Controller

**From Appendix A (Page A-1):**
- Memory controller functionality is implemented in **sample slave board** via PLE (Programmable Logic Element)
- Specific memory controller details are external to NBIC core specification
- Bank select and interleaving are **not** NBIC functions

---

## 9. Cross-Reference with Volume I Documentation

### 9.1 Verified Matches

| Topic | Volume I Chapter | Spec Page | Status |
|-------|-----------------|-----------|--------|
| Interrupt Register | Ch.13, Ch.23 | 4-3, 4-8 | ✅ 100% match |
| Interrupt Mask Register | Ch.23 | 4-8 | ✅ 100% match |
| Slot Space Addressing | Ch.12 | 1-7 | ✅ 100% match |
| Board Space Addressing | Ch.12 | 1-7 | ✅ 100% match |
| Address Decode Algorithm | Ch.15 | 1-7, 1-9 | ✅ 100% match |
| Bus Timeout Behavior | Ch.14 | 2-5 | ⚠️ Timing value needs correction (20.4µs, not 1-2µs) |

---

### 9.2 Critical Corrections Needed

**Bus Timeout Value:**
- **Volume I states:** "~1-2µs timeout"
- **Official spec:** 255 MCLK cycles = **20.4µs @ 12.5 MHz** (80ns/cycle)
- **Discrepancy:** Volume I value is ~10x too short
- **Action required:** Correct throughout Ch.14, Ch.15

---

### 9.3 Documentation Gaps

**Not documented in Volume I (missing from spec extraction so far):**
1. ID Register (FsFFFFF0h-FsFFFFFCh) and VALID bit requirement
2. Control Register (0h) complete bit fields
3. Configuration Register complete bit fields and LAD latching
4. Power-up initialization sequence (2 required software steps)
5. Store and Forward FIFO mechanism (2-transaction, 8-word buffer)
6. RMC deadlock handling (RMCOL bit, HALT* signal)
7. Inter-board interrupt aggregation (GAD7* signal, SINTEN behavior)

---

## 10. Additional Information Needed

To complete Volume I documentation, request these sections from official spec:

### Critical Priority
1. **Chapter 3:** Complete signal definitions (especially HALT*, GAD7*, GINT*)
2. **Chapter 5:** Arbitration protocol details
3. **Appendix:** Complete register reset values and bit field definitions

### High Priority
4. Store and Forward detailed operation
5. RMC (Read-Modify-Write) cycle complete specification
6. IGNSID0 behavior (512MB addressing mode)
7. EXIDREGEN behavior (external ID register mode)

### Medium Priority
8. SINTEN complete behavior (inter-board interrupts)
9. LBG/EXSEL signal usage
10. SSDECODE behavior (slot space decode enable/disable)

---

## Document History

- **2025-11-15:** Initial extraction from official NBIC specification
- **Source conversation:** User-provided spec excerpts covering Chapters 1, 2, 4, 6
- **Extracted by:** Claude Code analysis agent
- **Purpose:** Validate Volume I: System Architecture against official NeXT documentation

---

## Notes

1. This specification is for the **68030-based NeXTcube/NeXTstation** systems
2. NBIC chip is believed compatible across NeXT hardware generations (68030 → 68040)
3. Specification uses "Fs" notation for slot-relative addresses (F = top nibble, s = slot ID)
4. All timing calculations assume **12.5 MHz MCLK (80ns period)** per official specification
5. Some sections reference figures/diagrams not included in text extraction

---

## Terminology

- **MCLK:** Master clock (12.5 MHz on NextBus, 80ns period)
- **GAD[31:0]\*:** Global Address/Data bus (multiplexed)
- **GTM[1:0]\*:** Global Transfer Mode signals
- **GACK\*:** Global Acknowledge
- **GINT\*:** Global Interrupt
- **SINT\*:** Slave Interrupt (local board signal)
- **LAD[31:0]:** Local Address/Data bus
- **STERM\*:** Slave Termination
- **DSACK\*:** Data Size Acknowledge
- **BERR\*:** Bus Error
- **HALT\*:** Halt signal (for retry termination)
- **PON:** Power-On signal
- **RMC:** Read-Modify-Write Cycle (68030 atomic operation)
- **PLE:** Programmable Logic Element

All signals with "\*" suffix are active-low.
