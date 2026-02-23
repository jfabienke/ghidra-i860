# MACE Am79C940 Ethernet Controller - Hardware Specification

**Chip**: AMD Am79C940 MACE (Medium Access Control for Ethernet)
**Document Type**: Hardware reference and expected driver behavior
**Date**: 2025-01-13
**Source**: AMD datasheet + Linux/OpenBSD mace.h + NeXT hardware inference
**Confidence**: Hardware specs VERY HIGH (95%), NeXT-specific usage MEDIUM (60%, inferred)

---

## Executive Summary

The Am79C940 MACE is the Ethernet controller used in NeXTcube/NeXTstation systems. This document provides:

1. **Complete register map** (32 registers, offsets 0-31)
2. **Bit-level specifications** for each register
3. **Expected NeXTSTEP driver behavior** (inferred from hardware requirements)
4. **Verification checklist** for ROM disassembly analysis

**Key characteristics**:
- 8-bit register interface (byte-addressed)
- 128-byte receive FIFO, 136-byte transmit FIFO
- Hardware MAC address filtering + 64-bit multicast hash
- Big-endian mode support (BSWP bit) for 68k systems
- 10BASE-T and AUI transceiver support

---

## 1. Complete Register Map

### 1.1 Register Bank Overview

| Addr | Name | R/W | Function | NeXT Usage |
|------|------|-----|----------|------------|
| 0 | RCVFIFO | R | Receive data FIFO | ✅ Essential |
| 1 | XMTFIFO | W | Transmit data FIFO | ✅ Essential |
| 2 | XMTFC | R/W | Tx frame control | ✅ Essential |
| 3 | XMTFS | R | Tx frame status | ✅ Essential |
| 4 | XMTRC | R | Tx retry count | ✅ Likely |
| 5 | RCVFC | R/W | Rx frame control | ✅ Essential |
| 6 | RCVFS | R | Rx frame status (+len) | ✅ Essential |
| 7 | FIFOFC | R | FIFO frame count | ✅ Essential |
| 8 | IR | R/C | Interrupt flags | ✅ Essential |
| 9 | IMR | R/W | Interrupt mask | ✅ Essential |
| 10 | PR | R | Poll / FIFO request | ✅ Essential |
| 11 | BIUCC | R/W | Bus interface config | ✅ Essential |
| 12 | FIFOCC | R/W | FIFO config (watermarks) | ✅ Essential |
| 13 | MACCC | R/W | MAC config | ✅ Essential |
| 14 | PLSCC | R/W | Physical signalling cfg | ✅ Essential |
| 15 | PHYCC | R/W | PHY status / config | ✅ Likely |
| 16 | CHIPID_LO | R | Chip ID low byte | ⚠️ Optional |
| 17 | CHIPID_HI | R | Chip ID high byte | ⚠️ Optional |
| 18 | IAC | R/W | Internal addr control | ✅ Essential |
| 19 | REG19 | - | Reserved/test | ❌ Unused |
| 20 | LADRF | R/W | Logical addr filter (8B) | ✅ Likely |
| 21 | PADR | R/W | Physical addr (6B) | ✅ Essential |
| 22 | REG22 | - | Reserved/test | ❌ Unused |
| 23 | REG23 | - | Reserved/test | ❌ Unused |
| 24 | MPC | R/C | Missed packet count | ✅ Likely |
| 25 | REG25 | - | Reserved/test | ❌ Unused |
| 26 | RNTPCR | R/C | Runt packet count | ⚠️ Optional |
| 27 | RCVCC | R/C | Rx collision count | ⚠️ Optional |
| 28 | REG28 | - | Reserved/test | ❌ Unused |
| 29 | UTR | R/W | User test / loopback | ⚠️ Test only |
| 30 | REG30 | - | Reserved | ❌ Unused |
| 31 | REG31 | - | Reserved | ❌ Unused |

**Legend**:
- ✅ Essential: Must be used for normal operation
- ✅ Likely: Probably used for stats/error handling
- ⚠️ Optional: May or may not be used
- ❌ Unused: Reserved registers, not touched in production

---

## 2. Data Path Registers

### 2.1 RCVFIFO (Register 0) - Receive FIFO

**Access**: Read-only
**Width**: 8 bits
**FIFO Size**: 128 bytes

**Function**: Sequential byte window into receive FIFO

**NeXTSTEP Expected Usage**:
```c
// Wait for data ready
while (!(mace_read(PR) & RDTREQ))
    ; // Poll or interrupt-driven

// Read frame length from RCVFS
frame_len = mace_read(RCVFS) & 0x0FFF;

// Drain FIFO
for (i = 0; i < frame_len; i++) {
    buffer[i] = mace_read(RCVFIFO);
}
```

**Key Points**:
- Must check `PR.RDTREQ` before reading to avoid FIFO underrun
- Byte count comes from `RCVFS` low 12 bits
- Sequential reads automatically advance FIFO pointer

---

### 2.2 XMTFIFO (Register 1) - Transmit FIFO

**Access**: Write-only
**Width**: 8 bits
**FIFO Size**: 136 bytes (max Ethernet frame + overhead)

**Function**: Sequential byte window into transmit FIFO

**NeXTSTEP Expected Usage**:
```c
// Configure frame control (auto-pad, auto-FCS)
mace_write(XMTFC, AUTO_PAD_XMIT);

// Wait for FIFO space
while (!(mace_read(PR) & TDTREQ))
    ; // Poll or interrupt-driven

// Write frame data
for (i = 0; i < frame_len; i++) {
    mace_write(XMTFIFO, frame_buffer[i]);
}

// Last write triggers transmission (XMTFC latched)
```

**Key Points**:
- Check `PR.TDTREQ` to ensure FIFO has space
- `XMTFC` settings are latched when last byte is written
- Hardware appends FCS unless `XMTFC.DXMTFCS = 1`

---

## 3. Frame Control/Status Registers

### 3.1 XMTFC (Register 2) - Transmit Frame Control

**Access**: Read/Write
**Width**: 8 bits

**Bit Map**:
```
Bit 7: DRTRY      - Don't retry on collision (1=disable retry)
Bit 6: Reserved
Bit 5: Reserved
Bit 4: Reserved
Bit 3: DXMTFCS    - Disable auto FCS append (1=no FCS)
Bit 2: Reserved
Bit 1: Reserved
Bit 0: AUTO_PAD_XMIT - Auto pad short frames (1=enable)
```

**NeXTSTEP Expected Configuration**:
- `DRTRY = 0` (normal retry behavior, up to 16 attempts)
- `DXMTFCS = 0` (hardware appends 32-bit CRC)
- `AUTO_PAD_XMIT = 1` (pad frames < 60 bytes to minimum length)

**Typical Value**: `0x01` (auto-pad enabled, hardware FCS)

---

### 3.2 XMTFS (Register 3) - Transmit Frame Status

**Access**: Read-only (valid when `PR.XMTSV = 1`)
**Width**: 8 bits

**Bit Map**:
```
Bit 7: XMTSV   - Status valid (must check PR.XMTSV first)
Bit 6: UFLO    - Underflow (FIFO starved during transmission)
Bit 5: LCOL    - Late collision (after 512 bits)
Bit 4: MORE    - More than 1 retry needed
Bit 3: ONE     - Exactly 1 retry needed
Bit 2: DEFER   - Transmission deferred (carrier sensed)
Bit 1: LCAR    - Loss of carrier during transmission
Bit 0: RTRY    - Retry limit exceeded (16 attempts)
```

**NeXTSTEP Expected Usage**:
```c
if (mace_read(PR) & XMTSV) {
    uint8_t status = mace_read(XMTFS);

    // Fatal errors - increment output errors
    if (status & (RTRY | LCOL | LCAR | UFLO)) {
        ifp->if_oerrors++;
        // May need to reset transmitter
    }

    // Statistics only
    if (status & (DEFER | MORE | ONE)) {
        // Update collision counters
    }
}
```

---

### 3.3 XMTRC (Register 4) - Transmit Retry Count

**Access**: Read-only
**Width**: 8 bits

**Bit Map**:
```
Bit 7: EXDEF   - Excessive deferral (carrier busy for >6ms)
Bits 6-4: Reserved
Bits 3-0: Retry count (0-15, or 16 if XMTFS.RTRY set)
```

**NeXTSTEP Expected Usage**:
- Read after checking `PR.XMTSV` and `XMTFS`
- Accumulate for collision statistics (`netstat -i` output)
- `EXDEF` may indicate network congestion

---

### 3.4 RCVFC (Register 5) - Receive Frame Control

**Access**: Read/Write
**Width**: 8 bits

**Bit Map**:
```
Bit 7: Reserved
Bit 6: Reserved
Bit 5: Reserved
Bit 4: Reserved
Bit 3: LLRCV   - Low-latency receive (early DMA trigger)
Bit 2: M_RBAR  - Multipurpose pin function
Bit 1: Reserved
Bit 0: AUTO_STRIP_RCV - Auto strip pad/FCS (1=strip)
```

**NeXTSTEP Expected Configuration**:
- `AUTO_STRIP_RCV = 1` (strip FCS, deliver only payload to driver)
- `LLRCV = ?` (depends on DMA vs PIO mode, unknown for NeXT)

**Typical Value**: `0x01` (auto-strip enabled)

---

### 3.5 RCVFS (Register 6) - Receive Frame Status

**Access**: Read-only (16-bit word, read as 2 bytes)
**Width**: 16 bits

**Bit Map**:
```
Bit 15: OFLO   - FIFO overflow (packet dropped)
Bit 14: CLSN   - Collision during reception
Bit 13: FRAM   - Framing error (bad length/alignment)
Bit 12: FCS    - FCS error (bad CRC)
Bits 11-0: Frame length in bytes (0-4095)
```

**NeXTSTEP Expected Usage**:
```c
uint16_t rcvfs = mace_read_word(RCVFS); // 2-byte read

// Check for errors
if (rcvfs & (OFLO | CLSN | FRAM | FCS)) {
    ifp->if_ierrors++;
    // Discard frame, don't read from FIFO
    return;
}

// Extract length
uint16_t len = rcvfs & 0x0FFF;

// Read frame from RCVFIFO (len bytes)
```

**Key Points**:
- Must read before draining RCVFIFO
- Length includes Ethernet header (14 bytes) + payload
- Length does NOT include FCS if `RCVFC.AUTO_STRIP_RCV = 1`

---

### 3.6 FIFOFC (Register 7) - FIFO Frame Count

**Access**: Read-only
**Width**: 8 bits

**Bit Map**:
```
Bits 7-4: XMTFC - Transmit frames queued (0-2)
Bits 3-0: RCVFC - Receive frames queued (0-3)
```

**NeXTSTEP Expected Usage**:
```c
uint8_t fifofc = mace_read(FIFOFC);
uint8_t rx_frames = fifofc & 0x0F;

// Service all pending receive frames
while (rx_frames > 0) {
    process_rx_frame();
    rx_frames = mace_read(FIFOFC) & 0x0F;
}
```

---

## 4. Interrupt and Poll Registers

### 4.1 IR (Register 8) - Interrupt Register

**Access**: Read-to-clear
**Width**: 8 bits

**Bit Map**:
```
Bit 7: JABBER  - Jabber detected (transmitting too long)
Bit 6: BABBLE  - Babble detected (frame > max length)
Bit 5: CERR    - SQE test error (collision detection)
Bit 4: RCVCCO  - Receive collision counter overflow
Bit 3: RNTPCO  - Runt packet counter overflow
Bit 2: MPCO    - Missed packet counter overflow
Bit 1: RCVINT  - Receive interrupt (frame available)
Bit 0: XMTINT  - Transmit interrupt (frame sent)
```

**NeXTSTEP Expected Usage**:
```c
void mace_interrupt(void) {
    uint8_t ir = mace_read(IR); // Read clears flags

    if (ir & RCVINT) {
        // Service receive FIFO
        mace_rx_service();
    }

    if (ir & XMTINT) {
        // May be masked; if enabled, handle Tx completion
        mace_tx_complete();
    }

    // Error conditions
    if (ir & (JABBER | BABBLE | CERR)) {
        // Log error, may need reset
    }

    // Counter overflows
    if (ir & (MPCO | RNTPCO | RCVCCO)) {
        // Read and accumulate counters
        stats.missed_packets += mace_read(MPC);
        stats.runt_packets += mace_read(RNTPCR);
        stats.rx_collisions += mace_read(RCVCC);
    }
}
```

**Critical**: Reading `IR` clears the bits; must save value before processing.

---

### 4.2 IMR (Register 9) - Interrupt Mask Register

**Access**: Read/Write
**Width**: 8 bits
**Layout**: Same as `IR` (bit 7-0)

**Bit Values**:
- `1` = Mask (disable) this interrupt
- `0` = Unmask (enable) this interrupt

**NeXTSTEP Expected Configuration**:
```
JABBER  = 0  (unmask, want to know about jabber)
BABBLE  = 0  (unmask, want to know about babble)
CERR    = 0  (unmask, SQE test errors)
RCVCCO  = 0  (unmask, counter overflows)
RNTPCO  = 0  (unmask, counter overflows)
MPCO    = 0  (unmask, counter overflows)
RCVINT  = 0  (unmask, ESSENTIAL for receive)
XMTINT  = ?  (may be masked if using polling)
```

**Typical Value**: `0x01` (mask only XMTINT if polling Tx status)

---

### 4.3 PR (Register 10) - Poll Register

**Access**: Read-only
**Width**: 8 bits

**Bit Map**:
```
Bit 7: XMTSV   - Transmit status valid (XMTFS/XMTRC ready)
Bit 6: TDTREQ  - Transmit data transfer request (FIFO has space)
Bit 5: RDTREQ  - Receive data transfer request (FIFO has data)
Bits 4-0: Reserved
```

**NeXTSTEP Expected Usage**:
```c
// Before reading Tx status
if (mace_read(PR) & XMTSV) {
    status = mace_read(XMTFS);
    retries = mace_read(XMTRC);
}

// Before writing to Tx FIFO
while (!(mace_read(PR) & TDTREQ)) {
    // Wait for space or yield
}

// Before reading from Rx FIFO
if (mace_read(PR) & RDTREQ) {
    // Data available, drain FIFO
}
```

---

## 5. Bus and FIFO Configuration

### 5.1 BIUCC (Register 11) - Bus Interface Unit Config

**Access**: Read/Write
**Width**: 8 bits

**Bit Map**:
```
Bit 7: BSWP    - Byte swap enable (1=big-endian)
Bit 6: SWRST   - Software reset (1=reset chip)
Bits 5-4: XMTSP[1:0] - Transmit start point
          00 = 4 bytes
          01 = 16 bytes
          10 = 64 bytes
          11 = 112 bytes
Bits 3-0: Reserved
```

**NeXTSTEP Expected Configuration**:
- `BSWP = 1` (ESSENTIAL: 68k/68040 is big-endian)
- `SWRST = 1` (during init), then `= 0` (normal operation)
- `XMTSP = 01` or `10` (16 or 64 bytes, conservative for system latency)

**Typical Init Sequence**:
```c
// Reset chip
mace_write(BIUCC, 0x40); // SWRST=1
delay(10ms);

// Configure for big-endian, 64-byte Tx threshold
mace_write(BIUCC, 0xA0); // BSWP=1, XMTSP=10
```

---

### 5.2 FIFOCC (Register 12) - FIFO Config Control

**Access**: Read/Write
**Width**: 8 bits

**Bit Map**:
```
Bit 7: XMTBRST - Transmit burst mode enable
Bit 6: XMTFWU  - Update Tx FIFO watermark (write 1 to load)
Bits 5-4: XMTFW[1:0] - Tx watermark
          00 = 8 words free
          01 = 16 words free
          10 = 32 words free
          11 = Reserved
Bit 3: RCVBRST - Receive burst mode enable
Bit 2: RCVFWU  - Update Rx FIFO watermark (write 1 to load)
Bits 1-0: RCVFW[1:0] - Rx watermark
          00 = 16 bytes available
          01 = 32 bytes available
          10 = 64 bytes available
          11 = Reserved
```

**NeXTSTEP Expected Configuration**:
```c
// Configure Rx: 32-byte watermark, no burst
// Configure Tx: 16-word watermark, no burst
uint8_t fifocc = 0x44; // XMTFWU=1, XMTFW=01, RCVFWU=1, RCVFW=01
mace_write(FIFOCC, fifocc);

// Or with burst mode (if NeXT memory bus supports it)
uint8_t fifocc = 0xCC; // XMTBRST=1, RCVBRST=1, watermarks 01
mace_write(FIFOCC, fifocc);
```

**Note**: Burst mode depends on NeXT's custom memory controller; may or may not be used.

---

## 6. MAC and PHY Configuration

### 6.1 MACCC (Register 13) - MAC Config Control

**Access**: Read/Write
**Width**: 8 bits

**Bit Map**:
```
Bit 7: PROM    - Promiscuous mode (1=receive all)
Bit 6: DXMT2PD - Disable two-part deferral
Bit 5: EMBA    - Enable modified backoff algorithm
Bit 4: Reserved
Bit 3: DRCVPA  - Disable receive of physical address (1=ignore own MAC)
Bit 2: DRCVBC  - Disable receive of broadcast (1=ignore broadcast)
Bit 1: ENXMT   - Enable transmitter (1=Tx on)
Bit 0: ENRCV   - Enable receiver (1=Rx on)
```

**NeXTSTEP Expected Configuration**:

**Normal Operation**:
```c
// Enable Tx/Rx, accept own MAC and broadcasts
mace_write(MACCC, 0x03); // ENXMT=1, ENRCV=1
```

**Promiscuous Mode** (tcpdump, packet capture):
```c
// Enable Tx/Rx, promiscuous
mace_write(MACCC, 0x83); // PROM=1, ENXMT=1, ENRCV=1
```

**Disable Broadcasts** (rare, maybe for security):
```c
// Enable Tx/Rx, ignore broadcasts
mace_write(MACCC, 0x07); // DRCVBC=1, ENXMT=1, ENRCV=1
```

---

### 6.2 PLSCC (Register 14) - Physical Layer Signalling Config

**Access**: Read/Write
**Width**: 8 bits

**Bit Map**:
```
Bit 7: XMTSEL  - Transmit idle level select
Bits 6-5: PORTSEL[1:0] - Port select
          00 = AUI (Attachment Unit Interface)
          01 = 10BASE-T (twisted pair)
          10 = DAI (reserved)
          11 = GPSI (general purpose serial)
Bit 4: ENPLSIO - Enable PLS I/O pins
Bits 3-0: Reserved
```

**NeXTSTEP Expected Configuration**:

**NeXTcube with onboard RJ-45**:
```c
// Select 10BASE-T
mace_write(PLSCC, 0x20); // PORTSEL=01
```

**NeXTcube with external AUI transceiver**:
```c
// Select AUI
mace_write(PLSCC, 0x00); // PORTSEL=00
```

**With link LEDs** (if board has them wired):
```c
// 10BASE-T + enable PLS I/O
mace_write(PLSCC, 0x30); // ENPLSIO=1, PORTSEL=01
```

---

### 6.3 PHYCC (Register 15) - PHY Config/Status

**Access**: Read/Write
**Width**: 8 bits

**Bit Map**:
```
Bit 7: LNKFL   - Link fail (1=no link, read-only)
Bit 6: DLNKTST - Disable link test (1=disable)
Bit 5: REVPOL  - Polarity reversed (read-only)
Bit 4: DAPC    - Disable auto polarity correction (1=disable)
Bit 3: LRT     - Low receive threshold (1=lower sensitivity)
Bit 2: ASEL    - Auto port select (1=auto choose AUI/10T)
Bit 1: AWAKE   - PHY awake (power management)
Bit 0: RWAKE   - Remote wake (power management)
```

**NeXTSTEP Expected Usage**:

**Check Link Status**:
```c
if (mace_read(PHYCC) & LNKFL) {
    // Link down
    ifp->if_flags &= ~IFF_RUNNING;
} else {
    // Link up
    ifp->if_flags |= IFF_RUNNING;
}
```

**Auto Port Select** (if board supports both AUI and 10BASE-T):
```c
// Enable auto-select, leave link test enabled
mace_write(PHYCC, 0x04); // ASEL=1
```

**Fixed 10BASE-T** (most likely for NeXT):
```c
// Use PLSCC.PORTSEL instead, leave ASEL=0
mace_write(PHYCC, 0x00);
```

---

## 7. Addressing and Filtering

### 7.1 CHIPID_LO / CHIPID_HI (Registers 16-17)

**Access**: Read-only
**Width**: 8 bits each (16 bits total)

**Function**: Fixed silicon chip ID (e.g., `0x4940` for Am79C940)

**NeXTSTEP Expected Usage**:
```c
// Optional probe-time sanity check
uint16_t chip_id = (mace_read(CHIPID_HI) << 8) | mace_read(CHIPID_LO);
if (chip_id != 0x4940) {
    printf("MACE: unexpected chip ID 0x%04x\n", chip_id);
}
```

**Likely**: NeXTSTEP ignores this and relies on machine config tables.

---

### 7.2 IAC (Register 18) - Internal Address Control

**Access**: Read/Write
**Width**: 8 bits

**Bit Map**:
```
Bit 7: ADDRCHG - Address change (write 1 to commit)
Bit 6: Reserved
Bit 5: Reserved
Bit 4: PHYADDR - Select physical address (1=access PADR)
Bit 3: Reserved
Bit 2: LOGADDR - Select logical address (1=access LADRF)
Bit 1: Reserved
Bit 0: Reserved
```

**NeXTSTEP Expected Usage**:

**Set MAC Address**:
```c
// 1. Select physical address
mace_write(IAC, 0x10); // PHYADDR=1

// 2. Write 6 bytes to PADR (auto-increments)
for (i = 0; i < 6; i++) {
    mace_write(PADR, mac_addr[i]);
}

// 3. Commit
mace_write(IAC, 0x90); // ADDRCHG=1, PHYADDR=1
```

**Set Multicast Filter**:
```c
// 1. Select logical address
mace_write(IAC, 0x04); // LOGADDR=1

// 2. Write 8 bytes to LADRF
for (i = 0; i < 8; i++) {
    mace_write(LADRF, hash_mask[i]);
}

// 3. Commit
mace_write(IAC, 0x84); // ADDRCHG=1, LOGADDR=1
```

---

### 7.3 LADRF (Register 20) - Logical Address Filter

**Access**: Read/Write (8-byte register)
**Width**: 64 bits (8 bytes)

**Function**: 64-bit hash table for multicast address filtering

**NeXTSTEP Expected Usage**:
```c
// Compute CRC-based hash for multicast addresses
uint8_t ladrf[8] = {0};

for (each multicast address in list) {
    uint32_crc = ether_crc32(addr, 6);
    uint8_t hash = (crc >> 26) & 0x3F; // Top 6 bits
    ladrf[hash / 8] |= (1 << (hash % 8));
}

// Program via IAC (see section 7.2)
```

**All Multicast Mode**:
```c
// Accept all multicasts
uint8_t ladrf[8] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
```

---

### 7.4 PADR (Register 21) - Physical Address

**Access**: Read/Write (6-byte register)
**Width**: 48 bits (6 bytes)

**Function**: Station MAC address (e.g., `08:00:07:xx:xx:xx` for NeXT)

**NeXTSTEP Expected Usage**:
```c
// Read MAC from NVRAM/PROM
uint8_t mac[6];
read_mac_from_nvram(mac);

// Program via IAC (see section 7.2)
mace_write(IAC, 0x10); // PHYADDR=1
for (i = 0; i < 6; i++) {
    mace_write(PADR, mac[i]);
}
mace_write(IAC, 0x90); // ADDRCHG=1
```

---

## 8. Counters and Diagnostics

### 8.1 MPC (Register 24) - Missed Packet Count

**Access**: Read-to-clear
**Width**: 8 bits
**Range**: 0-255 (wraps)

**Function**: Counts packets dropped due to FIFO overflow / buffer limits

**NeXTSTEP Expected Usage**:
```c
// Periodically or on MPCO interrupt
uint8_t missed = mace_read(MPC); // Read clears counter
ifp->if_ierrors += missed;
stats.rx_missed += missed;
```

---

### 8.2 RNTPCR (Register 26) - Runt Packet Count

**Access**: Read-to-clear
**Width**: 8 bits

**Function**: Counts packets shorter than minimum Ethernet length (< 60 bytes)

**NeXTSTEP Expected Usage**:
```c
uint8_t runts = mace_read(RNTPCR);
stats.rx_runts += runts;
// May indicate cabling issues or half-duplex problems
```

---

### 8.3 RCVCC (Register 27) - Receive Collision Count

**Access**: Read-to-clear
**Width**: 8 bits

**Function**: Counts collisions during reception (late collisions, etc.)

**NeXTSTEP Expected Usage**:
```c
uint8_t rx_colls = mace_read(RCVCC);
stats.rx_collisions += rx_colls;
```

---

### 8.4 UTR (Register 29) - User Test Register

**Access**: Read/Write
**Width**: 8 bits

**Bit Map**:
```
Bit 7: Reserved
Bit 6: Reserved
Bits 5-4: LOOP[1:0] - Loopback mode
          00 = No loopback (normal)
          01 = External loopback (via transceiver)
          10 = Internal loopback (MAC level)
          11 = Reserved
Bit 3: RCVFCSE - Receive FCS enable (1=include FCS in frame)
Bit 2: Reserved
Bit 1: FCOLL  - Force collision (1=force collision on Tx)
Bit 0: RPAC   - Receive runt packets (1=accept runts)
```

**NeXTSTEP Expected Usage**:

**Normal Operation**:
```c
mace_write(UTR, 0x00); // No loopback, strip FCS, reject runts
```

**Self-Test / Loopback**:
```c
// Internal loopback for POST diagnostics
mace_write(UTR, 0x20); // LOOP=10 (internal)

// Send test packet, verify reception
// ...

// Restore normal mode
mace_write(UTR, 0x00);
```

**Packet Capture with FCS** (speculative):
```c
// For tcpdump/wireshark to see FCS
mace_write(UTR, 0x08); // RCVFCSE=1
```

---

## 9. Typical Initialization Sequence

Based on hardware requirements, NeXTSTEP likely follows this initialization flow:

```c
void mace_init(struct mace_softc *sc) {
    uint8_t mac[6];

    // 1. Software reset
    mace_write(BIUCC, 0x40);        // SWRST=1
    delay_ms(10);

    // 2. Configure bus interface (big-endian, 64-byte Tx threshold)
    mace_write(BIUCC, 0xA0);        // BSWP=1, XMTSP=10

    // 3. Configure FIFO watermarks (32-byte Rx, 16-word Tx)
    mace_write(FIFOCC, 0x44);       // RCVFW=01, XMTFW=01, update both

    // 4. Set MAC address
    read_mac_from_nvram(mac);
    mace_write(IAC, 0x10);          // PHYADDR=1
    for (i = 0; i < 6; i++)
        mace_write(PADR, mac[i]);
    mace_write(IAC, 0x90);          // ADDRCHG=1, PHYADDR=1

    // 5. Clear multicast filter (unicast + broadcast only)
    mace_write(IAC, 0x04);          // LOGADDR=1
    for (i = 0; i < 8; i++)
        mace_write(LADRF, 0x00);
    mace_write(IAC, 0x84);          // ADDRCHG=1, LOGADDR=1

    // 6. Configure frame control
    mace_write(XMTFC, 0x01);        // AUTO_PAD_XMIT=1
    mace_write(RCVFC, 0x01);        // AUTO_STRIP_RCV=1

    // 7. Configure PHY (10BASE-T, no auto-select)
    mace_write(PLSCC, 0x20);        // PORTSEL=01 (10BASE-T)
    mace_write(PHYCC, 0x00);        // ASEL=0, DLNKTST=0

    // 8. Configure interrupts (unmask Rx, errors, counters)
    mace_write(IMR, 0x01);          // Mask only XMTINT (poll Tx)

    // 9. Enable MAC (Tx + Rx)
    mace_write(MACCC, 0x03);        // ENXMT=1, ENRCV=1

    // 10. Clear pending interrupts
    (void)mace_read(IR);
}
```

---

## 10. Verification Checklist for ROM Disassembly

When analyzing NeXTSTEP ROM/kernel Ethernet code, check for:

### 10.1 Essential Register Writes

- [ ] **BIUCC**: `BSWP = 1` (big-endian mode) - **CRITICAL**
- [ ] **BIUCC**: `SWRST` toggled during init
- [ ] **MACCC**: `ENXMT = 1`, `ENRCV = 1` to enable
- [ ] **PADR**: 6-byte MAC address write via IAC
- [ ] **XMTFC**: `AUTO_PAD_XMIT = 1`
- [ ] **RCVFC**: `AUTO_STRIP_RCV = 1`
- [ ] **IMR**: Interrupt mask configuration
- [ ] **PLSCC**: Port selection (AUI vs 10BASE-T)

### 10.2 Data Path Operations

- [ ] **RCVFIFO**: Sequential reads after checking `PR.RDTREQ`
- [ ] **XMTFIFO**: Sequential writes after checking `PR.TDTREQ`
- [ ] **RCVFS**: Length extraction (`& 0x0FFF`)
- [ ] **RCVFS**: Error checking (OFLO, FCS, FRAM, CLSN)
- [ ] **XMTFS**: Status checking after `PR.XMTSV`
- [ ] **FIFOFC**: Loop counter for multi-frame processing

### 10.3 Interrupt Handler

- [ ] **IR**: Read-to-clear in interrupt handler
- [ ] **RCVINT**: Branch to receive service routine
- [ ] **XMTINT**: Branch to transmit complete (if enabled)
- [ ] **Error bits**: JABBER, BABBLE, CERR handling
- [ ] **Counter overflows**: MPCO, RNTPCO, RCVCCO

### 10.4 Multicast/Promiscuous Support

- [ ] **LADRF**: Write via IAC when multicast enabled
- [ ] **MACCC.PROM**: Set when promiscuous mode enabled

### 10.5 What May NOT Appear

- [ ] Writes to REG19, REG22, REG23, REG25, REG28, REG30, REG31 (reserved)
- [ ] **CHIPID** reads (may be omitted)
- [ ] **UTR** writes except during POST/self-test
- [ ] **PHYCC** polling (may just set-and-forget)

---

## 11. Open Questions (To Be Resolved by ROM Analysis)

1. **DMA vs PIO**: Does NeXT use DMA transfers or pure programmed I/O through FIFOs?
   - **Evidence needed**: Bus trace or register access patterns

2. **Transmit Interrupt Usage**: Is XMTINT enabled or does driver poll XMTSV?
   - **Evidence needed**: IMR value, interrupt handler code

3. **FIFO Watermark Tuning**: What values are used for XMTFW and RCVFW?
   - **Evidence needed**: FIFOCC register writes

4. **Burst Mode**: Are XMTBRST/RCVBRST enabled?
   - **Evidence needed**: FIFOCC bit 7 and bit 3

5. **Auto Port Select**: Is ASEL used or is port selection fixed?
   - **Evidence needed**: PHYCC register value

6. **Error Counter Polling**: How frequently are MPC/RNTPCR/RCVCC read?
   - **Evidence needed**: Counter access patterns

7. **Link State Monitoring**: Is PHYCC.LNKFL polled or only checked during init?
   - **Evidence needed**: PHYCC read frequency

---

## 12. Memory-Mapped I/O Address

**Unknown**: This specification describes register offsets 0-31 relative to the MACE base address.

**To be determined from ROM analysis**:
- NeXTcube/NeXTstation MACE base address
- Bus width (8-bit? 16-bit with byte strobes?)
- Endianness handling (BIUCC.BSWP should be set for 68k)

---

## Document Status

**Specification Source**: AMD Am79C940 datasheet + Linux/OpenBSD drivers
**NeXT-Specific Details**: Inferred from hardware requirements
**Confidence Levels**:
- Hardware register map: VERY HIGH (95%)
- Bit definitions: VERY HIGH (95%)
- NeXT usage patterns: MEDIUM (60%, inferred)

**Next Steps**:
1. Analyze NeXTSTEP ROM/kernel Ethernet code
2. Map memory-mapped I/O addresses
3. Verify actual register access patterns
4. Update confidence levels based on evidence

---

**Document Version**: 1.0
**Created**: 2025-01-13
**Last Updated**: 2025-01-13
**Analyst**: Claude Code
**Review Status**: Ready for ROM verification
