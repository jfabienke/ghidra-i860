# Bt463 RAMDAC Configuration — NeXTdimension Boot ROM

## Overview

The NeXTdimension boot ROM configures a Brooktree Bt463 168 MHz Triple DAC for
1120x832 @ 68.7 Hz, 32-bit RGBA output. Configuration occurs in virtual-mapped
code after paging setup, through a multi-stage process of 544+ register write
cycles.

Three functions implement the RAMDAC subsystem:

| Address      | Name             | Size     | Role |
|-------------|------------------|----------|------|
| 0xFFF00BE0  | `ramdac_init`     | 120 B    | Orchestrator: clears board regs, calls subroutines |
| 0xFFF00CB8  | `ramdac_program`  | 1,236 B  | Main Bt463 programming: 544 register writes |
| 0xFFF013A4  | `ramdac_reconfig` | 316 B    | Sync-gated reconfiguration with readback verify |
| 0xFFF00C58  | _(epilogue stub)_ | 4 B      | Compiler artifact (delay-slot `addu`) |

Call chain: `hw_detect` (0xFFF009C0) -> `ramdac_init` -> `ramdac_program` + `ramdac_reconfig`

## Bt463 Port Interface

Base address: **0xFF200000** (loaded into r19/r18 via `orh 0xff20,r0,rN`).

Four byte-wide ports at 32-bit-aligned offsets, decoded by the board's address
logic to the Bt463 RS pins:

| Offset | Address      | Direction | Function |
|--------|-------------|-----------|----------|
| +0x0   | 0xFF200000  | W         | Address Register — write index for indirect access |
| +0x4   | 0xFF200004  | W         | Palette/Colormap Data Port — sequential writes, auto-increment |
| +0x8   | 0xFF200008  | R/W       | Register Data Port — indirect register read/write, status readback |
| +0xC   | 0xFF20000C  | W         | Overlay/Alternate Control Port |

**Port assignment evidence:**
- +0x0 is used exclusively for address/index writes across all phases.
- +0x4 receives the bulk of sequential data (palette RGB bytes, LUT entries).
- +0x8 is the **only readable port** — `ld.b 0x8(r18)` in `ramdac_reconfig`
  (0xFFF01478) reads back for bit-test verification. This identifies it as the
  indirect register data port.
- +0xC appears in loop-phase write references for colormap/overlay data.

## Write Protocol

Every register write follows: **address -> delay -> data**.

The delay loop satisfies the Bt463 minimum 100 ns timing between address
and data writes:

```
    or   0xa,r0,r17          ; r17 = 10 (iteration count)
.L: shl  r0,r17,r16          ; r16 = 0 (dummy, burns cycles)
    addu -0x1,r17,r17        ; r17--
    btne r16,r0,.L            ; loop while r16 != 0 (always false after shl 0)
```

At 33 MHz (~30 ns/cycle), 10 iterations x ~3 cycles = ~300-500 ns, well above
the 100 ns minimum. The `shl r0,r17,r16` always produces 0 (shifting zero),
making the `btne` comparison effectively a countdown on r17.

## Configuration Phases

### Phase 0: Board Register Clears (ramdac_init)

Writes 0x00000000 to graphics controller registers before RAMDAC programming:

| Target       | Purpose |
|-------------|---------|
| 0xFF801000  | Graphics controller register 0 — clear/reset |
| 0xFF802000  | Graphics controller register 1 — clear/reset |

Prevents output glitches during RAMDAC setup by disabling the display path,
clearing interrupts, and resetting sync/dither logic.

### Phase 1: 12 Direct Control Register Writes (ramdac_program)

The first section of `ramdac_program` performs 12 indexed writes using varied
ports (+0x0 for address, then +0x4/+0x8/+0xC for data), targeting low-index
Bt463 control registers:

| Register Area        | Function |
|---------------------|----------|
| Command Reg 0 (CR0) | 1:1 multiplexing for ~70 MHz dot clock |
| Command Reg 1 (CR1) | 24-bit true-color bypass, 8-bit overlay depth |
| Command Reg 2 (CR2) | Port remapping: P[31:8] as RGB 8:8:8, lower bits as overlay/type |
| Pixel Read Mask     | 0xFF — all bits active |
| Overlay Control     | 8 overlays enabled, routed to alpha or separate map |
| Blank Level         | 0 IRE pedestal (no setup) |
| Test Control        | Test modes disabled |
| Clock/Mode Select   | External clock source, TrueVu enable |

Establishes the board's fixed 32-bit ARGB mode with per-pixel TrueVu
flexibility for X Windows multi-visual support.

### Phase 2: Window Type Table (16 Entries, ramdac_program)

Loop writes to Bt463 registers 0x0300-0x030F (extended address range). Each
entry is a 24-bit value (3 byte writes to data port).

The Window Type Table (WTT) uses 4-bit type codes extracted from pixel data to
select per-pixel rendering behavior:

- Most entries: 24-bit true-color direct bypass (no LUT lookup)
- Overlay/alpha integration from specific pixel bit fields
- Fallback pseudo-color paths for compatibility windows
- Plane shift/mask values matching the reconfigurable port setup

This enables simultaneous true-color and indexed-color windows on a per-pixel
basis — essential for the NeXTdimension's Display PostScript compositor.

### Phase 3: Cursor Color Table (4 Entries, ramdac_program)

Small loop writes to Bt463 registers 0x020C-0x020F (cursor color base). Each
entry contains RGB values for the hardware cursor.

The Bt463 supports a 64x64x2-bit hardware cursor with 3 colors + transparent:

| Entry | Typical Use |
|-------|------------|
| 0     | Background / transparent |
| 1     | Cursor body (e.g., white) |
| 2     | Cursor outline (e.g., black) |
| 3     | Complement / invert |

### Phase 4: Palette RAM (512 Entries, ramdac_program)

Largest loop: sets address 0x0000 via +0x0 port, then writes 512 x 3 bytes
(RGB) to data port +0x4 with auto-increment.

Loads a full 512-entry colormap into one or more of the three 528x8 LUTs
(size configured to 512 in Phase 1). Likely a standard 8x8x8 color cube
(512 colors) or gamma-corrected ramp for pseudo-color and overlay windows.

### Phase 5: Sync-Gated Reconfiguration (ramdac_reconfig)

A separate leaf function synchronizes register updates to the vertical blanking
interval:

```
1. Save 0xFF802004 (graphics control register) -> r20
2. Write 0x01 to 0xFF802004 (set sync gate / output enable bit)
3. Triple-phase sync poll on 0xFF800004 bit 0x100:
   a. bnc loop — wait for bit SET   (entering active region)
   b. bc  loop — wait for bit CLEAR (entering blank)
   c. bnc loop — wait for bit SET   (exiting blank -> safe window)
4. Fixed ~1000-cycle delay (or 0x3e8,r0,r17 -> countdown loop)
5. Three write cycles to Bt463:
   - Address = 0x0D (register index 13) via +0x0 port
   - Delay
   - Data to +0x4 and/or +0x8 ports
   -> Updates a critical control register (sync enable, PLL, or mode commit)
6. Read back from +0x8 port, test bit 3
   - Success: return 0 in r16
   - Failure: return 1 in r16
7. Restore saved r20 to 0xFF802004
```

Register index 0x0D targets a Bt463 control register — likely one governing
sync configuration, PLL parameters, or a mode-commit latch that must be updated
during blanking to avoid visual artifacts.

## Write Count Summary

| Phase | Target | Count | Content |
|-------|--------|-------|---------|
| 0 | Graphics controller | 2 | Clear/reset |
| 1 | Bt463 control regs | 12 | Command, mask, overlay, mode |
| 2 | Window Type Table | 16 | Per-pixel type configurations |
| 3 | Cursor colors | 4 | Hardware cursor palette |
| 4 | Palette RAM | 512 | Full colormap |
| 5 | Sync-gated update | 3 | Critical control register |
| **Total** | | **544 + 2 board + 3 reconfig** | |

## Supporting Hardware Registers

### Graphics Controller (0xFF800000 region)

| Address      | Name      | R/W | Role in RAMDAC Init |
|-------------|-----------|-----|---------------------|
| 0xFF800004  | CSR0+4    | R   | Status: bit 0x100 = sync/VSYNC signal, polled in triple-phase sequence |
| 0xFF801000  | GFX_CTRL_0| W   | Cleared to 0 before RAMDAC programming |
| 0xFF802000  | GFX_CTRL_1| W   | Cleared to 0 before RAMDAC programming |
| 0xFF802004  | GFX_CTRL_1+4| RW| Saved/restored during reconfig; bit 0 = sync gate |

### Data Table (0xFFF1FDA0)

28 x 4-byte entries in ROM used by the table-driven timing parameter writes.
Contains Bt463 register index + value pairs for video timing configuration
(not part of the 544-count main programmer — those are separate loop-driven
writes referenced in boot-rom-re.md Section 7.1).

## Outcome

After configuration completes, the Bt463 drives stable 1120x832 @ 68.7 Hz
output with:
- 32-bit ARGB pixel format
- TrueVu per-pixel window-type selection
- Default palette loaded (non-garbage colors for indexed windows)
- Hardware cursor with default colors
- Sync-verified control register state

The screen remains dark or shows a default gray until the kernel loads and
begins rendering through the Display PostScript system.

## Prior Misidentification

Early automated LLM analysis (swarm run `515c1f8e`) misclassified
`ramdac_program` and `ramdac_reconfig` as "serial UART initialization" because:

- Byte-wide writes (`st.b`) with fixed delay loops resemble UART register
  programming patterns.
- The value 0x0D (decimal 13) was interpreted as ASCII carriage return rather
  than Bt463 register index 13.
- The 4-port layout (+0x0/+0x4/+0x8/+0xC) superficially resembles a standard
  16550 UART register file.

The Previous/MAME emulator source (`nd_devs.c`) confirms 0xFF200000 is mapped
as the RAMDAC, not a serial port.

---

## Appendix A: Bt463 Full Register Map

The following is the complete register map and descriptions for the Brooktree
Bt463, extracted from the 1991 Brooktree Product Databook.

### A.1 Address Register (ADDR) Operation

| Item                  | Description |
|-----------------------|-------------|
| MPU interface         | 12-bit address register ADDR0-11 (ADDR12-15 ignored on write, read as 0) |
| CO, CI selection      | Determines which internal resource is accessed (see Table A-1) |
| Auto-increment        | After each 8-bit read/write, the address increments. For colour-palette / window-type table the address increments every third cycle (R/G/B sequencing) |
| Internal counters     | Additional bits ADDRa, ADDRb count modulo-3 for R/G/B cycles; not directly accessible by MPU |
| Access restrictions   | Window-type table may only be written/read during horizontal/vertical retrace |

#### Table A-1: Address Register Resource Mapping

| ADDR0-11      | CO, CI | Resource Accessed |
|---------------|--------|-------------------|
| `$xxxx`       | `00`   | Address register (ADDR0-7) |
| `$xxxx`       | `01`   | Address register (ADDR8-11) |
| `$0100`       | `10`   | Cursor colour 0 |
| `$0101`       | `10`   | Cursor colour 1 |
| `$0200`       | `10`   | ID register (`$2A`) |
| `$0201`       | `10`   | Command Register 0 (CR0) |
| `$0202`       | `10`   | Command Register 1 (CR1) |
| `$0203`       | `10`   | Command Register 2 (CR2) |
| `$0205`       | `10`   | P0-P7 read-mask register |
| `$0206`       | `10`   | P8-P15 read-mask register |
| `$0207`       | `10`   | P16-P23 read-mask register |
| `$0208`       | `10`   | P24-P27 read-mask register |
| `$0209`       | `10`   | P0-P7 blink-mask register |
| `$020A`       | `10`   | P8-P15 blink-mask register |
| `$020B`       | `10`   | P16-P23 blink-mask register |
| `$020C`       | `10`   | P24-P27 blink-mask register |
| `$020D`       | `10`   | Test register |
| `$020E`       | `10`   | Input-signature register |
| `$020F`       | `10`   | Output-signature register |
| `$0220`       | `10`   | Revision register (MS 4 bits = revision hex) |
| `$0300-$030F` | `10`   | Window-type table (16 entries x 24 bits) |
| `$0000-$020F` | `11`   | Colour-palette RAM (528 x 8 x 3, R/G/B) |

**Notes:**
- All accesses to the colour-palette and window-type table require three
  read/write cycles (R/G/B).
- Only two out of three cycles are valid for these resources.

### A.2 Command/Control Registers

| Register | Address | Width | Description |
|----------|---------|-------|-------------|
| **CR0**  | `$0201` | 8-bit | Multiplex select, blink rate/duty cycle |
| **CR1**  | `$0202` | 8-bit | Overlay mapping, plane config, cursor config |
| **CR2**  | `$0203` | 8-bit | Sync enable, pedestal, SAR control, test mode |

### A.3 Other Registers

| Register | Address | Width | Description |
|----------|---------|-------|-------------|
| ID Register | `$0200` | 8-bit | Read-only; value = `$2A` identifies the Bt463 |
| Revision Register | `$0220` | 8-bit | Read-only; MS 4 bits = revision number (hex) |
| Pixel Read-Mask | `$0205-$0208` | 28-bit (4x8) | Enable/disable individual pixel planes for palette access (P0-P27) |
| Pixel Blink-Mask | `$0209-$020C` | 28-bit (4x8) | Enable/disable blinking per pixel plane |
| Test Register | `$020D` | 8-bit | D0-D2: SAR pixel phase select; D3-D7: DAC comparison control |
| Input Signature | `$020E` | 16-bit | Captures pixel data for test purposes |
| Output Signature | `$020F` | 8-bit x 3 (R/G/B) | Captures DAC input for test purposes |
| Window-Type Table | `$0300-$030F` | 16 entries x 24 bits | Per-pixel mapping, plane selection, overlay mode |
| Colour Palette RAM | `$0000-$020F` | 528 x 8 x 3 (R/G/B) | Dual-port RAM; size variable by address mapping |
| Cursor Colours | `$0100-$0101` | 8-bit each | Define cursor colour 0 and colour 1 |

### A.4 Access and Timing Rules

- **Read/Write cycles**: Most registers are single-cycle 8-bit accesses.
  Colour-palette and window-type table accesses require three cycles (R/G/B);
  only two out of three carry valid data.
- **Auto-increment**: After each 8-bit transaction the address increments; for
  palette/window the address increments every third cycle.
- **Restricted windows**: Window-type table updates are allowed only during
  horizontal or vertical retrace to avoid visual artefacts.
- **Read-only registers**: ID (`$2A`) and Revision registers are read-only. All
  other registers are read/write.

---

## Appendix B: Bt463 Register ASCII Bit Diagrams

ASCII bit diagrams for key registers, derived from the Bt463 datasheet.
MSB left, LSB right.

### B.1 Command Register 0 (CR0) — `$0201` (R/W)

```
Bit:  7     6     5     4     3     2     1     0
     +-----+-----+-----+-----+-----+-----+-----+-----+
     |        Blink Rate/Duty        | Res | Res |     Multiplex Select      |
     |          (2 bits)             | (0) | (0) |         (2 bits)          |
     +-----+-----+-----+-----+-----+-----+-----+-----+
```

- Bits 7:6 — Blink rate/duty (`00`=16/48, `01`=16/16, `10`=32/32, `11`=64/64
  no blink)
- Bits 5:2 — Reserved (write 0)
- Bits 1:0 — Multiplex (`00`=reserved, `01`=4:1, `10`=1:1 high-speed, `11`=2:1)

**NeXTdimension setting**: `10` (1:1 mux) for ~70 MHz dot clock, `11` (no
blink) — typical value `0xC2`.

### B.2 Command Register 1 (CR1) — `$0202` (R/W)

```
Bit:  7     6     5     4     3     2     1     0
     +-----+-----+-----+-----+-----+-----+-----+-----+
     | Res | Res |       Overlay Config      | WTT | Ovly| Cont| Ovly |
     | (0) | (0) |         (2 bits)          |Size |Planes|Planes|Mapping|
     +-----+-----+-----+-----+-----+-----+-----+-----+
```

- Bits 7:6 — Reserved
- Bits 5:4 — Overlay/cursor config (`00`=none, `01`=1-bit cursor, `10`=2-bit
  cursor, `11`=reserved)
- Bit 3 — WTT entries (`0`=16, `1`=14)
- Bit 2 — Overlay planes (`0`=4, `1`=8)
- Bit 1 — Contiguous planes (`0`=24/28-bit standard, `1`=12/16-bit alternate)
- Bit 0 — Overlay mapping (`0`=start address, `1`=common palette)

**NeXTdimension setting**: 8 overlay planes (bit 2=1), 16 WTT entries (bit
3=0), 2-bit cursor (bits 5:4=`10`) — typical value `0x24`.

### B.3 Command Register 2 (CR2) — `$0203` (R/W)

```
Bit:  7     6     5     4     3     2     1     0
     +-----+-----+-----+-----+-----+-----+-----+-----+
     |             Test Mode             | SAR | SAR | Ped | Sync|
     |             (4 bits)              |Clock|Capt |estl |Enabl|
     +-----+-----+-----+-----+-----+-----+-----+-----+
```

- Bits 7:4 — Test mode (normally `0000`)
- Bit 3 — SAR clock control (`0`=LD*, `1`=CLOCK)
- Bit 2 — SAR capture select (`0`=lower 16 bits, `1`=upper 16 bits)
- Bit 1 — Pedestal (`0`=0 IRE, `1`=7.5 IRE)
- Bit 0 — Sync enable (`0`=off, `1`=on green DAC)

**NeXTdimension setting**: Normal operation (bits 7:4=0), 0 IRE pedestal (bit
1=0), sync enabled (bit 0=1) — typical value `0x01`.

### B.4 Pixel Read-Mask Registers — `$0205`-`$0208`

Four 8-bit registers forming a 28-bit mask (P0-P27).
`1` = plane enabled for palette lookup, `0` = masked.

```
Reg $0205 (P0-P7):   7   6   5   4   3   2   1   0
                    +---+---+---+---+---+---+---+---+
                    | P7| P6| P5| P4| P3| P2| P1| P0|
                    +---+---+---+---+---+---+---+---+

Reg $0206 (P8-P15):  7   6   5   4   3   2   1   0
                    +---+---+---+---+---+---+---+---+
                    |P15|P14|P13|P12|P11|P10| P9| P8|
                    +---+---+---+---+---+---+---+---+

Reg $0207 (P16-P23): 7   6   5   4   3   2   1   0
                    +---+---+---+---+---+---+---+---+
                    |P23|P22|P21|P20|P19|P18|P17|P16|
                    +---+---+---+---+---+---+---+---+

Reg $0208 (P24-P27): 7   6   5   4   3   2   1   0
                    +---+---+---+---+---+---+---+---+
                    |Res|Res|Res|Res|P27|P26|P25|P24|
                    +---+---+---+---+---+---+---+---+
```

**NeXTdimension setting**: All 0xFF (all planes active).

### B.5 Pixel Blink-Mask Registers — `$0209`-`$020C`

Identical layout to read-mask. Controls per-plane blinking when blink is
enabled in CR0. NeXTdimension sets all to 0x00 (no blinking).

---

## Appendix C: Window-Type Table (WTT) Bit Fields

The Window-Type Table consists of **16 entries** (addressed at `$0300`-`$030F`
with CO/CI = `10`), each a **24-bit configuration word**. Entries are indexed by
a **4-bit window type code** (WT3:WT0) supplied with each pixel, typically from
specific bits in the pixel/overlay port.

The WTT enables the proprietary **TrueVu** per-pixel reconfiguration, allowing
arbitrary mixing of display modes (true color bypass, pseudo color lookup,
overlays, etc.) within a single frame by routing and interpreting pixel data
differently per window/type.

Each 24-bit entry is accessed via **three sequential 8-bit write/read cycles**
(high byte bits 23-16, mid 15-8, low 7-0). Updates are restricted to retrace
periods to avoid artifacts.

### C.1 24-Bit Entry Layout

| Bits   | Field               | Width | Description |
|--------|---------------------|-------|-------------|
| 23     | LUT Bypass          | 1     | `1` = bypass palette in 8-plane pseudo color mode (direct: P<7:0> -> Red, P<15:8> -> Green, P<23:16> -> Blue; 256 gray shades). `0` = normal palette lookup. |
| 22:17  | Start Address       | 6     | Starting physical address (MSBs) for the color LUT in palette RAM. Maps start on 16-row boundaries. Max address `$020F` (528 entries). Supports variable map sizes (min 16, max 512 colors). |
| 16:13  | Overlay Mask        | 4     | Bitmask to enable/disable individual overlay planes (bit 13 = OL0 lockout, up to bit 16 = OL3). `1` = enabled (compacted to LSBs, zero-padded). `0` = masked. |
| 12     | Overlay Location    | 1     | Overlay data source: `0` = from high nibble P<27:24>. `1` = from LSBs of pixel data (True Color: interleaved; Pseudo: above pixel planes). |
| 11:9   | Display Mode        | 3     | Pixel data interpretation (see Table C-1). |
| 8:5    | Number of Planes    | 4     | Active pixel planes per channel or total. True Color: 0-8 planes/channel (total = 3 x value). Pseudo Color: 0-9 planes total. Constraint: shift + planes <= 28. |
| 4:0    | Shift               | 5     | Starting bit position of active pixel planes in the 28-bit input word P<27:0>. Shifts data right to align active bits to LSB. Range 0-27. Constraint: shift + total planes <= 28. |

#### Table C-1: Display Mode Encoding (Bits 11:9)

| Value | Mode | Description |
|-------|------|-------------|
| `000` | True Color | Equal R/G/B planes, direct DAC routing |
| `001` | Pseudo Color | Contiguous planes form LUT index |
| `010` | Bank Select | Overlay as MSBs for palette banking |
| `011` | Reserved | |
| `100` | 12-plane True Color | Interleaved load |
| `101` | 8-plane Pseudo Color | Interleaved load |
| `110` | Reserved | |
| `111` | Reserved | |

### C.2 Bit Layout Diagrams

Each 24-bit entry is written/read as three 8-bit cycles (high, mid, low):

```
Byte 2 (Bits 23-16): 23  22  21  20  19  18  17  16
                    +---+---+---+---+---+---+---+---+
                    |Byp|         Start Address         |
                    |ass|            (6 bits)            |
                    +---+---+---+---+---+---+---+---+

Byte 1 (Bits 15-8):  15  14  13  12  11  10   9   8
                    +---+---+---+---+---+---+---+---+
                    |   Overlay Mask    | OV  |   Display Mode    |
                    |OL3 OL2 OL1 OL0   | Loc |      (3 bits)     |
                    +---+---+---+---+---+---+---+---+

Byte 0 (Bits 7-0):   7   6   5   4   3   2   1   0
                    +---+---+---+---+---+---+---+---+
                    |     Planes        |         Shift           |
                    |     (4 bits)      |        (5 bits)         |
                    +---+---+---+---+---+---+---+---+
```

- Bit 23 — Bypass (`1`=direct in pseudo mode)
- Bits 22:17 — Start Address (6-bit MSB for LUT base)
- Bits 16:13 — Overlay Mask (per-plane enable)
- Bit 12 — Overlay Location (`0`=high nibble, `1`=interleaved/LSB)
- Bits 11:9 — Display Mode (`000`=True Color, `001`=Pseudo, etc.)
- Bits 8:5 — Planes (0-8 per channel or total)
- Bits 4:0 — Shift (starting bit position in 28-bit word)

### C.3 Operational Notes

- **True Color** (mode `000`): Pixel data routed directly to DACs; equal plane
  count for R/G/B. Bypass (bit 23) enables direct mapping in special cases.
- **Pseudo Color** (mode `001`): Planes form LUT index; start address + shifted
  index selects palette entry.
- **Overlay handling**: Masked/compacted overlay bits can replace or mix with
  color data; location is flexible for scattered or packed bit layouts.
- **Constraints**: All configurations must respect the 28-bit pixel port width
  (P<27:0>). Invalid combinations produce undefined behavior.
- **Flexibility**: Combined with command registers (CR1 for global overlay depth
  4/8, WTT size 16/14), this allows pixel-basis switching between visuals
  (e.g., 24-bit true color beside 8-bit pseudo color, each with private maps).

### C.4 NeXTdimension WTT Configuration

The boot ROM's 16-entry load likely configures most or all entries for True
Color (`000`) with 8 planes/channel, appropriate shifts for packed 32-bit ARGB
(e.g., Shift=0, Planes=8, RGB contiguous), overlay from high bits, and
bypass/start address set for compatibility. This structure is what makes the
Bt463 uniquely suited for advanced multi-window X11 environments like NeXTSTEP.

---

## Appendix D: Hardware Cursor

The Bt463 provides built-in hardware cursor support (often called a hardware
sprite), offloading cursor rendering from the CPU and frame buffer. This
reduces flicker, CPU load, and bandwidth usage — critical for smooth UI
performance in systems like NeXTSTEP on the NeXTdimension board.

### D.1 Specifications

| Parameter | Value |
|-----------|-------|
| Cursor size | 64 x 64 pixels (fixed) |
| Depth | 2 bits per pixel (4 states) |
| Programmable colors | 3 (or 4 including special mode) x 24-bit RGB |
| Pattern storage | 512 bytes on-chip cursor RAM (64 x 64 x 2-bit) |
| Position range | 0-2047 X/Y (board-specific registers) |

### D.2 2-Bit Cursor Color Mapping

| 2-Bit Value | Meaning | Description |
|-------------|---------|-------------|
| `00` | Transparent | Shows underlying frame buffer pixel unchanged |
| `01` | Cursor Color 1 | Programmable RGB (e.g., foreground / white) |
| `10` | Cursor Color 2 | Programmable RGB (e.g., background / black) |
| `11` | Cursor Color 3 or Invert | Programmable RGB or inverts frame buffer pixel (outline/shadow) |

This allows simple but effective cursors — arrows with outline, shadow, or
anti-aliased appearance without software blending.

### D.3 Color Registers

Cursor colors are loaded via dedicated registers accessed through the indirect
address mechanism (CO/CI = `10`):

| Address | Register |
|---------|----------|
| `$0100` | Cursor Colour 0 |
| `$0101` | Cursor Colour 1 |

Additional colors (for the third state or invert mode) may use extended or
adjacent registers. The boot ROM's 4-entry cursor load (Phase 3, registers
`$020C`-`$020F`) likely covers Color 1-3 plus a mask or alternate.

### D.4 Enabling via CR1

Cursor mode is controlled by Command Register 1 (CR1) bits 5:4:

```
Bit:  5     4
     +-----+-----+
     | Overlay/Cursor Mode |
     +-----+-----+
```

| Value | Mode |
|-------|------|
| `00` | No overlays / cursor disabled |
| `01` | 1-bit cursor (2 states: transparent or one color) |
| `10` | 2-bit cursor (full 4-state mode) |
| `11` | Reserved |

### D.5 Integration with TrueVu Overlay System

The cursor integrates with the Bt463's overlay architecture:

- Cursor can use dedicated overlay planes (configured via CR1 bit 2 for 4/8
  planes, and WTT entries for per-pixel overlay routing).
- Cursor pattern and index come from overlay bits in the pixel data stream, or
  via the dedicated internal cursor array.
- The 64 x 64 x 2-bit pattern (512 bytes) is loaded into on-chip cursor RAM
  via MPU writes (sequential or indexed through overlay/command ports).
- Updates restricted to retrace to avoid artifacts (same as WTT).

### D.6 Position Control

X/Y hotspot position (0-2047 range) is set via separate registers, typically
board-specific or accessed through additional indirect addresses not fully
documented in the basic register map. Hotspot offset is programmable for
precise alignment.

### D.7 NeXTdimension Usage

The boot ROM's RAMDAC init includes a small loop loading 4 cursor entries
(the RGB values for 3-4 colors). This sets up default cursor appearance
(e.g., black outline, white fill, transparent background) before the kernel
loads and takes over dynamic cursor changes (pattern updates, position via
mailbox commands or direct MMIO).

Hardware cursor acceleration ensures responsive mouse movement even on the
i860's graphics pipeline, complementing the board's 32-bit true-color +
alpha/overlay design for multi-window X11 environments.

The Bt463's cursor relies on overlay integration rather than a fully
independent sprite engine seen in later chips (e.g., Bt485 with explicit
256-entry cursor RAM).

---

## Appendix E: Initialization Sequence Detail

The Bt463 RAMDAC initialization in the NeXTdimension boot ROM (v43) occurs in
Region 5 (virtual addresses post-paging). It uses table-driven byte-wide writes
with ~10-cycle delays between address and data cycles to meet timing
requirements.

The process includes **544 total register write cycles** (address + data pairs,
some sequential with auto-increment). The sequences follow this order:

### E.1 Pre-Initialization Board Register Clears (ramdac_init, ~0xFFF00BE0)

Write `0x00000000` to undocumented board registers:

| Target       | Purpose |
|-------------|---------|
| 0xFF801000 (or offset +0x1) | Reset graphics controller state |
| 0xFF802000 (or offset +0x1) | Disable output or clear sync/dither logic |

Prevents glitches during RAMDAC setup.

### E.2 Direct Control/Command Register Writes (ramdac_program, ~0xFFF00CB8)

12 indexed single-byte (or short sequence) writes to low-address registers
(address via port +0x0, data via +0x8/+0xC). Targets include:

| Target                | Value / Purpose |
|-----------------------|-----------------|
| ID/Revision           | Read — verify `$2A` |
| Command Register CR0  | 1:1 multiplexing for ~70 MHz dot clock |
| Command Register CR1  | 24-bit true-color bypass, 8-bit overlay depth |
| Command Register CR2  | 0 IRE pedestal, sync enable, test disable |
| Pixel Read-Mask       | 0xFF — all 28 bits active |
| Pixel Blink-Mask      | All 0xFF |
| Overlay Control       | 8 overlays enabled, routed to alpha or separate map |
| Blank Level           | 0 IRE pedestal (no setup) |
| Test Control          | Test modes disabled |
| Clock/Mode Select     | External clock source, TrueVu enable |

Configures core mode: 24-bit true color + 8-bit overlay, TrueVu enable,
palette size 512.

### E.3 Window Type Table Load (Loop 1 in ramdac_program)

16 iterations for entries `$0300`–`$030F`. Per entry: set extended base address,
then 3 byte writes (24-bit: high/mid/low) to data port (auto-increment every 3
cycles).

- Total: ~48 write cycles (plus addresses)
- Configures per-pixel TrueVu mapping (mostly true color bypass, planes=8,
  shift for 32-bit ARGB packing, overlay from specific bits)

### E.4 Cursor Color Load (Loop 2 in ramdac_program)

4 iterations (addressing `$020C`–`$020F` or cursor base `$0100`+). Per entry:
1–3 byte writes (RGB for colors 0–3, supporting 2-bit cursor with
transparent/foreground/background/invert).

Enables hardware 64x64x2-bit cursor via CR1 overlay config.

### E.5 Palette RAM Load (Loop 3 in ramdac_program)

512 iterations for entries `$0000`–`$01FF`. Set start address `0x00` via port
+0x0, then sequential 3 byte writes per entry (RGB, 8-bit/channel) to data port
with auto-increment.

- Largest sequence (~1,536 data writes)
- Loads default colormap (likely 8x8x8 cube or ramp for pseudo-color
  compatibility)

### E.6 Reconfiguration and Verification (ramdac_reconfig, ~0xFFF013A4)

Separate leaf function ensuring updates apply during blanking:

```
1. Save board register 0xFF802004
2. Set enable bit (write 0x01)
3. Triple-phase poll on 0xFF800004 bit 0x100:
   a. Wait for bit SET   (entering active region)
   b. Wait for bit CLEAR (entering blank)
   c. Wait for bit SET   (exiting blank → safe window)
4. Fixed ~1,000-cycle delay (or 0x3E8,r0,r17 → countdown loop)
5. Three write cycles to Bt463:
   - Address = 0x0D (register index 13) via +0x0 port
   - Delay
   - Data to +0x4 and/or +0x8 ports
   → Updates critical control register (sync enable, PLL, or mode commit)
6. Readback from +0x8 port, test bit 3:
   - Success: return 0 in r16
   - Failure: return 1 in r16
7. Restore saved value to 0xFF802004
```

### E.7 Summary

These sequences fully configure the Bt463 for fixed 1120x832x32-bit mode with
hardware cursor and TrueVu flexibility. Exact byte values are hard-coded
constants/tables in the ROM. The structure and count match the documented 544
cycles precisely. Video remains dark/default until kernel rendering begins.

---

## Appendix F: Bt463 Quirks and Idiosyncrasies

The Brooktree Bt463 is a sophisticated but complex design from the early 1990s,
with several quirks stemming from its flexibility (TrueVu per-pixel mode
switching, reconfigurable ports) and era-specific constraints. These appear in
the datasheet (marked as "Advance Information" with target specs subject to
change) and real-world use (e.g., NeXTdimension).

### F.1 Preliminary/"Advance" Status

- The datasheet is labeled **"Advance Information"** — parametric and functional
  specs are targets, subject to change without notice.
- Advises consulting Brooktree for the latest version before design-in.
- Common for pre-production silicon; some early chips may have variances in
  timing or undocumented behavior.

### F.2 Access Restrictions for Sensitive Tables

- **Window Type Table (WTT)** and cursor pattern updates are **restricted to
  horizontal/vertical retrace (blanking) intervals only**.
- Writes outside blanking can cause visible artifacts (tearing, glitches) due
  to on-the-fly pixel routing changes.
- Requires careful synchronization in software (as seen in NeXTdimension's
  `ramdac_reconfig` with VSYNC polling).

### F.3 Unusual Auto-Increment Behavior

- Address register auto-increment is **mode-dependent**:
  - Single-byte registers: increment every write/read.
  - 24-bit resources (palette RAM, WTT): increment **every third cycle** (after
    full R/G/B sequence).
- Only **two out of three cycles** carry valid data for these (the third is
  dummy/no-op).
- Easy to mishandle in MPU code, leading to offset errors if not sequencing
  RGB properly.

### F.4 Alignment and Boundary Constraints

- Palette map start addresses (in WTT) must be on **16-entry boundaries**.
- Shift + planes total <= 28 bits (hard limit from pixel port width); invalid
  combos produce undefined routing.
- Variable palette sizes (16-512) but physical RAM is fixed 528 deep — wasted
  space or careful mapping needed for multiple maps.

### F.5 Reserved/Undocumented Bits and Modes

- Many reserved bits in CR0/CR1/CR2 and masks **must be written as 0** (read
  back undefined).
- Some test modes and SAR (Signature Analysis Register) bits are for
  factory/JTAG diagnostics; misuse can lock up DACs or enable undocumented
  strobes.
- Revision register only partially documented (MS 4 bits = hex revision).

### F.6 Overlay and Cursor Integration Quirks

- Cursor shares overlay logic — enabling 2-bit cursor consumes overlay config
  bits; no fully independent sprite RAM (pattern load indirect/via overlays).
- Overlay location bit flips between packed high nibble and
  interleaved/scattered bits — non-intuitive for scattered pixel formats.
- Blink masks apply globally if enabled, but duty cycles are coarse
  (field-based, not per-pixel).

### F.7 Timing and MPU Interface Idiosyncrasies

- Strict **100 ns minimum** between address and data writes (hence delays in
  firmware like NeXT's).
- No internal PLL — relies on external pixel clock; no programmable clock gen.
- Read-mask/blink-mask are 28-bit spread across four registers — awkward for
  32-bit systems.

### F.8 Testability Overheads

- Heavy emphasis on signature registers and JTAG — useful for production test
  but adds internal state that can capture garbage if not flushed.
- Output signature on DAC inputs — potential for test mode bleed if not
  disabled properly.

### F.9 Practical Impact

These make the Bt463 powerful for multi-visual X Windows (as in NeXT) but
fiddly to program correctly — firmware must be precise with sequencing, timing,
and retrace sync. No major silicon bugs are widely reported, but the flexibility
invites configuration mistakes. In practice, systems like NeXTdimension
hard-code everything for one mode to avoid pitfalls.

---

## Appendix G: NeXTdimension Board Implementation Details

The NeXTdimension (ND) is a NuBus expansion board for the NeXTcube
(1991-1993), adding accelerated 32-bit color graphics, 3D rendering, and video
compression/decompression. It functions as a co-processor system with its own
Intel i860 RISC CPU, memory, and peripherals, communicating with the host
NeXTcube via shared NuBus mailbox MMIO and DMA.

### G.1 Processor and Architecture

- **CPU**: Intel i860XR RISC processor at **33 MHz**.
- **Instruction Set**: Full i860 with FPU, used for PostScript rendering
  acceleration, 3D transforms, and imaging operations in NeXTSTEP.
- **Address Space** (from i860 view, per boot ROM RE):

| Range                     | Size     | Function |
|--------------------------|----------|----------|
| 0x00000000-0x03FFFFFF    | 8-64 MB  | DRAM (configurable, typically 16-32 MB) |
| 0x10000000-0x103FFFFF    | 4 MB     | VRAM (framebuffer) |
| 0xFF200000-0xFF200FFF    | 4 KB     | Bt463 RAMDAC |
| 0x02000000 range         | —        | Mailbox/DMA/interrupt registers |
| 0xFFF00000-0xFFF1FFFF    | 128 KB   | Boot ROM (28F010 flash) |

- **No UART**: All debugging/logging via host mailbox (no serial console).

### G.2 Memory Subsystem

- **Board DRAM**: 8 MB standard, expandable to 32 MB via 72-pin SIMMs
  (separate from host RAM; used for GaCK kernel, buffers, and i860 code/data).
- **VRAM**: Fixed **4 MB** (single-buffered 1120x832x32-bit uses ~3.73 MB;
  little overhead for double-buffering or extras).
- **Framebuffer Format**: 32-bit ARGB (8-bit alpha + 24-bit RGB), with
  overlay/TrueVu bits integrated.

### G.3 Video Output and RAMDAC

- **Resolution/Timing**: Fixed **1120x832** (~4:3 aspect, ~68-72 Hz refresh),
  non-programmable in hardware/firmware (no mode switching).
- **RAMDAC**: Brooktree **Bt463** 170 MHz TrueVu RAMDAC.
  - 1:1 multiplexing, 24-bit true color bypass + 8-bit overlay/alpha.
  - 16-entry WTT for per-pixel mode mixing (mostly true color).
  - 512-entry palette load for pseudo-color compatibility.
  - Hardware 64x64x2-bit cursor (4 states: transparent, color1, color2,
    invert).
  - Output: Analog RGB with sync-on-green via 13W3 connector.
- **Boot ROM Programming**: Table-driven init with 544 write cycles,
  retrace-synced updates, default gray/ramp palette until kernel render.

### G.4 Boot and Firmware

- **Boot ROM**: 128 KB flash (v43 known dump), minimal bootloader.
  - Cold-start init: PSR/EPSR setup, FPU warmup, cache/TLB flush, slot ID
    detection, paging enable.
  - RAMDAC full programming (clears, controls, WTT, cursor, palette).
  - Mailbox polling loop: Receives commands from host (NDserver driver),
    DMA-loads GaCK (Graphics and Core Kernel) to DRAM @0x00000000, jumps to
    it.
- **Kernel**: GaCK runs on i860, handles Display PostScript acceleration,
  compositing, and host offload.

### G.5 Video Compression/Acceleration

- **JPEG Codec**: C-Cube CL550 chip for hardware JPEG compress/decompress.
  - Supports real-time video capture and playback, integrated with NeXTSTEP's
    video apps.
  - Potential for frame grabbing/recording (community reports mixed success
    with quality).

### G.6 Host Integration

- **NuBus Interface**: Occupies one slot, shares memory window for DMA (host
  loads kernel binary stripped of headers).
- **Software**: Requires NeXTSTEP 3.x with ND driver; host handles window
  management, offloads rendering to board.
- **Power/Thermal**: Includes fan; board can draw significant power.

### G.7 Known Limitations and Quirks

- **Fixed Mode**: No resolution changes possible without extreme mods
  (VRAM/timing generator limits).
- **Compatibility**: Works only in NeXTcube (not slab/station); multiple boards
  supported in emulation but rare in hardware.
- **Emulation**: Well-supported in **Previous** emulator (open-source, accurate
  i860/MMIO modeling based on RE efforts).

### G.8 Historical Context

No public full schematics exist (proprietary), but reverse-engineering (boot
ROM, emulator source) provides deep insights into MMIO and init sequences. The
board exemplifies NeXT's high-end UNIX workstation push but saw limited adoption
due to cost (~$3,995) and fixed design.

---

## Appendix H: i860 Kernel (ND_MachDriver) — RE-Corrected Profile

The i860 kernel binary — variously called "GaCK" (Graphics and Core Kernel) in
community sources, or `ND_MachDriver` in the host-side NDserver driver — runs on
the Intel i860XR processor after the boot ROM completes initialization. It is
loaded by the host NDserver driver via mailbox DMA and handles Display PostScript
acceleration, graphics rendering, and video tasks.

> **Epistemic status**: This section distinguishes RE-verified facts from
> inferences and community speculation. Claims are tagged **[verified]**,
> **[inferred]**, or **[speculative]** accordingly. The kernel's static analysis
> ceiling (1.4% code recovery) means most internal details remain unknown.

### H.1 Binary Structure [verified]

The kernel binary is **not** a pure i860 image. It is a fat Mach-O container
bundling multiple architectures and non-code content:

| Property | Value |
|----------|-------|
| File | `i860_kernel.bin` (also `ND_MachDriver_reloc`) |
| Format | Mach-O (CPU type 15 = i860) |
| Size | 802,816 bytes (784 KB) |
| Load address | 0xF8000000 |
| Architecture | i860:LE:32:XR, GCC/NeXTSTEP ABI (r2=sp, r3=fp) |

**Content breakdown** (1 KB block classification):

| Type | Size | % | Description |
|------|------|---|-------------|
| X86 code | 298,312 B | 40.8% | NeXTtv.app, drivers |
| Null padding | 115,712 B | 15.8% | Zero-fill between objects |
| ASCII text | 108,544 B | 14.9% | Strings, Spanish localization, Emacs changelog |
| X86 data | 71,680 B | 9.8% | x86 initialized data |
| Binary data | 54,272 B | 7.4% | Unclassified |
| M68K code | 41,984 B | 5.7% | Host driver code |
| M68K data | 27,648 B | 3.8% | m68k initialized data |
| i860 code | ~9,216 B | ~1.3% | Actual i860 instructions |

Three embedded Mach-O objects at F8017CB8 (m68k), F803DCB8 (x86), F805DCB8
(x86). Three independent methods converge on ~1.3% real i860 code.

### H.2 Loading Mechanism [verified]

From NDserver RE (88 functions, 100% coverage):

1. NDserver loads kernel from `/usr/lib/NextDimension/nd_kernel` (or
   `ND_MachDriver_reloc` in psdrvr bundle).
2. NDserver also embeds a **backup kernel** in its own `__I860` segment
   (802,816 bytes, different MD5 from filesystem version).
3. Kernel loaded segment-by-segment to i860 DRAM via NuBus memory window.
4. **Branch instruction patching** (FUN_0000746c): NDserver rewrites i860
   `br` targets during load for relocation.
5. Checksum verification per segment.
6. Entry point set; i860 released from reset.

### H.3 Host Protocol [verified from NDserver RE]

NDserver operates as a **user-space driver daemon** bridging NeXTSTEP's Window
Server and the board:

```
Window Server (Display PostScript)
    -> NDserver (m68k user-space, 48-byte message protocol, magic 0xd9)
        -> Kernel driver (NeXTdimension.driver)
            -> i860 mailbox (0x02000000 MMIO)
```

**Message format** (48 bytes):
```
struct nd_message {
    uint32_t magic;           // 0xd9 (validation constant)
    uint32_t operator_code;   // Command/PS operator code
    uint32_t param1-3;        // Parameters
    void*    output_ptr1/2;   // Output buffer pointers
    uint32_t flags;           // Control flags
};
```

**Verified command codes** (from NDserver RE, not yet ROM-matched):

| Category | Codes | Description |
|----------|-------|-------------|
| Core commands | 0x28, 0x42C, 0x434, 0x43C, 0x838, 0x1EDC | Graphics, DMA, config, state, video, advanced |
| PostScript operators | 0xC0-0xE3 (28 total) | DPS acceleration dispatch |
| Message types | 0x20 (dual output), 0x30 (simple return) | Two dispatch paths |

**From Previous emulator** (not yet ROM-verified):

| Code | Name | Description |
|------|------|-------------|
| 0x01 | LOAD_KERNEL | DMA kernel to DRAM, jump to entry |
| 0x07 | SET_PALETTE | Load RAMDAC palette colors |
| 0x0B | DPS_EXECUTE | Execute Display PostScript program |
| 0x0C | VIDEO_CAPTURE | Capture video frame |
| 0x10 | GET_INFO | Return board info |
| 0x11 | MEMORY_TEST | Run memory diagnostics |

Three-level validation: magic constant check, then three global state
constants (0x7bac, 0x7bb0, 0x7bb4).

### H.4 Display PostScript Integration [verified host-side, inferred i860-side]

NDserver RE confirmed **28 DPS operator handlers** on the host (m68k) side,
dispatched via a table at codes 0xC0-0xE3:

| Operator | Address | Function | Purpose |
|----------|---------|----------|---------|
| 0xC0 | 0x3CDC | PS_ColorAlloc | Color allocation |
| 0xC6 | 0x43C6 | PS_Command | Command processor |
| 0xD1 | 0x44DA | PS_Graphics | Graphics state |
| 0xD6 | 0x4A52 | PS_SetColor | Set color |
| 0xDA | 0x4F64 | PS_MakeFont | Font creation |
| 0xDB | 0x5078 | PS_BitBlit | Block transfer |
| ... | ... | ... | (28 total) |

Each operator validates the 48-byte message, calls the kernel API (likely
`msg_send`), and processes the response.

The kernel binary contains a **32 KB embedded PostScript/Adobe Illustrator
resource** at VA 0xF800FCB8-0xF8017BFF with structure markers (`% graphic state
operators`, `% path painting operators`, `%%EndProlog`, AI3 encoding vectors).
This is **resource data, not executable code** — it contains operator wrappers
and vector path payloads.

> **[inferred]**: The i860 side likely executes rendering operations dispatched
> by these host-side operators, not a full PostScript interpreter. The
> PostScript parsing/stack happens on the host; the i860 accelerates
> rasterization, compositing, and color operations.

### H.5 Static Analysis Ceiling [verified]

| Metric | Value |
|--------|-------|
| Instructions recovered | 2,536 |
| Functions discovered | 60 |
| Code bytes | 10,144 (1.4% of __text) |
| Curated seeds | 311 definitions, 153 accepted |
| Indirect branch (bri) sites | 616 |
| bri sites hitting block boundaries | 512 |
| Statically resolved bri targets | **0** |

**Why the ceiling is absolute**:
- The kernel relies on `calli` (register indirect call) and `bri r8` (handler
  dispatch) rather than direct `call` instructions.
- Phase 2 cross-block analysis (reverse CFG: 5,642 blocks / 5,984 edges)
  proved bri dispatch addresses are runtime-computed via ALU chains.
- r7/r13/r18 are NOT persistent base pointers (160-337 writes each, all ALU).
- Zero automated function discovery: no direct calls, no recognizable
  prologues, no data pointers into code.

### H.6 Swarm Analysis Results [verified]

LLM swarm analysis (run 3f574718, 60 shards, 1.52M tokens):

- 52 accept (87%), 6 revise (10%), 2 reject (3%)
- **All 52 accepted functions are orphaned dead code** with zero callers and
  zero callees
- 77-100% of instructions write to hardwired-zero registers (r0/f0)
- Common patterns: loads into r0 sink, missing returns, self-contradictory
  register usage, duplicate sequences suggesting misalignment
- **Zero subsystems identified**; no call graph connectivity
- Three functions touch MMIO 0x401C (possible PostScript token register) but
  surrounding context is structurally invalid

**Conclusion**: The analyzed set represents linker artifacts, dead code from
elimination, test stubs, or data misinterpreted as code. Real firmware logic
is behind the 616 unresolved bri sites.

### H.7 Emulation Status [verified]

| Scenario | Result |
|----------|--------|
| Boot ROM run (0xFFF00020, stop at 0x00000000) | Success: 203 insns, post-ROM state captured |
| Kernel from 0xF8000348 (state JSON) | Faults after 1,040 insns: unaligned access at 0xF8001388 |
| Kernel with unaligned-bypass | Self-loops at 0xF800138C (~48,959 hits), no dispatch events |
| MMIO scalar sensitivity (49 value pairs) | No behavioral change; all trap at 0xF800138C |

The word at 0xF800138C is 0x19B8801E (primary opcode 0x06, reserved). Trap
behavior is expected; the unresolved issue is why execution reaches this
reserved-opcode region before dispatch-producing code.

### H.8 Resolved Questions [from source analysis]

The following were resolved via NextDimension-21 source code analysis:

- **Kernel entry protocol**: NDLoadCode (`code.c`) parses the Mach-O
  `LC_THREAD`/`LC_UNIXTHREAD` command to extract the entry point. Segments are
  loaded individually with mixed-endian writes: `LOADTEXT(addr, data)` uses
  `addr ^ 4` (XOR-4 byte swap for i860 big-endian instruction fetch in
  little-endian data mode), while `LOADDATA` writes directly. The ROM does not
  parse Mach-O headers — all Mach-O handling is host-side.
- **XOR-4 byte swap**: The i860 instruction bus is 64 bits wide but instruction
  words are 32 bits. The XOR-4 ensures words are placed in the correct half of
  the 64-bit bus when the processor is in Big-Endian mode.
- **MMIO wake protocol**: To drive firmware past poll loops, the host must:
  (1) populate shared memory message queues (`ToND` at
  `ND_START_UNCACHEABLE_DRAM=0xF80C0000`), and (2) set the `NDCSR_INT860` bit
  in the MC CSR (0xFF800000). Queues use Lamport locks (`Lock_x`, `Lock_y`,
  `Lock_b`) for lock-free host-i860 communication.
- **r15 / GState**: In the boot ROM, r15 points to `ROMGlobals` (per
  `NDrom.h`). In the kernel, it expands to a larger graphics state structure
  anchoring transformation matrices, clipping bounds, and color parameters.
- **CL550 JPEG codec**: Present at 0xF0000000 (DataPath) but not
  memory-mapped intelligent device. Controlled via bit-banging registers in
  DP_CSR (0x340): `JPEG_IN`, `JPEG_OUT`, `JPEG_OE` bits.
- **Board variant detection**: `ND_init` in `ND_server.c` probes for the NBIC
  (NextBus Interface Chip) and checks `machine_type` (NeXT_CUBE vs
  NeXT_WARP9) before locating the Dimension board.
- **NDkernel-21 source confirms cooperative scheduler**: `SpawnProc`,
  `Sleep`/`Wakeup` in `switch.c`; no preemptive task model. Syscall table
  (`init_sysent.c`) dominated by `nosys` entries — purpose-built, narrow
  runtime.

### H.9 What Is NOT Known [remaining unknowns]

- Internal function names for the 3.3 binary (no symbols recovered;
  NextDimension-21 names are 2.0-era and may not match)
- Whether the 3.3 binary still uses the same cooperative scheduler or has
  evolved
- Precise PostScript operator-to-handler binding in 3.3 firmware (0xC0-0xE3
  host-side operators are known; i860-side handlers are behind bri dispatch)
- Runtime BSS dispatch table contents (presumably built at startup in
  0xF80B7C00+, not yet traced)
- Whether GaCK is the official NeXT-internal name (NDkernel-21 source uses
  "NDkernel")
- External repositories (e.g., `johnsonjh/NeXTDimension`) — contents not
  verified against this RE effort

### H.10 Verified Architecture Summary

What IS firmly established:

- **Board-local lightweight runtime** with Mach-like services (trap handling,
  VM wrappers, message queues, cooperative scheduler), not a full Mach kernel
  — confirmed by NextDimension-21 source (`kern_main.c`, `switch.c`,
  `init_sysent.c`)
- **Fat Mach-O container** with ~1.3% real i860 code
- **Indirect dispatch architecture** using `bri r8` handler tables and `calli`
  — no direct call graph discoverable by static analysis
- **28 DPS operator types** dispatched from host via NDserver
- **Mailbox protocol** with 48-byte messages, magic 0xd9, three-level
  validation, Lamport-locked shared queues
- **802,816 bytes** loaded segment-by-segment with XOR-4 text swap, branch
  patching, and checksum verification
- **Entry point extracted from LC_THREAD** by host-side NDLoadCode
- GCC ABI (r2=sp, r3=fp) confirmed from Mach-O load commands
- **32 KB PostScript resource data** embedded (not executable)
- **CL550 JPEG** controlled via DP_CSR bit-banging, not memory-mapped I/O
- **0xF8000348** appears to be real code entry (past Mach-O header), but
  execution stalls before reaching dispatch code — likely because emulator
  does not model the queue+interrupt wake protocol
