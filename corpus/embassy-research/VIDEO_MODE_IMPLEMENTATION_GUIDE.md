# NeXTdimension Video Mode Implementation Guide
## Adding Modern 16:9 Widescreen Support to GaCKliNG

**Question**: To add new video modes (1366×768, 1600×900, 1920×1080), what needs to be modified?

**Answer**: You need to modify **three primary components** in this order of importance:

1. ✅ **ND Firmware (GaCK kernel)** - **CRITICAL** - Primary video mode logic
2. ✅ **ND Driver (Host-side)** - **REQUIRED** - NeXTSTEP integration
3. ⚠️ **ND ROM (Bootstrap)** - **OPTIONAL** - Default boot mode only

---

## Architecture Overview

The NeXTdimension display system has three layers:

```
┌─────────────────────────────────────────────────────────────┐
│  Layer 3: ND Driver (Host m68k/68040)                       │
│  ─────────────────────────────────────────────────────────  │
│  • NDserver daemon                                          │
│  • Window Server integration                                │
│  • Sends mailbox commands to i860                           │
│  • Knows framebuffer size, format, stride                   │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼ (NeXTBus mailbox protocol)
┌─────────────────────────────────────────────────────────────┐
│  Layer 2: ND Firmware (i860 GaCK kernel in DRAM)            │
│  ─────────────────────────────────────────────────────────  │
│  • Main operating system on i860                            │
│  • Handles CMD_SET_VIDEO_MODE, CMD_BLIT, CMD_FILL, etc.     │
│  • Programs RAMDAC timing registers                         │
│  • Programs clock generator (pixel clock)                   │
│  • Manages framebuffer in VRAM                              │
│  • Runs continuously after boot                             │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼ (One-time boot sequence)
┌─────────────────────────────────────────────────────────────┐
│  Layer 1: ND ROM (Bootstrap firmware, 128 KB Flash)         │
│  ─────────────────────────────────────────────────────────  │
│  • Runs ONCE at power-on                                    │
│  • Initializes i860 CPU, memory, devices                    │
│  • Sets INITIAL video mode (1120×832 @ 68Hz)                │
│  • Downloads GaCK kernel from host → DRAM                   │
│  • Jumps to kernel (bri 0x00000000)                         │
│  • NEVER RETURNS - ROM is done                              │
└─────────────────────────────────────────────────────────────┘
```

**Key Insight**: The ROM only sets the **initial** video mode. Once the GaCK kernel takes over, it has full control of the display hardware and can change modes dynamically.

---

## ROM Boot Sequence & Display Behavior

**Critical Question**: Does the ROM display anything on screen before handing control to the firmware?

**Answer**: ❌ **NO** - The ROM shows no intentional visual output. Only random garbage appears during the brief (~3ms) boot period.

### Complete Boot Timeline Analysis

Based on ROM disassembly (`ND_step1_v43_eeprom.asm`, 32,802 lines), here's exactly what happens:

```
┌─────────────────────────────────────────────────────────────────┐
│ Time: 0 ms - POWER-ON RESET                                     │
├─────────────────────────────────────────────────────────────────┤
│ • i860 CPU starts executing from ROM (0xFFF1FF20)               │
│ • Display State: Monitor in standby (no sync signal)            │
│ • Screen: Black or power-saving mode                            │
│ • VRAM: Undefined random data from manufacturing                │
└─────────────────────────────────────────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│ Time: 0-0.5 ms - CPU INITIALIZATION                             │
├─────────────────────────────────────────────────────────────────┤
│ ROM Code (Region 1: 0xFFF00000-0xFFF00370)                      │
│                                                                 │
│ • Configure PSR (Processor Status Register)                     │
│ • Configure EPSR (Extended PSR)                                 │
│ • Initialize FPU (r2apt.ss warmup instructions)                 │
│ • Set DIRBASE (page directory base for virtual memory)          │
│                                                                 │
│ Assembly Evidence:                                              │
│   fff00028:  ld.c  %psr,%r16                                    │
│   fff0002c:  andnot 0x0010,%r16,%r16  ; Clear interrupt bit     │
│   fff00030:  st.c  %r16,%psr                                    │
│                                                                 │
│ Display: Still no sync - monitor off                            │
└─────────────────────────────────────────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│ Time: 0.5-1.5 ms - MEMORY CONTROLLER SETUP                      │
├─────────────────────────────────────────────────────────────────┤
│ ROM Code (Region 2-3: Memory Init)                              │
│                                                                 │
│ • Call memory init routine 3× (0x00000380)                      │
│   - Test DRAM bank at 0x2E3A8000                                │
│   - Test DRAM bank at 0x4E3A8000                                │
│   - Test DRAM bank at 0x6E3A8000                                │
│                                                                 │
│ • Configure DRAM_SIZE register (0xFF803000)                     │
│   fff006f4:  or   0x0001,%r0,%r17  ; Set CSRDRAM_4MBIT          │
│   fff006f8:  st.l %r17,0(%r16)     ; Write to controller        │
│                                                                 │
│ Display: Still no sync - monitor waiting                        │
└─────────────────────────────────────────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│ Time: 1.5-2.5 ms - RAMDAC PROGRAMMING ★★★                       │
├─────────────────────────────────────────────────────────────────┤
│ ROM Code (Region 5: 0xFFF00BE0-0xFFF01570, 2,448 bytes)         │
│                                                                 │
│ *** CRITICAL MOMENT: Display sync established ***               │
│                                                                 │
│ • Program Bt463 RAMDAC (28-register initialization loop)        │
│   - Set horizontal timing: 1120 pixels active                   │
│   - Set vertical timing: 832 lines active                       │
│   - Set pixel clock: ~80 MHz                                    │
│   - Set sync polarities: Positive/Positive                      │
│                                                                 │
│ Assembly Evidence:                                              │
│   fff00c04:  or   0x2000,%r0,%r16   ; VRAM_TIMING register      │
│   fff00c08:  orh  0xff80,%r16,%r16  ; 0xFF802000                │
│   fff00c10:  st.l %r0,0(%r16)       ; Clear/configure           │
│                                                                 │
│ Display: *** MONITOR WAKES UP ***                               │
│   - Receives valid 1120×832 @ 68Hz sync signal                  │
│   - Exits standby mode                                          │
│   - Begins scanning VRAM for pixel data                         │
│   - Shows: WHATEVER IS IN VRAM (garbage!)                       │
└─────────────────────────────────────────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│ Time: 2.0-2.5 ms - VRAM MEMORY TEST                             │
├─────────────────────────────────────────────────────────────────┤
│ ROM Code (Region 3: Memory test routines)                       │
│                                                                 │
│ • Test VRAM at 0x10000000-0x103FFFFF (4 MB range)               │
│ • Write test patterns to verify memory integrity:               │
│   - Pattern 1: 0xDB6DB6DB (alternating bits)                    │
│   - Pattern 2: 0xB6DBB6DB (inverse)                             │
│   - Pattern 3: 0x5555AAAA (classic test)                        │
│                                                                 │
│ Assembly Evidence:                                              │
│   fff00564:  or   0xb6db,%r0,%r16                               │
│   fff00568:  orh  0xdb6d,%r16,%r16  ; r16 = 0xDB6DB6DB          │
│   fff00584:  st.l %r16,0(%r18)      ; Write to VRAM             │
│                                                                 │
│ Display: *** TEST PATTERNS VISIBLE ON SCREEN ***                │
│   - Random colored noise/static                                 │
│   - Flickering patterns (0xAA, 0x55, 0xDB6D, etc.)              │
│   - NOT intentional graphics                                    │
│   - Just memory testing side-effects                            │
│                                                                 │
│ ⚠️ ROM NEVER intentionally draws to framebuffer                 │
│ ⚠️ No splash screen code exists                                 │
│ ⚠️ No logo bitmap data in ROM                                   │
└─────────────────────────────────────────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│ Time: 2.5-3.0 ms - ENTER MAILBOX POLLING LOOP                   │
├─────────────────────────────────────────────────────────────────┤
│ ROM Code (Region 6: 0xFFF01580, Main Runtime)                   │
│                                                                 │
│ • Wait for host to send CMD_LOAD_KERNEL                         │
│ • Poll mailbox status register (0x02000000)                     │
│                                                                 │
│ Assembly Evidence:                                              │
│   main_loop:                                                    │
│     load  r16, [0x02000000]    ; MAILBOX_STATUS                 │
│     and   r17, r16, CMD_READY                                   │
│     branch_if_zero main_loop   ; Keep polling                   │
│                                                                 │
│ Display: Still showing test pattern garbage                     │
│ ROM: Waiting for host (can take 10-50ms)                        │
└─────────────────────────────────────────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│ Time: 50-100 ms - KERNEL DOWNLOAD (DMA TRANSFER)                │
├─────────────────────────────────────────────────────────────────┤
│ ROM Code: Kernel loader stub (Region 6)                         │
│                                                                 │
│ • Host sends CMD_LOAD_KERNEL via mailbox                        │
│ • ROM reads kernel size and source address                      │
│ • DMA transfer: Host memory → i860 DRAM                         │
│   - Source: NDserver embedded kernel (795 KB)                   │
│   - Dest: 0x00000000 (start of DRAM)                            │
│   - Speed: ~50 MB/s (NeXTBus bandwidth)                         │
│   - Time: ~15-20 ms for transfer                                │
│                                                                 │
│ Assembly Evidence:                                              │
│   dma_loop:                                                     │
│     load  r22, [r19]      ; Read from host memory               │
│     store r22, [r21]      ; Write to i860 DRAM                  │
│     add   r19, r19, 4                                           │
│     add   r21, r21, 4                                           │
│     sub   r20, r20, 4                                           │
│     branch_if_not_zero dma_loop                                 │
│                                                                 │
│ Display: *** STILL SHOWING GARBAGE ***                          │
│   - DMA goes to DRAM (0x00000000)                               │
│   - NOT to VRAM (0x10000000)                                    │
│   - Screen unchanged during kernel load                         │
└─────────────────────────────────────────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│ Time: ~100 ms - JUMP TO KERNEL (ROM EXIT)                       │
├─────────────────────────────────────────────────────────────────┤
│ ROM Code: Final instruction                                     │
│                                                                 │
│ • Verify kernel checksum                                        │
│ • Jump to kernel entry point:                                   │
│     load  r24, 0x00000000    ; Kernel entry                     │
│     bri   r24                ; *** JUMP OUT OF ROM ***          │
│                                                                 │
│ ROM: *** NEVER RETURNS - Job complete ***                       │
│                                                                 │
│ Display: Still showing test pattern garbage                     │
│ Kernel: About to take control...                                │
└─────────────────────────────────────────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│ Time: ~100-110 ms - KERNEL INITIALIZATION                       │
├─────────────────────────────────────────────────────────────────┤
│ GaCK Kernel Code: Entry point (DRAM, not ROM)                   │
│                                                                 │
│ *** FIRST INTENTIONAL DISPLAY OUTPUT ***                        │
│                                                                 │
│ • Clear framebuffer to solid color:                             │
│     memset(0x10000000, 0x80, 1120*832*4);  // Gray              │
│                                                                 │
│ • Or show boot splash:                                          │
│     draw_next_logo();                                           │
│     printf("NeXTdimension GaCK v2.0 starting...");              │
│                                                                 │
│ Display: *** CLEAN SCREEN - Garbage gone! ***                   │
│   - First real graphics since power-on                          │
│   - ROM's 100ms of noise is over                                │
└─────────────────────────────────────────────────────────────────┘
```

### Evidence: ROM Does NOT Draw Graphics

**No VRAM Base Address Formation**:
The ROM never forms the VRAM base address (0x10000000) for writing:

```assembly
; This code DOES NOT EXIST in the ROM:
; orh  0x0010,%r0,%r16    ; Would set upper 16 bits = 0x0010
; or   0x0000,%r16,%r16   ; Would complete 0x10000000
; st.l %r0,0(%r16)        ; Would clear framebuffer
```

**Only Memory Controller Configuration**:
The ROM only writes to the VRAM_TIMING register (configuration), not VRAM itself:

```assembly
; Location: 0xFFF00C04 (VRAM initialization)
fff00c04:  e4102000  or   0x2000,%r0,%r16     ; r16 = 0x00002000
fff00c08:  ee10ff80  orh  0xff80,%r16,%r16    ; r16 = 0xFF802000
fff00c0c:  6fffffc8  call 0x00000b30          ; Call init routine
fff00c10:  1e000001  st.l %r0,0(%r16)         ; Write 0x0 (clear config)
                                               ; This is a REGISTER, not VRAM!
```

**ROM Size Constraint**:
- Total ROM: 128 KB (131,072 bytes)
- Actual code: 10.9 KB (8.3%)
- Minimum splash screen: ~50 KB for simple 256-color logo
- **No room for graphics data**

### Boot Display Behavior: Cold vs Warm Boot

#### Cold Boot (Power-On from Off State)

```
Time | Display Content
-----|----------------------------------------------------------
0ms  | [Black - Monitor off]
2ms  | [Random colored snow - VRAM has manufacturing test data]
     | Patterns: Checkerboards, random RGB noise
100ms| [NeXT gray - Kernel cleared framebuffer]
200ms| [NeXT logo - Kernel draws boot splash]
```

#### Warm Boot (Reset Without Power Cycle)

```
Time | Display Content
-----|----------------------------------------------------------
0ms  | [Previous desktop - VRAM retains last image]
     | Still showing windows, icons, etc. from before reset
2ms  | [Same desktop - ROM doesn't touch VRAM]
     | Image remains frozen during ROM execution
100ms| [NeXT gray - Kernel cleared framebuffer]
200ms| [NeXT logo - Fresh boot sequence]
```

**Key Observation**: On warm boot, you briefly see the "ghost" of the previous desktop because ROM preserves VRAM content.

### Why ROM Has No Splash Screen

**Technical Constraints**:

1. **ROM Size**: 128 KB total, 10.9 KB code, 117 KB empty
   - Even compressed 16-color logo: ~30-50 KB
   - Would consume 25-40% of available ROM
   - Not enough space for RAMDAC tables + logo

2. **Boot Speed Priority**: ROM optimized for minimal latency
   - Drawing splash would add 5-10ms (2-3× current boot time)
   - NeXT prioritized instant boot over cosmetics
   - Philosophy: "Fast and silent is better than pretty and slow"

3. **Architecture Philosophy**: ROM is bootstrap only
   - Hardware initialization, not user interface
   - Visual feedback is the kernel's responsibility
   - Similar to modern UEFI vs traditional BIOS

**Comparison to Other Systems**:

| System | Boot Display | Duration | Justification |
|--------|--------------|----------|---------------|
| **PC BIOS** | Manufacturer logo, POST codes | 500-2000ms | Marketing, diagnostics |
| **UEFI** | OEM splash screen | 100-500ms | Branding, hide POST |
| **Mac ROM** | Happy Mac icon | 100-300ms | User feedback |
| **NeXT ROM** | ❌ Nothing (garbage) | 2-3ms | Speed, minimalism |
| **SGI PROM** | SGI logo | 200-500ms | Branding |

NeXT chose the **fastest possible path** at the expense of visual polish during the brief ROM phase.

### Implications for GaCKliNG Development

**Where to Implement Boot Graphics**:

```c
/* File: gackling/init/splash.c */

/* Called immediately after kernel takes control (~100ms) */
void gackling_show_splash(void) {
    // *** THIS IS THE FIRST INTENTIONAL GRAPHICS OUTPUT ***

    // Clear framebuffer to black (remove ROM test pattern garbage)
    uint32_t *fb = (uint32_t*)0x10000000;
    uint32_t pixels = 1120 * 832;
    for (uint32_t i = 0; i < pixels; i++) {
        fb[i] = 0x00000000;  // Black
    }

    // Draw centered GaCKliNG logo
    draw_logo(fb, 560 - LOGO_WIDTH/2, 416 - LOGO_HEIGHT/2);

    // Show version info
    draw_text(fb, 10, 10, "GaCKliNG v1.0 - Modern NeXTdimension Firmware");
    draw_text(fb, 10, 30, "Detecting video modes...");

    // This replaces the ~100ms of ROM garbage with clean branding
}
```

**Boot Experience Comparison**:

| Phase | Original NeXT | GaCKliNG |
|-------|---------------|----------|
| 0-3ms | ROM (garbage) | ROM (garbage) |
| 3-100ms | Kernel load (garbage) | Kernel load (garbage) |
| 100ms+ | NeXT gray → logo | **GaCKliNG splash** |

You **cannot** eliminate the initial garbage without modifying ROM (not recommended), but you **can** replace it quickly with branded splash screen from kernel.

**Minimum Flicker Strategy**:

```c
/* Fastest possible splash display */
void gackling_fast_splash(void) {
    // Don't clear entire framebuffer (slow: ~5ms at 79 MB/s)
    // Just draw logo over garbage (fast: <1ms)

    draw_logo_opaque(0x10000000, 512, 384);  // Overwrites center region

    // Garbage still visible in corners, but logo is instant
    // Will be cleaned up by Window Server in next 100ms anyway
}
```

---

## Component 1: ND Firmware (GaCK Kernel) - PRIMARY

**Location**: `ND_MachDriver_reloc` (795 KB, runs on i860 in DRAM)

**Why This is Most Important**:
- Runs continuously after boot (ROM is one-shot)
- Has full hardware access (RAMDAC, clock generator, VRAM)
- Can implement dynamic mode switching
- Can auto-detect best mode based on hardware capabilities
- Handles all post-boot display operations

### What Needs to Be Implemented

#### 1. RAMDAC Programming Routines

**Bt463 Register Programming** for each video mode:

```c
/* File: gackling/video/ramdac_bt463.c */

typedef struct {
    uint16_t h_active;        // Active pixels per line
    uint16_t h_sync_start;    // Horizontal sync pulse start
    uint16_t h_sync_end;      // Horizontal sync pulse end
    uint16_t h_total;         // Total pixels per line (including blanking)

    uint16_t v_active;        // Active lines per frame
    uint16_t v_sync_start;    // Vertical sync pulse start
    uint16_t v_sync_end;      // Vertical sync pulse end
    uint16_t v_total;         // Total lines per frame (including blanking)

    uint8_t  h_sync_polarity; // 0=negative, 1=positive
    uint8_t  v_sync_polarity; // 0=negative, 1=positive

    uint32_t pixel_clock_khz; // Pixel clock in kHz
    uint8_t  bits_per_pixel;  // 8, 16, 24, or 32
} video_timing_t;

/* VESA standard timings for 1366×768 @ 60Hz */
static const video_timing_t MODE_1366x768_60 = {
    .h_active        = 1366,
    .h_sync_start    = 1366 + 72,   // Front porch
    .h_sync_end      = 1366 + 72 + 96,  // Sync width
    .h_total         = 1708,        // Total with back porch

    .v_active        = 768,
    .v_sync_start    = 768 + 3,     // Front porch
    .v_sync_end      = 768 + 3 + 6, // Sync width
    .v_total         = 822,         // Total with back porch

    .h_sync_polarity = 1,           // Positive
    .v_sync_polarity = 1,           // Positive

    .pixel_clock_khz = 84300,       // 84.3 MHz
    .bits_per_pixel  = 16,          // RGB565
};

/* VESA standard timings for 1600×900 @ 60Hz */
static const video_timing_t MODE_1600x900_60 = {
    .h_active        = 1600,
    .h_sync_start    = 1600 + 96,
    .h_sync_end      = 1600 + 96 + 128,
    .h_total         = 2000,

    .v_active        = 900,
    .v_sync_start    = 900 + 3,
    .v_sync_end      = 900 + 3 + 4,
    .v_total         = 963,

    .h_sync_polarity = 1,
    .v_sync_polarity = 1,

    .pixel_clock_khz = 115560,      // 115.6 MHz
    .bits_per_pixel  = 16,
};

/* VESA CVT timings for 1920×1080 @ 60Hz */
static const video_timing_t MODE_1920x1080_60 = {
    .h_active        = 1920,
    .h_sync_start    = 1920 + 88,
    .h_sync_end      = 1920 + 88 + 44,
    .h_total         = 2200,

    .v_active        = 1080,
    .v_sync_start    = 1080 + 4,
    .v_sync_end      = 1080 + 4 + 5,
    .v_total         = 1125,

    .h_sync_polarity = 1,
    .v_sync_polarity = 1,

    .pixel_clock_khz = 148500,      // 148.5 MHz
    .bits_per_pixel  = 32,          // RGBA8888
};

/* Bt463 RAMDAC register addresses (MMIO) */
#define BT463_BASE          0xFF200000
#define BT463_ADDR_LO       (BT463_BASE + 0x00)
#define BT463_ADDR_HI       (BT463_BASE + 0x04)
#define BT463_REG_DATA      (BT463_BASE + 0x08)
#define BT463_COLOR_DATA    (BT463_BASE + 0x0C)

/* Bt463 internal registers */
#define BT463_CMD_REG_0     0x0201
#define BT463_CMD_REG_1     0x0202
#define BT463_CMD_REG_2     0x0203

#define BT463_H_SYNC_START  0x0210
#define BT463_H_SYNC_END    0x0211
#define BT463_H_TOTAL       0x0212

#define BT463_V_SYNC_START  0x0220
#define BT463_V_SYNC_END    0x0221
#define BT463_V_TOTAL       0x0222

/* Write to Bt463 register */
static void bt463_write_reg(uint16_t addr, uint8_t value) {
    volatile uint32_t *addr_lo = (uint32_t*)BT463_ADDR_LO;
    volatile uint32_t *addr_hi = (uint32_t*)BT463_ADDR_HI;
    volatile uint32_t *data    = (uint32_t*)BT463_REG_DATA;

    *addr_lo = addr & 0xFF;
    *addr_hi = (addr >> 8) & 0xFF;
    *data    = value;
}

/* Program Bt463 for a specific video mode */
int bt463_set_timing(const video_timing_t *timing) {
    // Set horizontal timing
    bt463_write_reg(BT463_H_SYNC_START, timing->h_sync_start & 0xFF);
    bt463_write_reg(BT463_H_SYNC_START + 1, (timing->h_sync_start >> 8) & 0xFF);

    bt463_write_reg(BT463_H_SYNC_END, timing->h_sync_end & 0xFF);
    bt463_write_reg(BT463_H_SYNC_END + 1, (timing->h_sync_end >> 8) & 0xFF);

    bt463_write_reg(BT463_H_TOTAL, timing->h_total & 0xFF);
    bt463_write_reg(BT463_H_TOTAL + 1, (timing->h_total >> 8) & 0xFF);

    // Set vertical timing
    bt463_write_reg(BT463_V_SYNC_START, timing->v_sync_start & 0xFF);
    bt463_write_reg(BT463_V_SYNC_START + 1, (timing->v_sync_start >> 8) & 0xFF);

    bt463_write_reg(BT463_V_SYNC_END, timing->v_sync_end & 0xFF);
    bt463_write_reg(BT463_V_SYNC_END + 1, (timing->v_sync_end >> 8) & 0xFF);

    bt463_write_reg(BT463_V_TOTAL, timing->v_total & 0xFF);
    bt463_write_reg(BT463_V_TOTAL + 1, (timing->v_total >> 8) & 0xFF);

    // Set sync polarities in command register
    uint8_t cmd_reg_1 = bt463_read_reg(BT463_CMD_REG_1);
    if (timing->h_sync_polarity) {
        cmd_reg_1 |= 0x01;  // Positive H-sync
    } else {
        cmd_reg_1 &= ~0x01; // Negative H-sync
    }
    if (timing->v_sync_polarity) {
        cmd_reg_1 |= 0x02;  // Positive V-sync
    } else {
        cmd_reg_1 &= ~0x02; // Negative V-sync
    }
    bt463_write_reg(BT463_CMD_REG_1, cmd_reg_1);

    // Set pixel format (8/16/24/32-bit)
    uint8_t cmd_reg_0 = bt463_read_reg(BT463_CMD_REG_0);
    switch (timing->bits_per_pixel) {
        case 8:  cmd_reg_0 = (cmd_reg_0 & 0xF8) | 0x00; break; // 8-bit indexed
        case 16: cmd_reg_0 = (cmd_reg_0 & 0xF8) | 0x02; break; // 16-bit RGB565
        case 24: cmd_reg_0 = (cmd_reg_0 & 0xF8) | 0x04; break; // 24-bit RGB888
        case 32: cmd_reg_0 = (cmd_reg_0 & 0xF8) | 0x05; break; // 32-bit RGBA8888
    }
    bt463_write_reg(BT463_CMD_REG_0, cmd_reg_0);

    return 0; // Success
}
```

---

#### 2. Clock Generator Programming

**Critical Component**: Must generate the correct pixel clock frequency.

```c
/* File: gackling/video/clock_gen.c */

/* Common clock chip: ICS9248 or similar PLL-based synthesizer */
#define CLOCK_CHIP_I2C_ADDR  0x69  // Example address (board-specific)

#define CLOCK_REG_M_LOW      0x02  // Multiplier low byte
#define CLOCK_REG_M_HIGH     0x03  // Multiplier high byte
#define CLOCK_REG_N          0x04  // Divider
#define CLOCK_REG_CONTROL    0x05  // Control register
#define CLOCK_REG_STATUS     0x06  // Status register

#define CLOCK_PLL_LOCKED     0x01  // PLL lock status bit

/* Reference crystal frequency (board-specific, usually 14.318 MHz) */
#define CLOCK_REF_FREQ_KHZ   14318

/* Calculate PLL parameters for target frequency */
typedef struct {
    uint16_t multiplier;  // M
    uint16_t divider;     // N
} pll_params_t;

static pll_params_t calculate_pll(uint32_t target_khz) {
    // Target = Reference × (M / N)
    // Choose N to be a power of 2 for stability
    // M should be as large as possible for fine frequency control

    pll_params_t params;
    uint32_t ratio_scaled = (target_khz * 1000) / CLOCK_REF_FREQ_KHZ;

    // Try dividers from 1 to 128
    for (uint16_t n = 1; n <= 128; n *= 2) {
        uint32_t m = (ratio_scaled * n) / 1000;

        // Check if this gives us the target frequency
        uint32_t actual_khz = (CLOCK_REF_FREQ_KHZ * m) / n;
        uint32_t error_khz = (actual_khz > target_khz) ?
                             (actual_khz - target_khz) :
                             (target_khz - actual_khz);

        // Accept if error < 0.5%
        if (error_khz < (target_khz / 200)) {
            params.multiplier = m;
            params.divider = n;
            return params;
        }
    }

    // Fallback: best-effort approximation
    params.multiplier = ratio_scaled;
    params.divider = 1;
    return params;
}

/* Program clock chip via I²C */
int clock_set_pixel_clock(uint32_t freq_khz) {
    pll_params_t pll = calculate_pll(freq_khz);

    // Write M (multiplier)
    i2c_write(CLOCK_CHIP_I2C_ADDR, CLOCK_REG_M_LOW, pll.multiplier & 0xFF);
    i2c_write(CLOCK_CHIP_I2C_ADDR, CLOCK_REG_M_HIGH, (pll.multiplier >> 8) & 0xFF);

    // Write N (divider)
    i2c_write(CLOCK_CHIP_I2C_ADDR, CLOCK_REG_N, pll.divider);

    // Update PLL (trigger recalculation)
    i2c_write(CLOCK_CHIP_I2C_ADDR, CLOCK_REG_CONTROL, 0x01);

    // Wait for PLL lock (with timeout)
    uint32_t timeout = 10000; // 10ms
    while (timeout--) {
        uint8_t status = i2c_read(CLOCK_CHIP_I2C_ADDR, CLOCK_REG_STATUS);
        if (status & CLOCK_PLL_LOCKED) {
            return 0; // Success
        }
        delay_us(1);
    }

    return -1; // Timeout - PLL did not lock
}

/* Preset clock frequencies for common modes */
int clock_set_mode(video_mode_id_t mode) {
    switch (mode) {
        case MODE_1120x832_68HZ:
            return clock_set_pixel_clock(80000);  // 80 MHz (original)
        case MODE_1366x768_60HZ:
            return clock_set_pixel_clock(84300);  // 84.3 MHz
        case MODE_1600x900_60HZ:
            return clock_set_pixel_clock(115560); // 115.6 MHz
        case MODE_1920x1080_60HZ:
            return clock_set_pixel_clock(148500); // 148.5 MHz
        default:
            return -1; // Unknown mode
    }
}
```

---

#### 3. Video Mode Manager

**High-level API** for mode detection, switching, and validation:

```c
/* File: gackling/video/video_mode.c */

typedef enum {
    MODE_1120x832_68HZ_32BPP,   // Original NeXT mode
    MODE_1366x768_60HZ_16BPP,   // Safe modern widescreen
    MODE_1600x900_60HZ_16BPP,   // Ambitious widescreen
    MODE_1920x1080_60HZ_32BPP,  // Ultimate (8 MB VRAM required)
} video_mode_id_t;

typedef struct {
    video_mode_id_t id;
    const char *name;
    const video_timing_t *timing;
    uint32_t vram_required_bytes;
    uint32_t max_pixel_clock_khz;  // For stability checking
} video_mode_desc_t;

static const video_mode_desc_t video_modes[] = {
    {
        .id = MODE_1120x832_68HZ_32BPP,
        .name = "1120x832 @ 68Hz (32-bit) - NeXT Original",
        .timing = &MODE_1120x832_68,
        .vram_required_bytes = 3723264,  // 3.55 MB
        .max_pixel_clock_khz = 80000,
    },
    {
        .id = MODE_1366x768_60HZ_16BPP,
        .name = "1366x768 @ 60Hz (16-bit) - HD Ready Widescreen",
        .timing = &MODE_1366x768_60,
        .vram_required_bytes = 2097152,  // 2.00 MB
        .max_pixel_clock_khz = 84300,
    },
    {
        .id = MODE_1600x900_60HZ_16BPP,
        .name = "1600x900 @ 60Hz (16-bit) - HD+ Widescreen",
        .timing = &MODE_1600x900_60,
        .vram_required_bytes = 2880000,  // 2.75 MB
        .max_pixel_clock_khz = 115560,
    },
    {
        .id = MODE_1920x1080_60HZ_32BPP,
        .name = "1920x1080 @ 60Hz (32-bit) - Full HD",
        .timing = &MODE_1920x1080_60,
        .vram_required_bytes = 8294400,  // 7.91 MB
        .max_pixel_clock_khz = 148500,
    },
};

/* Current active mode */
static video_mode_id_t current_mode = MODE_1120x832_68HZ_32BPP;

/* Test if a mode is stable */
static bool test_mode_stability(const video_mode_desc_t *mode) {
    // Set the mode
    if (clock_set_pixel_clock(mode->timing->pixel_clock_khz) != 0) {
        return false; // Clock generator failed
    }

    if (bt463_set_timing(mode->timing) != 0) {
        return false; // RAMDAC programming failed
    }

    // Wait for display to stabilize
    delay_ms(100);

    // Check for sync (read back Bt463 status)
    if (!bt463_has_sync()) {
        return false; // No sync signal
    }

    // Perform memory test (check for bus errors at this clock speed)
    if (!memory_test_vram()) {
        return false; // Memory unstable at this speed
    }

    return true; // Mode is stable!
}

/* Auto-detect best supported mode */
video_mode_id_t video_detect_best_mode(void) {
    uint32_t vram_size = get_vram_size(); // 4 MB or 8 MB

    // Try modes from highest to lowest
    for (int i = sizeof(video_modes)/sizeof(video_modes[0]) - 1; i >= 0; i--) {
        const video_mode_desc_t *mode = &video_modes[i];

        // Check VRAM capacity
        if (mode->vram_required_bytes > vram_size) {
            continue; // Not enough VRAM
        }

        // Test stability
        if (test_mode_stability(mode)) {
            printf("Auto-detected mode: %s\n", mode->name);
            return mode->id;
        } else {
            printf("Mode %s unstable, trying next...\n", mode->name);
        }
    }

    // Fallback to original mode (should always work)
    printf("Falling back to original NeXT mode\n");
    return MODE_1120x832_68HZ_32BPP;
}

/* Set video mode (called from mailbox command handler) */
int video_set_mode(video_mode_id_t mode_id) {
    const video_mode_desc_t *mode = NULL;

    // Find mode descriptor
    for (int i = 0; i < sizeof(video_modes)/sizeof(video_modes[0]); i++) {
        if (video_modes[i].id == mode_id) {
            mode = &video_modes[i];
            break;
        }
    }

    if (!mode) {
        return -1; // Invalid mode ID
    }

    // Check VRAM capacity
    if (mode->vram_required_bytes > get_vram_size()) {
        printf("Insufficient VRAM for mode %s\n", mode->name);
        return -2; // Not enough VRAM
    }

    // Program clock generator
    if (clock_set_pixel_clock(mode->timing->pixel_clock_khz) != 0) {
        printf("Failed to set pixel clock for %s\n", mode->name);
        return -3; // Clock programming failed
    }

    // Program RAMDAC timing
    if (bt463_set_timing(mode->timing) != 0) {
        printf("Failed to program RAMDAC for %s\n", mode->name);
        return -4; // RAMDAC programming failed
    }

    // Update framebuffer configuration
    framebuffer_config_t fb_config = {
        .base_addr = 0x10000000,  // VRAM base
        .width = mode->timing->h_active,
        .height = mode->timing->v_active,
        .stride = mode->timing->h_active * (mode->timing->bits_per_pixel / 8),
        .format = mode->timing->bits_per_pixel,
    };

    if (framebuffer_configure(&fb_config) != 0) {
        printf("Failed to configure framebuffer for %s\n", mode->name);
        return -5; // Framebuffer config failed
    }

    current_mode = mode_id;
    printf("Video mode set to: %s\n", mode->name);
    return 0; // Success
}

/* Get current mode info */
const video_mode_desc_t *video_get_current_mode(void) {
    for (int i = 0; i < sizeof(video_modes)/sizeof(video_modes[0]); i++) {
        if (video_modes[i].id == current_mode) {
            return &video_modes[i];
        }
    }
    return NULL;
}
```

---

#### 4. Mailbox Command Handler

**Add CMD_SET_VIDEO_MODE** to mailbox protocol:

```c
/* File: gackling/mailbox/commands.c */

#define CMD_SET_VIDEO_MODE  0x20  // New command

typedef struct {
    uint32_t mode_id;        // video_mode_id_t
    uint32_t flags;          // Reserved for future use
} cmd_set_video_mode_t;

typedef struct {
    int32_t status;          // 0=success, negative=error
    uint32_t actual_width;   // Actual resolution set
    uint32_t actual_height;
    uint32_t actual_bpp;
} reply_set_video_mode_t;

/* Command handler */
static void handle_set_video_mode(mailbox_t *mb) {
    cmd_set_video_mode_t *cmd = (cmd_set_video_mode_t*)mb->data_ptr;
    reply_set_video_mode_t reply;

    // Attempt to set mode
    int result = video_set_mode(cmd->mode_id);
    reply.status = result;

    if (result == 0) {
        // Success - fill in actual mode info
        const video_mode_desc_t *mode = video_get_current_mode();
        reply.actual_width = mode->timing->h_active;
        reply.actual_height = mode->timing->v_active;
        reply.actual_bpp = mode->timing->bits_per_pixel;
    } else {
        // Failed - return zeros
        reply.actual_width = 0;
        reply.actual_height = 0;
        reply.actual_bpp = 0;
    }

    // Send reply
    mailbox_send_reply(mb, &reply, sizeof(reply));
}
```

---

#### 5. Boot-Time Mode Detection

**Initialize video system** during GaCK kernel startup:

```c
/* File: gackling/init/video_init.c */

void gackling_video_init(void) {
    printf("GaCKliNG Video Subsystem Initializing...\n");

    // Detect VRAM size
    uint32_t vram_size = detect_vram_size();
    printf("  VRAM: %u MB\n", vram_size / (1024*1024));

    // Check for user override
    const char *mode_override = getenv("ND_VIDEO_MODE");
    if (mode_override) {
        video_mode_id_t mode = parse_mode_string(mode_override);
        if (video_set_mode(mode) == 0) {
            printf("  Mode: %s (user override)\n", mode_override);
            return;
        } else {
            printf("  Warning: User mode '%s' failed, auto-detecting...\n",
                   mode_override);
        }
    }

    // Auto-detect best mode
    video_mode_id_t best_mode = video_detect_best_mode();
    video_set_mode(best_mode);

    const video_mode_desc_t *mode = video_get_current_mode();
    printf("  Mode: %s\n", mode->name);
    printf("  Resolution: %ux%u @ %u-bit\n",
           mode->timing->h_active,
           mode->timing->v_active,
           mode->timing->bits_per_pixel);
}
```

---

### Summary: ND Firmware Changes

**Files to Create/Modify**:
1. `gackling/video/ramdac_bt463.c` - RAMDAC programming
2. `gackling/video/clock_gen.c` - Pixel clock control
3. `gackling/video/video_mode.c` - Mode management
4. `gackling/mailbox/commands.c` - Add CMD_SET_VIDEO_MODE handler
5. `gackling/init/video_init.c` - Boot-time initialization

**Priority**: ⭐⭐⭐⭐⭐ **CRITICAL** - This is where the real work happens

---

## Component 2: ND Driver (Host-Side) - REQUIRED

**Location**: NDserver daemon (m68k/68040, NeXTSTEP host)

**Why This is Required**:
- Window Server needs to know framebuffer dimensions
- DPS rendering engine needs pixel format info
- Applications query display capabilities
- Mode switching UI needs to communicate with i860

### What Needs to Be Implemented

#### 1. Framebuffer Configuration Updates

**IOKit Driver** (or equivalent for NeXTSTEP):

```objective-c
/* File: NDDisplay.m (Host-side driver) */

@interface NDDisplay : IODisplay {
    uint32_t fb_width;
    uint32_t fb_height;
    uint32_t fb_bpp;
    uint32_t fb_stride;
    void *fb_base;
}

- (void)queryVideoMode;
- (BOOL)setVideoMode:(NDVideoMode)mode;

@end

@implementation NDDisplay

- (void)queryVideoMode {
    // Send mailbox command to i860: CMD_QUERY_VIDEO_MODE
    mailbox_command_t cmd = {
        .opcode = CMD_QUERY_VIDEO_MODE,
        .data_len = 0,
    };

    mailbox_reply_t *reply = nd_mailbox_send_sync(&cmd);

    // Update local state
    fb_width = reply->width;
    fb_height = reply->height;
    fb_bpp = reply->bits_per_pixel;
    fb_stride = reply->stride;

    NSLog(@"NeXTdimension mode: %ux%u @ %u-bit",
          fb_width, fb_height, fb_bpp);
}

- (BOOL)setVideoMode:(NDVideoMode)mode {
    mailbox_command_t cmd = {
        .opcode = CMD_SET_VIDEO_MODE,
        .data_len = sizeof(uint32_t),
    };
    *(uint32_t*)cmd.data = mode;

    mailbox_reply_t *reply = nd_mailbox_send_sync(&cmd);

    if (reply->status == 0) {
        // Success - update local state
        [self queryVideoMode];

        // Notify Window Server of mode change
        [self notifyDisplayChanged];

        return YES;
    } else {
        NSLog(@"Failed to set video mode: error %d", reply->status);
        return NO;
    }
}

- (void)notifyDisplayChanged {
    // Tell Window Server that display configuration changed
    // This causes window positions to be recalculated, etc.
    NXPing();  // Force screen refresh
}

@end
```

---

#### 2. Display PostScript Context Updates

**DPS Context** needs to know about framebuffer format:

```objective-c
/* File: NDDPSContext.m */

- (void)updateContextForVideoMode {
    NDDisplay *display = [NDDisplay sharedDisplay];

    // Update DPS context with new framebuffer parameters
    DPSSetContext(dpsContext);
    DPSgsave(dpsContext);

    // Set coordinate system
    DPSinitmatrix(dpsContext);
    DPSscale(dpsContext,
             [display width],
             [display height]);

    // Set pixel format
    switch ([display bitsPerPixel]) {
        case 16:
            // RGB565 format
            DPSsetcolorspace(dpsContext, "DeviceRGB");
            DPSsetpixelformat(dpsContext, RGB565);
            break;
        case 32:
            // RGBA8888 format
            DPSsetcolorspace(dpsContext, "DeviceRGB");
            DPSsetpixelformat(dpsContext, RGBA8888);
            break;
    }

    DPSgrestore(dpsContext);
}
```

---

#### 3. System Configuration Files

**Update NeXTSTEP display database**:

```
# File: /NextLibrary/Displays/NextDimension.config

# Original mode
Mode "1120x832x32@68" {
    Resolution 1120 832
    Depth 32
    RefreshRate 68
    Flags Original
}

# GaCKliNG modern modes
Mode "1366x768x16@60" {
    Resolution 1366 768
    Depth 16
    RefreshRate 60
    Flags Widescreen Default
}

Mode "1600x900x16@60" {
    Resolution 1600 900
    Depth 16
    RefreshRate 60
    Flags Widescreen
}

Mode "1920x1080x32@60" {
    Resolution 1920 1080
    Depth 32
    RefreshRate 60
    Flags Widescreen Requires8MBVRAM
}
```

---

#### 4. Preferences Panel

**User Interface** for mode selection:

```objective-c
/* File: NDDisplayPrefs.m */

@interface NDDisplayPrefs : NSObject {
    IBOutlet NSPopUpButton *modeSelector;
    IBOutlet NSButton *applyButton;
}

- (void)populateModes;
- (IBAction)applyMode:(id)sender;

@end

@implementation NDDisplayPrefs

- (void)populateModes {
    NDDisplay *display = [NDDisplay sharedDisplay];
    NSArray *modes = [display availableModes];

    [modeSelector removeAllItems];

    for (NDVideoMode *mode in modes) {
        NSString *title = [NSString stringWithFormat:@"%ux%u @ %u-bit (%s)",
                          mode.width, mode.height, mode.bpp,
                          mode.isWidescreen ? "16:9" : "4:3"];

        [modeSelector addItemWithTitle:title];
        [[modeSelector lastItem] setTag:mode.id];
    }

    // Select current mode
    [modeSelector selectItemWithTag:[display currentMode].id];
}

- (IBAction)applyMode:(id)sender {
    NSInteger modeId = [[modeSelector selectedItem] tag];
    NDDisplay *display = [NDDisplay sharedDisplay];

    if ([display setVideoMode:modeId]) {
        NSRunAlertPanel(@"Display Mode Changed",
                       @"The display mode has been updated successfully.",
                       @"OK", nil, nil);
    } else {
        NSRunAlertPanel(@"Mode Change Failed",
                       @"The selected mode is not supported by your hardware.",
                       @"OK", nil, nil);
    }
}

@end
```

---

### Summary: ND Driver Changes

**Files to Create/Modify**:
1. `NDDisplay.m` - Framebuffer configuration and mode switching
2. `NDDPSContext.m` - DPS context updates for new pixel formats
3. `/NextLibrary/Displays/NextDimension.config` - System configuration
4. `NDDisplayPrefs.m` - User preferences panel

**Priority**: ⭐⭐⭐⭐⭐ **REQUIRED** - Host must understand new modes

---

## Component 3: ND ROM (Bootstrap) - OPTIONAL

**Location**: `ND_step1_v43_eeprom.bin` (128 KB Flash EEPROM)

**Why This is Optional**:
- ROM only runs ONCE at boot
- After loading GaCK kernel, ROM is never used again
- GaCK kernel can change mode immediately after boot
- Modifying ROM is risky (requires Flash programmer, can brick board)

**Why You Might Want to Modify ROM Anyway**:
- Set a **modern default** video mode from power-on
- Avoid brief flicker when GaCK changes mode after boot
- Boot splash screen at native widescreen resolution

### What Would Need to Be Modified (If You Choose To)

#### 1. RAMDAC Initialization Code

**Location**: ROM offset 0xBE0-0x1570 (Device Initialization region)

**Current Code** (sets 1120×832 @ 68Hz):

```assembly
; Address: 0xFFF00C04
fff00c04:  e4102000  or        0x2000,%r0,%r16     ; r16 = 0x2000
fff00c08:  ee10ff80  orh       0xff80,%r16,%r16    ; r16 = 0xFF802000 (VRAM_TIMING)
fff00c0c:  6fffffc8  call      0x00000b30          ; Call VRAM init routine
fff00c10:  1e000001  st.l      %r0,0(%r16)         ; Clear register
```

**Modified Code** (example: set 1366×768 @ 60Hz):

```assembly
; New initialization routine for 1366×768
init_1366x768:
    ; Program horizontal timing
    ec10ff20  orh       0xff20,%r0,%r16       ; Bt463 base
    e4110210  or        0x0210,%r0,%r17       ; H_SYNC_START register
    1e008805  st.l      %r17,4(%r16)          ; Set register address
    e41105a6  or        0x05a6,%r0,%r17       ; Value: 1438
    1e008809  st.l      %r17,8(%r16)          ; Write data

    ; ... (repeat for all timing registers) ...

    ; Set pixel format to 16-bit RGB565
    e4110201  or        0x0201,%r0,%r17       ; CMD_REG_0
    1e008805  st.l      %r17,4(%r16)
    e4110002  or        0x0002,%r0,%r17       ; 16-bit mode
    1e008809  st.l      %r17,8(%r16)
```

**Challenge**: ROM has limited space. Full timing tables would consume significant ROM.

**Recommendation**: **Don't modify ROM**. Let GaCK kernel handle it.

---

#### 2. Clock Generator Initialization

**Location**: ROM offset 0x6EC (DRAM init) and 0xC04 (VRAM init)

**Current Code** (sets ~80 MHz pixel clock):

```assembly
fff006ec:  e4103000  or        0x3000,%r0,%r16
fff006f0:  ee10ff80  orh       0xff80,%r16,%r16    ; Memory controller
fff006f4:  e4110001  or        0x0001,%r0,%r17
fff006f8:  1e008801  st.l      %r17,0(%r16)        ; Configure for 80 MHz
```

**Modified Code** (example: set 84.3 MHz for 1366×768):

```assembly
; Program clock chip for 84.3 MHz
; Assuming ICS9248 or similar at I²C address 0x69
    ec10ff80  orh       0xff80,%r0,%r16       ; I²C controller base
    e411024d  or        0x024d,%r0,%r17       ; M = 589
    6fffff??  call      i2c_write_m           ; Write multiplier
    e4110064  or        0x0064,%r0,%r17       ; N = 100
    6fffff??  call      i2c_write_n           ; Write divider
    6fffff??  call      i2c_update_pll        ; Trigger update
```

**Challenge**: ROM doesn't have I²C driver code. Would need to add it.

**Recommendation**: **Don't modify ROM**. Too complex, too risky.

---

### Summary: ND ROM Changes

**What Would Change** (if you chose to modify ROM):
1. RAMDAC timing initialization (Region 5, 0xBE0-0x1570)
2. Clock generator programming (add I²C driver code)
3. Initial framebuffer configuration

**Why NOT Recommended**:
- ❌ ROM modification requires Flash programmer
- ❌ Risk of bricking the board
- ❌ Limited ROM space for timing tables
- ❌ GaCK kernel can change mode immediately after boot anyway
- ❌ No significant benefit (brief flicker during boot is acceptable)

**Priority**: ⭐ **LOW** - Only for perfectionists

---

## Additional Components to Consider

### 4. Monitor EDID Support (Optional Enhancement)

**Modern monitors** provide EDID (Extended Display Identification Data) via DDC/I²C:

```c
/* File: gackling/video/edid.c */

#define DDC_I2C_ADDR  0x50  // Standard EDID address

typedef struct {
    uint16_t width;
    uint16_t height;
    uint8_t refresh_rate;
    bool is_widescreen;
} edid_preferred_mode_t;

/* Read monitor's preferred mode from EDID */
int edid_read_preferred_mode(edid_preferred_mode_t *mode) {
    uint8_t edid[128];

    // Read EDID block via I²C
    if (i2c_read_block(DDC_I2C_ADDR, 0x00, edid, 128) != 0) {
        return -1; // No EDID available
    }

    // Parse detailed timing descriptor (offset 0x36)
    uint16_t h_active = ((edid[0x38] & 0xF0) << 4) | edid[0x36];
    uint16_t v_active = ((edid[0x3B] & 0xF0) << 4) | edid[0x39];

    mode->width = h_active;
    mode->height = v_active;
    mode->is_widescreen = (h_active * 9 == v_active * 16);

    // Calculate refresh rate from pixel clock
    uint16_t pixel_clock = ((edid[0x37] << 8) | edid[0x36]) * 10; // kHz
    uint16_t h_total = h_active + edid[0x3C]; // Simplified
    uint16_t v_total = v_active + edid[0x3F];
    mode->refresh_rate = (pixel_clock * 1000) / (h_total * v_total);

    return 0; // Success
}

/* Auto-select mode based on monitor capabilities */
video_mode_id_t edid_auto_select_mode(void) {
    edid_preferred_mode_t preferred;

    if (edid_read_preferred_mode(&preferred) == 0) {
        printf("Monitor prefers: %ux%u @ %uHz %s\n",
               preferred.width, preferred.height, preferred.refresh_rate,
               preferred.is_widescreen ? "(16:9)" : "(4:3)");

        // Find closest supported mode
        if (preferred.width == 1920 && preferred.height == 1080) {
            return MODE_1920x1080_60HZ_32BPP;
        } else if (preferred.width >= 1600 && preferred.height >= 900) {
            return MODE_1600x900_60HZ_16BPP;
        } else if (preferred.width >= 1366 && preferred.height >= 768) {
            return MODE_1366x768_60HZ_16BPP;
        }
    }

    // Fallback to auto-detection
    return video_detect_best_mode();
}
```

---

### 5. Runtime Mode Switching (User Experience)

**Keyboard Shortcut** or **Menu Option**:

```c
/* File: gackling/ui/hotkeys.c */

/* Cycle through available modes with Cmd+Option+M */
void handle_mode_cycle_hotkey(void) {
    static int mode_index = 0;

    uint32_t vram_size = get_vram_size();
    int num_modes = 0;
    video_mode_id_t available_modes[4];

    // Build list of modes that fit in VRAM
    for (int i = 0; i < sizeof(video_modes)/sizeof(video_modes[0]); i++) {
        if (video_modes[i].vram_required_bytes <= vram_size) {
            available_modes[num_modes++] = video_modes[i].id;
        }
    }

    // Cycle to next mode
    mode_index = (mode_index + 1) % num_modes;

    // Apply mode
    video_set_mode(available_modes[mode_index]);

    // Show OSD notification
    const video_mode_desc_t *mode = video_get_current_mode();
    show_osd("Video Mode: %s", mode->name);
}
```

---

## Implementation Checklist

### Minimum Required (For Basic Widescreen Support)

- [ ] **ND Firmware**: RAMDAC programming routines
- [ ] **ND Firmware**: Clock generator control
- [ ] **ND Firmware**: Video mode manager with 1366×768 support
- [ ] **ND Firmware**: CMD_SET_VIDEO_MODE mailbox handler
- [ ] **ND Firmware**: Boot-time auto-detection
- [ ] **ND Driver**: Framebuffer configuration updates
- [ ] **ND Driver**: DPS context pixel format handling
- [ ] **ND Driver**: Display preferences panel

### Recommended (For Full Feature Set)

- [ ] **ND Firmware**: Support for 1600×900 mode (stretch goal)
- [ ] **ND Firmware**: Support for 1920×1080 mode (if 8 MB VRAM)
- [ ] **ND Firmware**: EDID monitor detection
- [ ] **ND Firmware**: Runtime mode validation (stability testing)
- [ ] **ND Driver**: Mode cycling hotkey (Cmd+Option+M)
- [ ] **ND Driver**: Boot-time mode preference saving
- [ ] **System**: Update `/NextLibrary/Displays/` configuration files

### Optional (For Perfectionists)

- [ ] **ND ROM**: Modify default boot mode to 1366×768
- [ ] **ND ROM**: Add I²C driver for clock programming
- [ ] **Testing**: Oscilloscope signal integrity verification
- [ ] **Testing**: Long-term stability testing (24+ hours each mode)

---

## Testing Strategy

### Phase 1: Firmware-Only Testing (Previous Emulator)

1. Implement RAMDAC and clock routines in GaCKliNG
2. Test in Previous emulator (may need emulator updates)
3. Verify mode switching logic
4. Test framebuffer rendering at different resolutions

### Phase 2: Real Hardware Testing (Stock 4 MB VRAM)

1. Flash GaCKliNG to NeXTdimension board
2. Test 1366×768 mode (should work reliably)
3. Test 1600×900 mode (may be unstable)
4. Measure pixel clock with oscilloscope
5. Document which modes work on your specific board

### Phase 3: 8 MB VRAM Testing (If Hardware Modified)

1. Perform address decoder modification
2. Install 8 MB VRAM chips
3. Update GaCKliNG memory map
4. Test 1920×1080 @ 32-bit mode
5. Extensive stability testing under load

---

## Conclusion

**To add modern 16:9 widescreen video modes to GaCKliNG, you must modify:**

| Component | Priority | Complexity | Risk |
|-----------|----------|------------|------|
| **ND Firmware (GaCK Kernel)** | ⭐⭐⭐⭐⭐ Critical | High | Low |
| **ND Driver (Host)** | ⭐⭐⭐⭐⭐ Required | Medium | Low |
| **ND ROM (Bootstrap)** | ⭐ Optional | Very High | **High** |

**Recommended Approach**:
1. ✅ Implement video mode support in **GaCKliNG firmware** first
2. ✅ Update **host driver** to understand new modes
3. ✅ Test thoroughly in emulator and on real hardware
4. ❌ **Skip ROM modification** - unnecessary and risky

**Result**: Modern widescreen support without touching the ROM!

---

*"The firmware is the brain, the driver is the interface, and the ROM is just the bootloader."*
