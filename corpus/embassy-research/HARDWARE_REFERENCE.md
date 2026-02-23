# NeXTdimension Hardware Reference Guide

**For Embassy Firmware Implementation**

This document consolidates hardware specifications, register addresses, protocol details, and implementation guidance extracted from 77 reverse-engineering documentation files.

---

## 1. MEMORY MAP

### DRAM Layout (32 MB @ 0x00000000)

```
Address Range           Size      Purpose
─────────────────────────────────────────────────────────────
0x00000000-0x000003FF   1 KB      Exception vectors (256 bytes used)
0x00000400-0x000B27FF   ~706 KB   Kernel code (.TEXT)
0x000B2800-0x000C3FFF   ~69 KB    Initialized data (.DATA)
0x000C4000-0x000C5FFF   8 KB      Uninitialized data (.BSS)
0x000C6000-0x006EFFFF   ~6.1 MB   Kernel heap (allocator region)
0x006F0000-0x007EFFFF   1 MB      Font cache hash table
0x007F0000-0x007FFFFF   64 KB     Reserved/alignment
0x00800000-0x01EFFFFF   ~23 MB    Font glyph storage
0x01FF0000-0x01FFFFFF   64 KB     Stack (grows downward from 0x01FFFFFF)
```

### VRAM Layout (8 MB @ 0x10000000)

```
Address Range           Size      Purpose
─────────────────────────────────────────────────────────────
0x10000000-0x1038FFFF   ~3.56 MB  Primary framebuffer (1120×832×32bpp)
0x10390000-0x1071FFFF   ~3.56 MB  Secondary framebuffer (double-buffer)
0x10720000-0x10AAFFFF   ~3.56 MB  Tertiary framebuffer (triple-buffer)
0x10AB0000-0x10ABFFFF   64 KB     Cursor bitmaps (32×32×2bpp)
0x10AC0000-0x10FFFFFF   ~5.25 MB  Off-screen buffers, temp storage
```

### MMIO Regions

```
0x02000000-0x020000FF   Mailbox & Control Registers
0x02000100-0x020001FF   RAMDAC (Brooktree BT463)
0x02000200-0x020002FF   Video Controller (hypothetical)
0x02000300-0x020003FF   DMA Controller (hypothetical)
0xFF800000              CSR0 - Memory Controller (PROVEN)
0xFFF00000-0xFFF1FFFF   ROM (128 KB)
```

---

## 2. CRITICAL REGISTER SPECIFICATIONS

### Mailbox Registers (0x02000000-0x0200003F)

**PROVEN working in Previous emulator:**

```c
#define MAILBOX_BASE        0x02000000

// Register offsets
+0x00  STATUS          RW   Bit 0:READY, 1:BUSY, 2:COMPLETE, 3:ERROR
+0x04  COMMAND         WO   Command opcode (0x00-0x3F)
+0x08  DATA_PTR        WO   Shared memory address
+0x0C  DATA_LEN        WO   Data length in bytes
+0x10  RESULT          RO   Result value from i860
+0x14  ERROR_CODE      RO   Error details (0x00-0x0F)
+0x18  HOST_SIGNAL     WO   Host interrupt trigger
+0x1C  I860_SIGNAL     WO   i860 interrupt trigger
+0x20  ARG1            WO   Command argument 1
+0x24  ARG2            WO   Command argument 2
+0x28  ARG3            WO   Command argument 3
+0x2C  ARG4            WO   Command argument 4
+0x30-0x3C  RESERVED        Future use
```

**Status Register Bits:**
```
Bit 0 (0x001): READY     - Mailbox ready for new command
Bit 1 (0x002): BUSY      - Command being processed
Bit 2 (0x004): COMPLETE  - Command finished
Bit 3 (0x008): ERROR     - Error occurred (check ERROR_CODE)
```

### CSR0 - Memory Controller (0xFF800000) **PROVEN**

**This is the verified source for VBL interrupts:**

```c
#define CSR0_ADDR       0xFF800000

// CSR0 bits (from Previous emulator src/dimension/nd_mem.c)
Bit 0  (0x00000001): CSR0_i860PIN_RESET      - i860 reset
Bit 2  (0x00000004): CSR0_i860_IMASK         - i860 interrupt mask
Bit 3  (0x00000008): CSR0_i860_INT           - i860 interrupt trigger
Bit 6  (0x00000040): CSR0_VBL_IMASK          - VBlank interrupt mask ⭐
Bit 7  (0x00000080): CSR0_VBL_INT            - VBlank interrupt flag ⭐
Bit 8  (0x00000100): CSR0_VBLANK (read-only) - Current VBlank status
Bit 12 (0x00001000): CSR0_i860_CACHE_EN      - i860 cache enable

// Initial value from ROM: 0xC7000000
```

**VBL Interrupt Implementation:**
```rust
// Enable VBL interrupts
pub fn enable_vblank_interrupt() {
    let csr0 = unsafe { core::ptr::read_volatile(0xFF800000 as *const u32) };
    unsafe {
        core::ptr::write_volatile(0xFF800000 as *mut u32, csr0 | 0x00000040);
    }
}

// VBL ISR (minimal)
#[no_mangle]
pub extern "C" fn vblank_irq_handler() {
    let csr0 = unsafe { core::ptr::read_volatile(0xFF800000 as *const u32) };

    if csr0 & 0x00000080 != 0 {  // CSR0_VBL_INT set
        // Clear interrupt
        unsafe {
            core::ptr::write_volatile(0xFF800000 as *mut u32, csr0 & !0x00000080);
        }

        // Signal waiting task
        VBLANK_SIGNAL.signal(());
    }
}
```

### RAMDAC - Brooktree BT463 (0x02000100)

```c
#define RAMDAC_BASE     0x02000100

+0x00  ADDR_LOW        WO   Palette index (low byte)
+0x04  ADDR_HIGH       WO   Palette index (high byte)
+0x08  CMD_REG         WO   Command register
+0x0C  COLOR_PALETTE   WO   Color palette data (write 3× for R,G,B)
+0x10  CURSOR_COLOR    WO   Cursor color register
+0x14  CURSOR_DATA     WO   Cursor bitmap data
+0x18  READ_MASK       RW   Pixel read mask
+0x1C  BLINK_MASK      WO   Blink mask
+0x20  TEST_REG        RW   Diagnostic test register
```

**Initialization Sequence (28 register writes from ROM):**
```
1. Set pixel clock: 120 MHz
2. Configure video timing: 1120×832 @ 68.7 Hz
3. Initialize 256-entry color palette (768 writes total)
4. Set cursor to 32×32 2bpp mode
5. Enable overlay planes
```

---

## 3. PROTOCOL SPECIFICATIONS

### Mailbox Communication Flow

**Host → i860 Command:**
```
1. Host polls STATUS until READY bit set (or BUSY clear)
2. Host writes:
   - COMMAND = opcode
   - ARG1-ARG4 = parameters
   - DATA_PTR = shared memory address (if needed)
   - DATA_LEN = buffer size
3. Host sets STATUS.READY bit
4. (Optional) Host triggers HOST_SIGNAL for interrupt

5. i860 detects READY (polling or interrupt)
6. i860 sets STATUS.BUSY, clears STATUS.READY
7. i860 reads COMMAND, ARG1-4, DATA_PTR, DATA_LEN
8. i860 processes command (10µs-10ms)
9. i860 writes RESULT, ERROR_CODE
10. i860 sets STATUS.COMPLETE, clears STATUS.BUSY
11. (Optional) i860 triggers I860_SIGNAL

12. Host polls STATUS for COMPLETE
13. Host reads RESULT, ERROR_CODE
14. Host clears STATUS.COMPLETE (write 0)
15. Repeat
```

**Performance:**
- Command latency: 12-30 µs (simple operations)
- Throughput: 10,000-100,000 commands/sec
- Data bandwidth: 50-150 MB/s (VRAM writes)

### Command Opcodes (Documented)

```c
// Basic Commands (0x00-0x12)
#define CMD_NOP              0x00  // No-op / keepalive
#define CMD_LOAD_KERNEL      0x01  // Load kernel from shared memory
#define CMD_INIT_VIDEO       0x02  // Initialize video subsystem
#define CMD_SET_MODE         0x03  // Set video mode
#define CMD_UPDATE_FB        0x04  // Update framebuffer region
#define CMD_FILL_RECT        0x05  // Fill rectangle
#define CMD_BLIT             0x06  // Copy rectangle
#define CMD_SET_PALETTE      0x07  // Load palette
#define CMD_SET_CURSOR       0x08  // Set cursor shape
#define CMD_MOVE_CURSOR      0x09  // Move cursor position
#define CMD_SHOW_CURSOR      0x0A  // Show/hide cursor
#define CMD_DPS_EXECUTE      0x0B  // Execute DPS operators
#define CMD_VIDEO_CAPTURE    0x0C  // Start video input
#define CMD_VIDEO_STOP       0x0D  // Stop video capture
#define CMD_GENLOCK_EN       0x0E  // Enable genlock
#define CMD_GENLOCK_DIS      0x0F  // Disable genlock
#define CMD_GET_INFO         0x10  // Query board info
#define CMD_MEMORY_TEST      0x11  // Memory self-test
#define CMD_RESET            0x12  // Reset i860 subsystem

// Reserved for future (0x13-0x1F)

// GaCKling Extensions (0x20-0x3F)
// (User-defined command space)
```

### Error Codes

```c
#define ERR_SUCCESS            0x00  // No error
#define ERR_INVALID_COMMAND    0x01  // Unknown opcode
#define ERR_INVALID_PARAM      0x02  // Bad parameter value
#define ERR_INVALID_ADDRESS    0x03  // Bad memory address
#define ERR_BUFFER_TOO_SMALL   0x04  // Output buffer insufficient
#define ERR_BUFFER_TOO_LARGE   0x05  // Input buffer too large
#define ERR_TIMEOUT            0x06  // Operation timeout
#define ERR_NO_MEMORY          0x07  // Allocation failed
#define ERR_DEVICE_BUSY        0x08  // Device in use
#define ERR_NOT_READY          0x09  // Board not initialized
#define ERR_HW_FAILURE         0x0A  // Hardware error
#define ERR_DMA_ERROR          0x0B  // DMA failed
#define ERR_VIDEO_ERROR        0x0C  // Video error
#define ERR_RAMDAC_ERROR       0x0D  // RAMDAC error
#define ERR_NOT_SUPPORTED      0x0E  // Feature not supported
#define ERR_UNKNOWN            0x0F  // Generic error
```

---

## 4. GRAPHICS PRIMITIVES

### 37 Identified Handlers

**From ROM disassembly and call graph analysis:**

**Complex Operations (1KB+):**
1. Math/Utility Library (4.1 KB) - FP ops, trig, matrix
2. Bezier/Curve Rendering (2.5 KB) - Path tessellation
3. Text Rendering (1.9 KB) - Glyph blitting, font cache
4. Advanced Blit (1.5 KB) - Clipping, transparency
5. Image Scaling (1.4 KB) - Interpolation
6. Compositing (2.5 KB) - Alpha blending, Porter-Duff
7. Pattern Fill (1.3 KB) - Tiled patterns
8. Polygon Fill (1.2 KB) - Scanline fill

**Standard Primitives (200-1000B):**
9. Standard Blit (864B)
10. Line Drawing (780B) - Bresenham
11. Rectangle Fill (732B)
12. Alpha Compositing (688B)
13. Color Conversion (540B)
14. Mask Operations (532B)
15. Pixel Block Operations (512B)
16. Coordinate Transform (408B)
17. Gradient Fill (340B)
18. Texture Mapping (328B)
19. Antialiasing (324B)
20. Pixel Format Convert (236B)
21. Screen Clear (224B)
22. Point Drawing (220B)
23. Synchronization (212B)
24. VRAM Copy (212B)
25. Cursor Operations (212B)
26. Dithering (208B)
27. Viewport Operations (200B)

**Simple Operations (50-200B):**
28-37. Buffer swap, pixel read/write, simple fill, lines, palette lookup, etc.

### Performance Targets

```
Operation             Latency        Throughput
──────────────────────────────────────────────────
Simple fill           10-50 µs       50-100K/sec
Rectangle fill        50-200 µs      5-20K/sec
Blit operation        50-200 µs      5-20K/sec
Text (cached glyph)   100-500 µs     1-10K/sec
Bezier curve          500 µs-2 ms    Varies
Line drawing          10-100 µs      10-100K/sec
VBL sync              14.55 ms       68.7 Hz
```

### Framebuffer Access Pattern

```rust
// Optimized fill (8-pixel unroll for i860 pipeline)
pub fn fill_rect_optimized(x: u16, y: u16, w: u16, h: u16, color: u32) {
    let fb_base = 0x10000000 as *mut u32;
    let stride = 1120;

    for row in 0..h {
        let row_addr = unsafe {
            fb_base.add(((y + row) as usize * stride) + x as usize)
        };

        let mut col = 0;
        while col + 8 <= w {
            unsafe {
                row_addr.add(col as usize + 0).write_volatile(color);
                row_addr.add(col as usize + 1).write_volatile(color);
                row_addr.add(col as usize + 2).write_volatile(color);
                row_addr.add(col as usize + 3).write_volatile(color);
                row_addr.add(col as usize + 4).write_volatile(color);
                row_addr.add(col as usize + 5).write_volatile(color);
                row_addr.add(col as usize + 6).write_volatile(color);
                row_addr.add(col as usize + 7).write_volatile(color);
            }
            col += 8;
        }

        // Handle remaining pixels
        while col < w {
            unsafe { row_addr.add(col as usize).write_volatile(color); }
            col += 1;
        }
    }
}
```

**Performance:** 50-70 MB/s (NeXTBus limited), 150 MB/s with write-combining

---

## 5. BOOT SEQUENCE

### ROM Boot Process (0xFFF00000)

```
RESET @ 0x1FF20 → Branch to 0x00000020
     │
     ▼
[1] PSR/EPSR/FSR Setup
     │ - PSR to known state
     │ - EPSR for exception control
     │ - FSR for FPU control
     ▼
[2] FPU Pipeline Warmup
     │ - Execute dummy FPU instructions
     │ - Populate 3-stage FP pipeline
     ▼
[3] DIRBASE = 0x00000000
     │ - Page table base
     │ - Identity mapping (virtual == physical)
     ▼
[4] Memory Detection
     │ - Test 0x2E3A8000 (16MB)
     │ - Test 0x4E3A8000 (32MB)
     │ - Test 0x6E3A8000 (64MB)
     ▼
[5] RAMDAC Initialization
     │ - 28 register writes to Bt463
     │ - Set pixel clock: 120 MHz
     │ - Video timing: 1120×832 @ 68.7 Hz
     │ - Initialize palette
     ▼
[6] Mailbox Polling Loop
     │ - Poll 0x02000000 STATUS register
     │ - Wait for READY bit or HOST_SIGNAL
     │ - If READY: copy kernel from shared memory
     │ - Jump to 0x00000000 (kernel entry)
     │ - **ROM NEVER RETURNS**
     ▼
[Embassy Firmware Takes Over]
```

### Critical Startup Values

```c
// From ROM disassembly
CSR0_INITIAL    = 0xC7000000
DIRBASE         = 0x00000000  // Identity mapping
PSR_INITIAL     = (value TBD from ROM analysis)

// Video timing for 1120×832 @ 68.7 Hz
HTOTAL          = 1632 pixels
HBLANK_START    = 1120
HBLANK_END      = 1632
VTOTAL          = 1216 lines
VBLANK_START    = 832
VBLANK_END      = 1216
PIXEL_CLOCK     = 120 MHz
```

---

## 6. PERFORMANCE OPTIMIZATION

### i860 Pipeline Characteristics

```
Integer Pipeline:  4 stages (IF/ID/EX/WB)
FP Adder Pipeline: 3 stages
FP Mult Pipeline:  2 stages
Branch Delay:      1 slot
```

**Optimization Patterns:**

1. **Loop Unrolling (8×)**
   - Keeps pipeline full
   - No data dependencies between iterations
   - Target: 8 operations per loop

2. **Write-Combining**
   - Batch VRAM writes
   - CPU buffers, bursts when full
   - 3× performance improvement (50→150 MB/s)

3. **Deferred Interrupt Processing**
   - ISR: Read hardware, signal, return (< 20 cycles)
   - Task: Process in normal context
   - Avoids pipeline flush (200+ cycle penalty)

4. **Cooperative Scheduling**
   - Tasks yield at `.await` points
   - No involuntary preemption
   - Pipeline stays full

### Memory Access Performance

```
Region              Access       Latency      Bandwidth
─────────────────────────────────────────────────────────
DRAM (cached)       R/W          3-4 cy       130 MB/s
DRAM (uncached)     R/W          10-15 cy     50 MB/s
MMIO registers      R/W          5-10 cy      Variable
VRAM (uncombined)   Write        10-15 cy     50 MB/s
VRAM (combined)     Write        3-4 cy/px    150 MB/s
ROM                 Read         10-15 cy     50 MB/s
```

---

## 7. IMPLEMENTATION CHECKLIST

### ✅ Already Implemented in Embassy Firmware

- [x] Memory management (bump/buddy/pool allocators)
- [x] Async DMA engine with Signal & Wake
- [x] Mailbox protocol structure
- [x] Video controller with triple buffering
- [x] Hardware abstractions (CPU, FPU, VLIW)
- [x] Deferred interrupt processing
- [x] Priority-based task routing

### ⚠️ Needs Verification/Correction

- [ ] **VBL interrupt source** - Update to use CSR0 @ 0xFF800000 (PROVEN)
- [ ] **Mailbox register addresses** - Verify 0x02000000 base
- [ ] **Video timing registers** - Implement if available
- [ ] **Command opcode mapping** - Verify 0x00-0x12 range

### ❌ Not Yet Implemented

- [ ] **Graphics primitives** - 37 handlers from documentation
- [ ] **Font cache** - 1 MB hash table + 23 MB glyphs
- [ ] **PostScript operator wraps** - DPS command handling
- [ ] **Cursor operations** - Hardware cursor support
- [ ] **Video input/genlock** - NeXTcamera support
- [ ] **Performance monitoring** - Cycle counters, statistics
- [ ] **Exception handlers** - 256-byte vector table
- [ ] **Memory protection** - MMU configuration (optional)

---

## 8. REFERENCES

**Primary Sources:**
- `NEXTDIMENSION_MEMORY_MAP_COMPLETE.md` - Memory layout
- `HOST_I860_PROTOCOL_SPEC.md` - Mailbox protocol
- `GRAPHICS_PRIMITIVES_MAP.md` - Graphics handlers
- `ROM_BOOT_SEQUENCE_DETAILED.md` - Boot process
- `i860-firmware-SBB-embassy-architecture.md` - Embassy design
- Previous emulator source: `src/dimension/nd_mem.c` - CSR0 register

**Verification Status:**
- ✅ **PROVEN**: CSR0 VBL interrupts (Previous emulator)
- ✅ **PROVEN**: Mailbox polling (Previous emulator)
- ✅ **PROVEN**: Memory map (ROM disassembly)
- ⚠️ **HYPOTHETICAL**: Interrupt controller @ 0x020000C0
- ⚠️ **HYPOTHETICAL**: Video timing registers
- ⚠️ **HYPOTHETICAL**: DMA controller registers

---

## 9. NEXT STEPS

### Immediate Priority

1. **Update VBL ISR** to use CSR0 @ 0xFF800000
2. **Implement command handlers** for opcodes 0x00-0x12
3. **Add font cache** per FONT_CACHE_ARCHITECTURE.md
4. **Verify mailbox addresses** against hardware/Previous
5. **Add performance counters** for optimization

### Medium Term

1. Implement all 37 graphics primitives
2. Add PostScript operator wrapping
3. Hardware cursor support
4. Video input/genlock support
5. Exception vector handlers

### Long Term

1. Full PostScript acceleration
2. 3D graphics pipeline
3. Advanced compositing
4. MMU/memory protection
5. Multi-core i860 support (future hardware)

---

**Document Status:** Based on analysis of 77 reverse-engineering documents
**Last Updated:** 2025-11-06
**Verification:** Cross-referenced with Previous emulator source code
