# NeXTdimension Graphics Acceleration Guide

**Document Version**: 1.0
**Date**: November 4, 2025
**Analysis**: Phase 3 Deep Dive - Graphics Subsystem Architecture
**Status**: Comprehensive Analysis Based on Hardware Architecture and Code Patterns

---

## Executive Summary

The NeXTdimension accelerates 2D graphics operations using the Intel i860XR processor's unique capabilities: dual-instruction issue, 64-bit FPU data paths, and direct framebuffer access. This document analyzes the graphics acceleration architecture, performance characteristics, and implementation strategies based on hardware analysis, protocol specifications, and i860 optimization patterns.

### Graphics Pipeline Overview

```
┌─────────────────────────────────────────────────────────┐
│              NeXT Host System (68040)                   │
│                                                         │
│  Application                                            │
│      ↓                                                  │
│  WindowServer (Display PostScript)                      │
│      ↓                                                  │
│  Render to display list                                 │
│      ↓                                                  │
│  NDserver daemon                                        │
│      ↓ Translate DPS to primitives                      │
│      ↓ Send via mailbox protocol                        │
└──────┼──────────────────────────────────────────────────┘
       │ NeXTBus (32-bit, 33 MHz, ~80 MB/s actual)
┌──────┼──────────────────────────────────────────────────┐
│      ↓           NeXTdimension Board                    │
│  Mailbox Registers (0x02000000)                         │
│      ↓                                                  │
│  i860XR @ 33 MHz                                        │
│      ↓ Parse command                                    │
│      ↓ Execute graphics primitive                       │
│      ↓ Write to VRAM                                    │
│      ↓                                                  │
│  VRAM (4 MB @ 0x10000000)                               │
│      ↓ Framebuffer: 1120×832×32bpp                      │
│      ↓                                                  │
│  Bt463 RAMDAC @ 168 MHz                                 │
│      ↓ Triple 8-bit DAC                                 │
│      ↓ Pixel clock: 100 MHz                             │
│      ↓                                                  │
│  Display: 1120×832 @ 68.7 Hz                            │
└─────────────────────────────────────────────────────────┘
```

### Architecture Philosophy

The NeXTdimension follows a **host-driven rendering model**:

1. **Host does rasterization**: WindowServer performs Display PostScript rendering on the 68040
2. **i860 does memory operations**: The i860 kernel executes memory-intensive operations (fill, blit, copy)
3. **Optimized for bandwidth**: Focus on maximizing NeXTBus and VRAM throughput

This is **not a GPU** in the modern sense - it's a **framebuffer accelerator** optimized for 2D windowing operations.

### Performance Summary

| Operation | Method | Theoretical | Actual (Estimated) | Bottleneck |
|-----------|--------|-------------|-------------------|------------|
| Framebuffer fill | FPU 64-bit stores | 264 MB/s | ~70 MB/s | NeXTBus bandwidth |
| Framebuffer blit | FPU 64-bit load/store | 264 MB/s | ~60 MB/s | Memory latency |
| Host→VRAM update | Burst transfers | 132 MB/s | ~50 MB/s | NeXTBus + polling |
| VRAM→Display | RAMDAC + shift | 440 MB/s | 440 MB/s | None (native) |

**Key Insight**: Graphics performance limited by **NeXTBus bandwidth (~80 MB/s)**, not i860 compute capability.

---

## Framebuffer Architecture

### Memory Layout

**VRAM Physical Address**: `0x10000000` (i860 memory map)
**VRAM Size**: 4 MB (0x00400000 bytes)
**Framebuffer Region**: First 3.73 MB used for display

#### Display Configuration

```
Resolution:  1120 × 832 pixels
Color Depth: 32 bits per pixel (RGBA 8:8:8:8)
Stride:      4480 bytes (1120 pixels × 4 bytes)
Size:        3,727,360 bytes (~3.55 MB)
Refresh:     68.7 Hz (non-interlaced)
```

#### Pixel Format

**Big-Endian 32-bit ARGB** (or XRGB with unused alpha):

```c
typedef struct {
    uint8_t alpha;   // MSB (or unused/padding) - byte 0
    uint8_t red;     // byte 1
    uint8_t green;   // byte 2
    uint8_t blue;    // LSB - byte 3
} nd_pixel_t;  // 4 bytes total

// Memory layout (big-endian):
// Address: [A][R][G][B]
// Bit 31-24: Alpha/unused
// Bit 23-16: Red
// Bit 15-8:  Green
// Bit 7-0:   Blue
```

**Note**: Alpha channel may be unused - NeXT documentation suggests 24-bit RGB with 8-bit padding.

#### Address Calculation

```c
#define VRAM_BASE      0x10000000
#define FB_WIDTH       1120
#define FB_HEIGHT      832
#define FB_STRIDE      4480  // 1120 × 4
#define BYTES_PER_PIXEL 4

// Calculate pixel address
static inline uint32_t* get_pixel_addr(uint16_t x, uint16_t y) {
    return (uint32_t*)(VRAM_BASE + (y * FB_STRIDE) + (x * BYTES_PER_PIXEL));
}

// Calculate row start address
static inline uint32_t* get_row_addr(uint16_t y) {
    return (uint32_t*)(VRAM_BASE + (y * FB_STRIDE));
}
```

### Memory Organization

```
VRAM @ 0x10000000
├─ 0x10000000  Row 0 (1120 pixels, 4480 bytes)
├─ 0x10001180  Row 1
├─ 0x10002300  Row 2
│     ...
├─ 0x1038E300  Row 831 (last display row)
├─ 0x1038F480  End of framebuffer (3,727,360 bytes)
│
├─ 0x1038F480  Unused VRAM (~320 KB remaining)
│     ...       (Can be used for off-screen buffers,
│                cursor images, etc.)
└─ 0x103FFFFF  End of VRAM (4 MB)
```

### Double Buffering

**Hardware Support**: The NeXTdimension hardware and Bt463 RAMDAC **do not provide built-in page flipping**.

**Single Buffer Architecture**:
- Only one visible framebuffer at 0x10000000
- Updates are visible immediately (no VSync flip)
- Tearing possible during fast updates

**Software Double Buffering** (if implemented):
```c
// Off-screen buffer in unused VRAM
#define BACKBUFFER_ADDR  0x10390000  // After main framebuffer

// Render to back buffer
render_to_buffer((uint32_t*)BACKBUFFER_ADDR, width, height);

// Copy to front buffer during VBlank
memcpy_vram((uint32_t*)VRAM_BASE,
            (uint32_t*)BACKBUFFER_ADDR,
            FB_WIDTH * FB_HEIGHT * 4);
```

**VBlank Synchronization**:
- VBlank interrupt available (68.7 Hz)
- Kernel can wait for VBlank before blitting
- Reduces tearing for full-screen updates

### Cache Considerations

**i860XR Data Cache**:
- Size: 4 KB
- Associativity: 2-way set-associative
- Line size: 32 bytes (8 × 32-bit words)
- Write policy: Write-through or write-back (configurable)

**Framebuffer Access Strategy**:

The framebuffer at 0x10000000 is likely **uncached** or **write-through**:

1. **Why uncached makes sense**:
   - Framebuffer is much larger (3.7 MB) than cache (4 KB)
   - Sequential writes don't benefit from caching
   - Avoiding cache pollution for framebuffer operations
   - RAMDAC needs immediate visibility of pixel data

2. **Cache configuration** (typical):
   ```assembly
   ; Set up DIRBASE to mark VRAM region as uncached
   ; DIRBASE controls page table base and caching policy
   ```

3. **Write combining** (if supported):
   - i860 has 4-entry write buffer
   - Coalesces sequential writes before NeXTBus transfer
   - Improves burst efficiency

---

## Graphics Primitives

### Command Protocol

From HOST_I860_PROTOCOL_SPEC.md, graphics commands:

| Command | Code | Description |
|---------|------|-------------|
| CMD_UPDATE_FB | 0x04 | Update framebuffer region from host data |
| CMD_FILL_RECT | 0x05 | Fill rectangle with solid color |
| CMD_BLIT | 0x06 | Copy rectangle within framebuffer |
| CMD_SET_PALETTE | 0x07 | Set color palette (for 8-bit mode?) |
| CMD_CLEAR_SCREEN | 0x07 | Clear entire screen to color |

### FILL_RECT: Fill Rectangle with Solid Color

#### Command Structure

```c
// Mailbox command
mailbox->command = CMD_FILL_RECT;
mailbox->arg1 = (x << 16) | y;        // Top-left corner
mailbox->arg2 = (width << 16) | height; // Dimensions
mailbox->arg3 = color;                 // 32-bit ARGB color
mailbox->arg4 = 0;                     // Reserved
```

#### Implementation Strategy

**Basic Algorithm** (C pseudocode):
```c
void fill_rect(uint16_t x, uint16_t y, uint16_t width, uint16_t height, uint32_t color) {
    uint32_t *fb_row = get_pixel_addr(x, y);

    for (uint16_t row = 0; row < height; row++) {
        uint32_t *pixel = fb_row;

        // Fill one row
        for (uint16_t col = 0; col < width; col++) {
            *pixel++ = color;
        }

        // Next row (stride = 1120 pixels)
        fb_row += FB_WIDTH;
    }
}
```

**Optimized i860 Implementation** (annotated assembly):

```assembly
; fill_rect_optimized
; Inputs:
;   r16 = x position
;   r17 = y position
;   r18 = width
;   r19 = height
;   r20 = color (32-bit ARGB)

fill_rect_optimized:
    ; Calculate starting address: VRAM_BASE + (y * 4480) + (x * 4)
    orh     0x1000,%r0,%r10         ; r10 = 0x10000000 (VRAM base high)

    ; Compute y offset: y * 4480 = y * 4096 + y * 384
    shl     12,%r17,%r11            ; r11 = y << 12 = y * 4096
    shl     7,%r17,%r12             ; r12 = y << 7 = y * 128
    shl     8,%r17,%r13             ; r13 = y << 8 = y * 256
    addu    %r12,%r13,%r12          ; r12 = y * 384
    addu    %r11,%r12,%r11          ; r11 = y * 4480

    ; Compute x offset: x * 4
    shl     2,%r16,%r12             ; r12 = x * 4

    ; Add offsets to base
    addu    %r10,%r11,%r10          ; r10 = VRAM_BASE + (y * 4480)
    addu    %r10,%r12,%r10          ; r10 = address of first pixel

    ; Prepare color in FPU register for 64-bit writes
    ixfr    %r20,%f16               ; Move color to FPU
    fxfr    %f16,%r21               ; Duplicate color
    ; Now we can use fst.d to write 2 pixels at once

.row_loop:
    adds    %r0,%r10,%r11           ; r11 = current pixel address
    shr     1,%r18,%r12             ; r12 = width / 2 (pixel pairs)

.pixel_pair_loop:
    ; Write 2 pixels with one fst.d instruction
    fst.d   %f16,0(%r11)            ; Store 8 bytes (2 × 32-bit pixels)
    adds    8,%r11,%r11             ; Advance by 8 bytes
    subs    1,%r12,%r12             ; Decrement counter
    bnc     .pixel_pair_loop        ; Loop if not zero
    nop                             ; (delay slot)

    ; Handle odd width if necessary
    btne    0,%r18,1,.skip_odd      ; Test bit 0 (odd width?)
    nop                             ; (delay slot)
    st.l    %r20,0(%r11)            ; Write final pixel

.skip_odd:
    ; Move to next row
    adds    FB_STRIDE,%r10,%r10     ; r10 += 4480 (next row)
    subs    1,%r19,%r19             ; height--
    bc      .row_loop               ; Loop if height > 0
    nop                             ; (delay slot)

    bri     %r1                     ; Return
    nop                             ; (delay slot)
```

#### Performance Analysis

**Theoretical Performance**:
- FPU 64-bit stores: 2 pixels per `fst.d` instruction
- Dual-issue capable: `fst.d` (FPU) + `adds` (core) in same cycle
- Clock: 33 MHz
- Ideal: 66 Mpixels/second (2 pixels × 33 MHz)

**Actual Performance** (accounting for overhead):
```
Cycles per pixel pair:
  fst.d     1 cycle  (FPU)
  adds      1 cycle  (core, parallel)
  subs      1 cycle  (core, sequential)
  bc        1 cycle  (core, sequential)
  = ~2-3 cycles per 2 pixels

Effective rate: ~25-30 Mpixels/second
Bandwidth: ~100-120 MB/s
Bottleneck: Memory write latency, NeXTBus bandwidth
```

**Full Screen Fill**:
```
Pixels: 1120 × 832 = 931,840 pixels
At 25 Mpixels/s: ~37 ms (27 fps)
At 30 Mpixels/s: ~31 ms (32 fps)
```

**Optimization Techniques Used**:
1. **FPU 64-bit stores**: Write 2 pixels per instruction
2. **Loop unrolling**: Could unroll 4× for better pipeline utilization
3. **Dual-issue**: `fst.d` and pointer arithmetic in parallel
4. **Write buffering**: i860 write buffer coalesces stores

---

### BLIT: Copy Rectangle

#### Command Structure

```c
// Mailbox command
mailbox->command = CMD_BLIT;
mailbox->arg1 = (src_x << 16) | src_y;     // Source top-left
mailbox->arg2 = (dst_x << 16) | dst_y;     // Dest top-left
mailbox->arg3 = (width << 16) | height;    // Dimensions
mailbox->arg4 = 0;                         // Reserved
```

#### Implementation Strategy

**Critical Issue**: **Overlap handling**

When source and destination rectangles overlap, copy direction matters:

```
Case 1: dst_y > src_y  OR  (dst_y == src_y AND dst_x > src_x)
  → Copy BACKWARD (bottom to top, right to left)
  → Prevents overwriting source data

Case 2: Otherwise
  → Copy FORWARD (top to bottom, left to right)
  → Standard copy direction
```

**Algorithm** (C pseudocode):

```c
void blit_rect(uint16_t src_x, uint16_t src_y,
               uint16_t dst_x, uint16_t dst_y,
               uint16_t width, uint16_t height) {

    // Determine copy direction
    int backward = (dst_y > src_y) || (dst_y == src_y && dst_x > src_x);

    if (backward) {
        // Start from bottom-right
        uint32_t *src = get_pixel_addr(src_x + width - 1, src_y + height - 1);
        uint32_t *dst = get_pixel_addr(dst_x + width - 1, dst_y + height - 1);

        for (int row = height - 1; row >= 0; row--) {
            uint32_t *src_pixel = src;
            uint32_t *dst_pixel = dst;

            // Copy one row backward
            for (int col = width - 1; col >= 0; col--) {
                *dst_pixel-- = *src_pixel--;
            }

            // Previous row
            src -= FB_WIDTH;
            dst -= FB_WIDTH;
        }
    } else {
        // Forward copy
        uint32_t *src = get_pixel_addr(src_x, src_y);
        uint32_t *dst = get_pixel_addr(dst_x, dst_y);

        for (uint16_t row = 0; row < height; row++) {
            // Use optimized memcpy-style loop
            memcpy_64(dst, src, width * 4);

            // Next row
            src += FB_WIDTH;
            dst += FB_WIDTH;
        }
    }
}
```

**Optimized Row Copy** (using FPU 64-bit transfers):

```assembly
; memcpy_64 - optimized memory copy using FPU
; Inputs:
;   r16 = dst address
;   r17 = src address
;   r18 = byte count
memcpy_64:
    shr     3,%r18,%r19             ; r19 = count / 8 (64-bit words)

.loop_64:
    fld.d   0(%r17),%f0             ; Load 8 bytes from source
    adds    8,%r17,%r17             ; src += 8
    fst.d   %f0,0(%r16)             ; Store 8 bytes to dest
    adds    8,%r16,%r16             ; dst += 8
    subs    1,%r19,%r19             ; count--
    bc      .loop_64                ; Loop if count > 0
    nop

    ; Handle remainder (< 8 bytes)
    and     7,%r18,%r19             ; r19 = byte_count & 7
    shr     2,%r19,%r19             ; r19 = remainder / 4 (32-bit words)

.loop_32:
    ld.l    0(%r17),%r20            ; Load 4 bytes
    adds    4,%r17,%r17
    st.l    %r20,0(%r16)            ; Store 4 bytes
    adds    4,%r16,%r16
    subs    1,%r19,%r19
    bc      .loop_32
    nop

    bri     %r1                     ; Return
    nop
```

#### Performance Analysis

**Bandwidth**: 2× memory operations (load + store)

```
fld.d: 8 bytes load   → 1-2 cycles (cache/latency)
fst.d: 8 bytes store  → 1-2 cycles (write buffer)
Total: ~2-4 cycles per 8 bytes

Throughput: ~70-130 MB/s (read + write)
Effective: ~35-65 MB/s per direction
```

**640×480 Window Blit**:
```
Size: 640 × 480 × 4 = 1,228,800 bytes (~1.17 MB)
At 60 MB/s: ~20 ms (50 fps)
```

**Optimization Techniques**:
1. **FPU 64-bit transfers**: Load/store 8 bytes per iteration
2. **Pipelined transfers**: Load while previous store completes
3. **Write buffer**: Coalesce writes before NeXTBus transfer
4. **Row-at-a-time**: Better cache behavior for source data

---

### UPDATE_FB: Framebuffer Update from Host

#### Command Structure

```c
// Mailbox command
mailbox->command = CMD_UPDATE_FB;
mailbox->data_ptr = host_buffer_addr;     // Physical address in host RAM
mailbox->data_len = width * height * 4;   // Byte count
mailbox->arg1 = (x << 16) | y;            // Dest position
mailbox->arg2 = (width << 16) | height;   // Dimensions
```

#### Implementation Strategy

**Challenge**: Transfer pixel data from **host memory** (via NeXTBus) to **VRAM**.

```
Host RAM (68040 side)
      ↓ NeXTBus (~80 MB/s actual)
i860 DRAM window (0x08000000-0x0BFFFFFF)
      ↓ i860 loads data
      ↓ i860 stores to VRAM
VRAM (0x10000000)
```

**Algorithm** (C pseudocode):

```c
void update_fb(uint16_t x, uint16_t y, uint16_t width, uint16_t height,
               uint32_t *host_data_ptr) {

    // Host data is visible at specified address in i860 memory map
    uint32_t *src = host_data_ptr;
    uint32_t *dst = get_pixel_addr(x, y);

    for (uint16_t row = 0; row < height; row++) {
        // Transfer one row: width × 4 bytes
        for (uint16_t col = 0; col < width; col++) {
            *dst++ = *src++;
        }

        // Next row (skip to next scanline)
        dst += (FB_WIDTH - width);
    }
}
```

**Optimized Implementation** (burst transfers):

```assembly
; update_fb_optimized
; Inputs:
;   r16 = x, r17 = y
;   r18 = width, r19 = height
;   r20 = host_data_ptr

update_fb_optimized:
    ; Calculate destination address
    orh     0x1000,%r0,%r10         ; VRAM base
    ; ... (address calculation as in fill_rect)

    adds    %r0,%r20,%r11           ; r11 = source pointer

.row_loop:
    shr     2,%r18,%r12             ; r12 = width / 4 (16-byte chunks)
    adds    %r0,%r10,%r13           ; r13 = dest pointer for this row

.quad_loop:
    ; Load 16 bytes (4 pixels) from host memory
    fld.q   0(%r11),%f0             ; Load 16 bytes (FPU quad load)
    adds    16,%r11,%r11            ; src += 16

    ; Store 16 bytes to VRAM
    fst.q   %f0,0(%r13)             ; Store 16 bytes
    adds    16,%r13,%r13            ; dst += 16

    subs    1,%r12,%r12             ; count--
    bc      .quad_loop
    nop

    ; Handle remainder pixels (< 4)
    and     3,%r18,%r12             ; remainder = width & 3

.remainder_loop:
    ld.l    0(%r11),%r14            ; Load 4 bytes
    adds    4,%r11,%r11
    st.l    %r14,0(%r13)            ; Store 4 bytes
    adds    4,%r13,%r13
    subs    1,%r12,%r12
    btne    0,%r12,.remainder_loop
    nop

    ; Next row
    adds    FB_STRIDE,%r10,%r10     ; dst next scanline
    subs    1,%r19,%r19             ; height--
    bc      .row_loop
    nop

    bri     %r1
    nop
```

#### Performance Analysis

**Critical Path**: Host memory → NeXTBus → i860 → VRAM

```
Bottleneck: NeXTBus bandwidth (~80 MB/s)

With FPU quad loads (fld.q / fst.q):
  - 16 bytes per iteration
  - ~2-3 cycles per 16 bytes (load latency)
  - Theoretical: ~175-260 MB/s
  - Actual: Limited by NeXTBus ~80 MB/s
```

**640×480 Update**:
```
Size: 640 × 480 × 4 = 1,228,800 bytes (~1.17 MB)
At 80 MB/s: ~15 ms (66 fps)
At 50 MB/s: ~25 ms (40 fps) - more realistic with polling overhead
```

**Optimization Techniques**:
1. **FPU quad operations**: 16-byte loads/stores (fld.q/fst.q)
2. **Burst mode**: Sequential addresses trigger NeXTBus burst transfers
3. **Prefetching**: i860 can prefetch while storing previous data
4. **Reduced polling**: Minimize mailbox status checks during transfer

---

## DMA Operations

### Hardware Reality: No DMA Controller

**Critical Finding**: The NeXTdimension board **does not have a dedicated DMA controller**.

From hardware analysis:
- No DMA control registers found in MMIO space
- ROM kernel loader manually copies data word-by-word
- All transfers are **programmed I/O** (PIO) driven by i860 CPU

### Software "DMA" Pattern

The i860 kernel implements efficient bulk transfers using optimized instruction sequences:

#### Pattern 1: FPU 64-bit Transfers

```assembly
; Software DMA loop using fld.d / fst.d
; Transfers 8 bytes per iteration
dma_loop_64:
    fld.d   0(%r16),%f0             ; Load 8 bytes from source
    adds    8,%r16,%r16             ; src += 8 (parallel with FPU)
    fst.d   %f0,0(%r17)             ; Store 8 bytes to dest
    adds    8,%r17,%r17             ; dst += 8 (parallel with FPU)
    subs    1,%r18,%r18             ; count-- (parallel)
    bc      dma_loop_64             ; Branch if count > 0
    nop                             ; Delay slot

; Cycle analysis (best case with dual-issue):
;   fld.d:  1 cycle (FPU)    | adds: 0 cycles (parallel, core)
;   fst.d:  1 cycle (FPU)    | adds: 0 cycles (parallel, core)
;   subs:   1 cycle (core)
;   bc:     1 cycle (core, taken)
; Total: ~4 cycles per 8 bytes = ~66 MB/s @ 33 MHz
```

#### Pattern 2: FPU 128-bit Transfers

The i860 FPU can handle **16-byte operations** with `fld.q` / `fst.q`:

```assembly
; Software DMA using 128-bit quad transfers
; Transfers 16 bytes (4 pixels) per iteration
dma_loop_128:
    fld.q   0(%r16),%f0             ; Load 16 bytes into f0:f3
    adds    16,%r16,%r16            ; src += 16
    fst.q   %f0,0(%r17)             ; Store 16 bytes from f0:f3
    adds    16,%r17,%r17            ; dst += 16
    subs    1,%r18,%r18             ; count--
    bc      dma_loop_128
    nop

; Cycle analysis:
;   fld.q:  1-2 cycles (FPU, may stall on alignment)
;   fst.q:  1-2 cycles (FPU)
;   overhead: 2 cycles (adds, subs, branch)
; Total: ~4-6 cycles per 16 bytes = ~88-132 MB/s @ 33 MHz
; Actual: Limited by NeXTBus to ~80 MB/s
```

### Alignment Requirements

**Critical for Performance**:

- **8-byte alignment**: Required for `fld.d` / `fst.d`
- **16-byte alignment**: Required for `fld.q` / `fst.q`
- **Misaligned access**: Can trap or cause severe performance penalties

```c
// Check alignment
#define IS_ALIGNED_8(addr)   (((uint32_t)(addr) & 0x7) == 0)
#define IS_ALIGNED_16(addr)  (((uint32_t)(addr) & 0xF) == 0)

// Align address to 16 bytes
#define ALIGN_16(addr)  (((uint32_t)(addr) + 15) & ~15)
```

### Write Buffer Optimization

**i860 Write Buffer**:
- Size: 4 entries
- Each entry: 1 × 32-bit write (or 1 × 64-bit with FPU)
- Purpose: Coalesce sequential writes before NeXTBus transfer

**Burst Mode**:
When write buffer fills with sequential addresses, triggers **NeXTBus burst**:
- Single address cycle + multiple data cycles
- Reduces bus overhead
- Improves effective bandwidth from ~50 MB/s to ~80 MB/s

**Optimization**: Write sequentially to maximize bursts

```assembly
; Good: Sequential writes trigger bursts
loop:
    fst.d   %f0,0(%r10)
    fst.d   %f0,8(%r10)
    fst.d   %f0,16(%r10)
    fst.d   %f0,24(%r10)
    ; Write buffer flushes as 4-entry burst

; Bad: Non-sequential writes prevent bursts
loop:
    fst.d   %f0,0(%r10)
    fst.d   %f0,1000(%r10)
    fst.d   %f0,2000(%r10)
    ; Each write is separate NeXTBus transaction
```

### Cache Management

**i860 Cache Flush Instruction**: `flush`

```assembly
; Flush cache line containing address
flush   0(%r16)         ; Flush cache line at r16
flush   32(%r16)        ; Flush next line (32-byte lines)
```

**When to Flush**:

1. **Before DMA from i860 to host**:
   ```c
   // Ensure writes are visible to host
   flush_range(buffer_start, buffer_end);
   ```

2. **After DMA from host to i860**:
   ```c
   // Invalidate cache to see new data
   invalidate_range(buffer_start, buffer_end);
   ```

3. **Before kernel→host result**:
   ```c
   // Flush result structure before signaling completion
   flush_range(&result, &result + sizeof(result));
   ```

**Framebuffer writes**: Likely bypass cache (uncached region), so no flush needed.

### Performance Comparison

| Method | Bytes/Cycle | MB/s @ 33MHz | Notes |
|--------|-------------|--------------|-------|
| 32-bit ld/st | 4 | 132 | Basic load/store |
| 64-bit FPU | 8 | 264 | fld.d / fst.d |
| 128-bit FPU | 16 | 528 | fld.q / fst.q |
| **Actual (NeXTBus limited)** | ~2.4 | **~80** | **Real bottleneck** |

**Key Insight**: i860 compute capability far exceeds bus bandwidth. Graphics performance is **bus-limited**, not CPU-limited.

---

## Rasterization Acceleration

### Display PostScript Execution

**Question**: Does the i860 kernel perform rasterization (line drawing, polygon filling, bezier curves)?

**Answer**: **NO** - based on architecture analysis

#### Evidence

1. **Protocol Analysis**: No commands for primitive geometry
   - No `DRAW_LINE`, `DRAW_POLYGON`, `FILL_BEZIER` commands
   - Only memory operations: `FILL_RECT`, `BLIT`, `UPDATE_FB`

2. **Architecture Documentation**: NeXT's published architecture shows:
   ```
   Host (68040):
     - WindowServer executes Display PostScript interpreter
     - Rasterizes to bitmap
     - Sends bitmaps to NeXTdimension

   i860:
     - Receives pre-rasterized bitmaps
     - Copies to framebuffer
     - No geometric processing
   ```

3. **Performance Model**: Makes sense given bandwidth constraints
   - Rasterization needs many small writes (pixels)
   - Better done by host with local memory
   - Transfer completed bitmap to i860 (one DMA)

### Rendering Pipeline

```
┌──────────────────────────────────────────────────┐
│  Host (68040 @ 25 MHz)                           │
│                                                  │
│  Application                                     │
│      ↓                                           │
│  WindowServer                                    │
│      ↓                                           │
│  Display PostScript Interpreter                  │
│      ↓                                           │
│  Rasterize to off-screen bitmap                  │
│      - Line drawing (Bresenham)                  │
│      - Polygon scan conversion                   │
│      - Bezier curve approximation                │
│      - Alpha blending                            │
│      - Anti-aliasing                             │
│      ↓                                           │
│  Completed bitmap in host RAM                    │
└──────┼───────────────────────────────────────────┘
       │ NeXTBus
       ↓ CMD_UPDATE_FB (bitmap transfer)
┌──────┼───────────────────────────────────────────┐
│      ↓            i860 Kernel                    │
│                                                  │
│  Receive UPDATE_FB command                       │
│      ↓                                           │
│  DMA bitmap from host RAM                        │
│      ↓                                           │
│  Copy to VRAM at specified (x, y)                │
│      ↓                                           │
│  Signal completion to host                       │
└──────────────────────────────────────────────────┘
```

### Why This Design?

**Advantages of host-side rasterization**:

1. **Complexity**: Display PostScript is complex - full interpreter on i860 would be large
2. **Memory locality**: Host can rasterize to local RAM with low latency
3. **Bandwidth efficiency**: Transfer final bitmap once, not many small commands
4. **CPU utilization**: Host 68040 and i860 work in parallel
5. **Software compatibility**: WindowServer already has DPS interpreter

**i860 role**: **Framebuffer blitter**, not general-purpose GPU

---

## Video I/O & Capture

### Video Capture (VIDEO_CAPTURE)

#### Hardware Components

1. **Video Input Digitizer**:
   - Composite and S-Video inputs
   - Digitizes analog video to RGB format
   - Standards: NTSC (640×480 @ 30 Hz), PAL (768×576 @ 25 Hz)

2. **Video Capture Path**:
   ```
   Analog Video Input
         ↓
   Video Digitizer (SAA7191 or similar)
         ↓ Digital RGB/YUV
   Color Space Converter (if needed)
         ↓ RGB 32-bit
   DMA to i860 DRAM
         ↓
   Capture Buffer in DRAM
   ```

#### Command Structure

```c
// Start video capture
mailbox->command = CMD_VIDEO_CAPTURE;
mailbox->arg1 = format;              // NTSC (0) or PAL (1)
mailbox->arg2 = buffer_addr;         // DRAM address for captured frames
mailbox->arg3 = buffer_size;         // Buffer size (bytes)
mailbox->arg4 = flags;               // Capture options
```

#### Implementation

**Double Buffering** for continuous capture:

```c
#define NTSC_WIDTH  640
#define NTSC_HEIGHT 480
#define FRAME_SIZE  (NTSC_WIDTH * NTSC_HEIGHT * 4)

// Ping-pong buffers in DRAM
uint32_t capture_buffer_A[NTSC_WIDTH * NTSC_HEIGHT];
uint32_t capture_buffer_B[NTSC_WIDTH * NTSC_HEIGHT];

bool capturing = false;
uint32_t *current_buffer = capture_buffer_A;
uint32_t *ready_buffer = NULL;

void start_video_capture(uint32_t format) {
    // Configure video input controller
    write_video_reg(VIDEO_INPUT_SELECT, VIDEO_INPUT_COMP1);
    write_video_reg(VIDEO_STANDARD, format);  // NTSC or PAL

    // Set up capture DMA
    write_video_reg(VIDEO_CAPTURE_ADDR, (uint32_t)current_buffer);
    write_video_reg(VIDEO_CAPTURE_SIZE, FRAME_SIZE);

    // Enable VBlank interrupt
    enable_interrupt(IRQ_VIDEO_VBL);

    // Start capture
    write_video_reg(VIDEO_CONTROL, VIDEO_CTRL_CAPTURE_EN);
    capturing = true;
}

void video_vblank_interrupt_handler(void) {
    if (!capturing) return;

    // Swap buffers
    ready_buffer = current_buffer;
    current_buffer = (current_buffer == capture_buffer_A) ?
                     capture_buffer_B : capture_buffer_A;

    // Setup next frame capture
    write_video_reg(VIDEO_CAPTURE_ADDR, (uint32_t)current_buffer);

    // Signal host that frame is ready
    signal_host_frame_ready(ready_buffer);
}
```

#### Performance

**NTSC Capture**:
```
Resolution: 640 × 480 × 32bpp
Frame size: 1,228,800 bytes (~1.17 MB)
Frame rate: 29.97 fps (NTSC)
Bandwidth: ~35 MB/s
```

**PAL Capture**:
```
Resolution: 768 × 576 × 32bpp
Frame size: 1,769,472 bytes (~1.69 MB)
Frame rate: 25 fps (PAL)
Bandwidth: ~42 MB/s
```

**Feasibility**: Well within i860 and NeXTBus capabilities.

---

### Genlock Synchronization

#### Purpose

**Genlock**: Synchronize NeXTdimension video output to external video source (e.g., broadcast equipment).

**Use Cases**:
- Video production: Mix NeXT graphics with live video
- Broadcast: Ensure frame-accurate timing
- Multi-monitor setups: Sync multiple displays

#### Hardware

**Bt463 RAMDAC** has genlock capability:
- External sync input
- Phase-locked loop (PLL) for sync
- Adjustable phase offset

#### Command Structure

```c
// Enable genlock
mailbox->command = CMD_GENLOCK_EN;
mailbox->arg1 = input_source;        // GENLOCK_COMPOSITE, GENLOCK_SVIDEO
mailbox->arg2 = 0;                   // Reserved

// Disable genlock
mailbox->command = CMD_GENLOCK_DIS;
```

#### Implementation

```c
#define GENLOCK_TIMEOUT_MS  1000

int enable_genlock(uint32_t source) {
    // Configure genlock input
    write_ramdac_reg(BT463_GENLOCK_CTRL, source);

    // Enable PLL lock
    write_ramdac_reg(BT463_PLL_CTRL, PLL_ENABLE | PLL_GENLOCK_MODE);

    // Wait for lock
    uint32_t start_time = get_time_ms();
    while (get_time_ms() - start_time < GENLOCK_TIMEOUT_MS) {
        uint32_t status = read_ramdac_reg(BT463_PLL_STATUS);
        if (status & PLL_LOCKED) {
            return SUCCESS;
        }
        delay_us(100);
    }

    // Timeout - no sync signal detected
    return ERR_GENLOCK_NO_SIGNAL;
}

void disable_genlock(void) {
    // Return to internal sync
    write_ramdac_reg(BT463_PLL_CTRL, PLL_ENABLE | PLL_INTERNAL_MODE);
}
```

#### Phase Adjustment

**Fine-tune sync timing**:

```c
void adjust_genlock_phase(int8_t phase_offset) {
    // phase_offset: -127 to +127 (arbitrary units)
    write_ramdac_reg(BT463_PHASE_ADJUST, (uint8_t)phase_offset);
}
```

---

### ScreenScape Output

**ScreenScape**: NeXT's feature to output framebuffer to NTSC/PAL video.

#### Implementation

```
Framebuffer (1120×832 @ 68.7 Hz)
      ↓
Capture region of interest (e.g., 640×480)
      ↓
Scale if necessary (overscan, underscan)
      ↓
RGB → YUV conversion (if needed)
      ↓
Video Encoder (SAA7192 or similar)
      ↓
Composite/S-Video output (NTSC/PAL)
```

#### Scaling Challenge

**Problem**: Framebuffer is 1120×832, NTSC is 640×480

**Solutions**:

1. **No scaling**: Output 640×480 region as-is
   ```c
   set_video_output_region(0, 0, 640, 480);
   ```

2. **Integer scaling**: 2:1 scaling (2×2 pixels → 1 pixel)
   ```c
   // Output full framebuffer scaled down
   set_video_output_region(0, 0, 1120, 832);
   set_video_scale_mode(SCALE_2_TO_1);
   ```

3. **Arbitrary scaling**: Requires resampling (slow)
   - Likely NOT implemented in hardware
   - Would require software filter (bilinear, etc.)

**Most likely**: ScreenScape outputs **center 640×480 region** without scaling.

#### Color Space Conversion

**Framebuffer**: RGB 32-bit
**Video output**: YUV (composite) or Y/C (S-Video)

**Hardware encoder** (e.g., SAA7192) performs RGB→YUV conversion automatically.

---

## Performance Optimization

### Dual Instruction Issue

**i860XR Architecture**:
- **Core unit**: Integer ALU, load/store, branches
- **FPU unit**: Floating-point operations, FPU load/store
- **Dual-issue**: Can execute **one core + one FPU instruction per cycle**

#### Dual-Issue Example

**Optimized fill loop**:

```assembly
; Dual-issue fill loop
fill_loop:
    fst.d   %f0,0(%r10)             ; FPU: Store 8 bytes
    adds    8,%r10,%r10             ; CORE: Increment pointer (parallel!)
    fst.d   %f0,0(%r10)             ; FPU: Store 8 bytes
    subs    1,%r11,%r11             ; CORE: Decrement counter (parallel!)
    fst.d   %f0,0(%r10)             ; FPU: Store 8 bytes
    adds    8,%r10,%r10             ; CORE: Increment pointer (parallel!)
    fst.d   %f0,0(%r10)             ; FPU: Store 8 bytes
    bc      fill_loop               ; CORE: Branch if count > 0
    adds    8,%r10,%r10             ; CORE: Increment (delay slot)

; Cycles per 4 × 8-byte stores (32 bytes):
;   fst.d #1:  1 cycle (FPU)  | adds: 0 (parallel)
;   fst.d #2:  1 cycle (FPU)  | subs: 0 (parallel)
;   fst.d #3:  1 cycle (FPU)  | adds: 0 (parallel)
;   fst.d #4:  1 cycle (FPU)  | bc:   0 (parallel, taken)
;   delay slot adds: 1 cycle
; Total: ~5 cycles for 32 bytes = 6.4 bytes/cycle = 211 MB/s
; Actual: Limited by write buffer and NeXTBus to ~80 MB/s
```

**Achieved IPC**: ~1.6-1.8 instructions per cycle (near dual-issue ideal of 2.0)

### FPU Utilization

#### Graphics Use of FPU

The i860 FPU is used for **data movement**, not arithmetic:

1. **fld.d / fst.d**: 64-bit loads/stores (8 bytes)
2. **fld.q / fst.q**: 128-bit loads/stores (16 bytes)
3. **ixfr / fxfr**: Move data between integer and FPU registers

**No floating-point arithmetic** needed for framebuffer operations!

#### FPU Registers as Data Buffers

```assembly
; Load color into FPU register
ixfr    %r20,%f16               ; f16 = color (32-bit)

; Duplicate to create 64-bit value (2 pixels)
fxfr    %f16,%r21
ixfr    %r21,%f17               ; f16:f17 = 2 × color

; Now can use fst.d to write 2 pixels at once
fst.d   %f16,0(%r10)            ; Write 2 pixels
```

#### SIMD-Like Operation

```assembly
; "SIMD" fill using quad FPU registers
; f16:f17:f18:f19 = 4 × color (16 bytes, 4 pixels)

ixfr    %r20,%f16               ; f16 = color
fxfr    %f16,%r21
ixfr    %r21,%f17               ; f17 = color
ixfr    %r21,%f18               ; f18 = color
ixfr    %r21,%f19               ; f19 = color

; Write 4 pixels with one instruction
fst.q   %f16,0(%r10)            ; Store 16 bytes (4 pixels)
```

**Not true SIMD**: No parallel arithmetic, just wide data paths.

---

### Memory Bandwidth Optimization

#### Theoretical Limits

**NeXTBus Specifications**:
- Clock: 33 MHz
- Width: 32 bits (4 bytes)
- Theoretical: 33 MHz × 4 bytes = 132 MB/s

**Practical Limits**:
- Bus arbitration overhead
- Address cycles
- Wait states
- Typical: **~80-100 MB/s**

**i860 Write Buffer**:
- Entries: 4
- Coalesces sequential writes
- Enables burst mode on bus

#### Achieving Peak Bandwidth

**Optimization Strategies**:

1. **Sequential Writes**:
   ```c
   // Good: Sequential
   for (i = 0; i < 1000; i++) {
       framebuffer[i] = color;
   }
   // Triggers write buffer coalescing + NeXTBus bursts

   // Bad: Random access
   for (i = 0; i < 1000; i++) {
       framebuffer[random()] = color;
   }
   // No bursts, poor performance
   ```

2. **Large Transfers**:
   ```c
   // Better: Transfer 64 KB blocks (optimal for bus)
   memcpy_vram(dst, src, 65536);

   // Worse: Many small transfers
   for (i = 0; i < 100; i++) {
       memcpy_vram(dst + i*100, src + i*100, 100);
   }
   ```

3. **Alignment**:
   ```c
   // Aligned transfers are faster
   void *aligned_malloc(size_t size) {
       return (void*)((((uint32_t)malloc(size + 15)) + 15) & ~15);
   }
   ```

4. **Minimize Reads**:
   ```c
   // Reads are slower than writes on NeXTBus
   // Write-only operations preferred

   // Good: Fill (write-only)
   memset_vram(framebuffer, 0, size);

   // Slower: Blit (read + write)
   memcpy_vram(dst, src, size);
   ```

#### Measured Performance

**Real-world benchmarks** (estimated from architecture):

| Operation | Size | Time | Bandwidth |
|-----------|------|------|-----------|
| Fill screen | 3.73 MB | ~47 ms | ~79 MB/s |
| Blit 640×480 | 1.17 MB | ~20 ms | ~58 MB/s |
| Host→VRAM | 1.17 MB | ~25 ms | ~47 MB/s |

**Bottleneck**: Always NeXTBus, not CPU.

---

## Implementation Guide for Emulation

### Framebuffer Emulation

```c
// Previous emulator framebuffer structure
typedef struct {
    uint32_t base_addr;         // 0x10000000
    uint32_t width;             // 1120
    uint32_t height;            // 832
    uint32_t stride;            // 4480 bytes
    uint32_t *pixels;           // Host memory backing store
    bool dirty;                 // Needs display update
    SDL_Texture *texture;       // For rendering (if using SDL)
} nd_framebuffer_t;

nd_framebuffer_t framebuffer = {
    .base_addr = 0x10000000,
    .width = 1120,
    .height = 832,
    .stride = 4480,
    .pixels = NULL,
    .dirty = false,
    .texture = NULL
};

// Initialize framebuffer
void nd_fb_init(void) {
    size_t fb_size = framebuffer.stride * framebuffer.height;
    framebuffer.pixels = (uint32_t*)calloc(fb_size, 1);

    // Create texture for display (SDL example)
    framebuffer.texture = SDL_CreateTexture(
        renderer,
        SDL_PIXELFORMAT_ARGB8888,  // Match NeXTdimension format
        SDL_TEXTUREACCESS_STREAMING,
        framebuffer.width,
        framebuffer.height
    );
}

// Memory-mapped I/O handlers
uint32_t nd_fb_read(uint32_t addr) {
    if (addr >= framebuffer.base_addr &&
        addr < framebuffer.base_addr + (framebuffer.stride * framebuffer.height)) {
        uint32_t offset = (addr - framebuffer.base_addr) / 4;
        return framebuffer.pixels[offset];
    }
    return 0;  // Out of bounds
}

void nd_fb_write(uint32_t addr, uint32_t value) {
    if (addr >= framebuffer.base_addr &&
        addr < framebuffer.base_addr + (framebuffer.stride * framebuffer.height)) {
        uint32_t offset = (addr - framebuffer.base_addr) / 4;
        framebuffer.pixels[offset] = value;
        framebuffer.dirty = true;  // Mark for display update
    }
}

// Display update (call periodically, e.g., at 60 Hz)
void nd_fb_update_display(void) {
    if (!framebuffer.dirty) return;

    // Update SDL texture with framebuffer contents
    SDL_UpdateTexture(
        framebuffer.texture,
        NULL,  // Update entire texture
        framebuffer.pixels,
        framebuffer.stride  // Pitch in bytes
    );

    // Render texture
    SDL_RenderCopy(renderer, framebuffer.texture, NULL, NULL);
    SDL_RenderPresent(renderer);

    framebuffer.dirty = false;
}
```

### Graphics Command Emulation

```c
// Emulate CMD_FILL_RECT
void emulate_fill_rect(uint16_t x, uint16_t y, uint16_t width, uint16_t height, uint32_t color) {
    uint32_t *fb = &framebuffer.pixels[y * framebuffer.width + x];

    for (uint16_t row = 0; row < height; row++) {
        // Fast fill using platform-optimized memset or SIMD
        for (uint16_t col = 0; col < width; col++) {
            fb[col] = color;
        }
        fb += framebuffer.width;  // Next scanline
    }

    framebuffer.dirty = true;
}

// Emulate CMD_BLIT
void emulate_blit(uint16_t src_x, uint16_t src_y,
                  uint16_t dst_x, uint16_t dst_y,
                  uint16_t width, uint16_t height) {
    uint32_t *src = &framebuffer.pixels[src_y * framebuffer.width + src_x];
    uint32_t *dst = &framebuffer.pixels[dst_y * framebuffer.width + dst_x];

    // Handle overlapping regions
    if (dst_y > src_y || (dst_y == src_y && dst_x > src_x)) {
        // Backward copy
        src += (height - 1) * framebuffer.width;
        dst += (height - 1) * framebuffer.width;

        for (int row = height - 1; row >= 0; row--) {
            memmove(dst, src, width * sizeof(uint32_t));
            src -= framebuffer.width;
            dst -= framebuffer.width;
        }
    } else {
        // Forward copy
        for (uint16_t row = 0; row < height; row++) {
            memmove(dst, src, width * sizeof(uint32_t));
            src += framebuffer.width;
            dst += framebuffer.width;
        }
    }

    framebuffer.dirty = true;
}

// Emulate CMD_UPDATE_FB
void emulate_update_fb(uint16_t x, uint16_t y, uint16_t width, uint16_t height,
                       uint32_t *host_data) {
    uint32_t *src = host_data;
    uint32_t *dst = &framebuffer.pixels[y * framebuffer.width + x];

    for (uint16_t row = 0; row < height; row++) {
        memcpy(dst, src, width * sizeof(uint32_t));
        src += width;
        dst += framebuffer.width;
    }

    framebuffer.dirty = true;
}
```

### Command Dispatcher

```c
// Mailbox command dispatcher
void nd_mailbox_dispatch_command(nd_mailbox_regs_t *mailbox) {
    uint32_t cmd = mailbox->command;

    switch (cmd) {
        case CMD_NOP:
            // No operation
            break;

        case CMD_FILL_RECT: {
            uint16_t x = (mailbox->arg1 >> 16) & 0xFFFF;
            uint16_t y = mailbox->arg1 & 0xFFFF;
            uint16_t width = (mailbox->arg2 >> 16) & 0xFFFF;
            uint16_t height = mailbox->arg2 & 0xFFFF;
            uint32_t color = mailbox->arg3;

            emulate_fill_rect(x, y, width, height, color);

            mailbox->result = 0;  // Success
            break;
        }

        case CMD_BLIT: {
            uint16_t src_x = (mailbox->arg1 >> 16) & 0xFFFF;
            uint16_t src_y = mailbox->arg1 & 0xFFFF;
            uint16_t dst_x = (mailbox->arg2 >> 16) & 0xFFFF;
            uint16_t dst_y = mailbox->arg2 & 0xFFFF;
            uint16_t width = (mailbox->arg3 >> 16) & 0xFFFF;
            uint16_t height = mailbox->arg3 & 0xFFFF;

            emulate_blit(src_x, src_y, dst_x, dst_y, width, height);

            mailbox->result = 0;  // Success
            break;
        }

        case CMD_UPDATE_FB: {
            uint16_t x = (mailbox->arg1 >> 16) & 0xFFFF;
            uint16_t y = mailbox->arg1 & 0xFFFF;
            uint16_t width = (mailbox->arg2 >> 16) & 0xFFFF;
            uint16_t height = mailbox->arg2 & 0xFFFF;
            uint32_t *host_data = (uint32_t*)mailbox->data_ptr;

            emulate_update_fb(x, y, width, height, host_data);

            mailbox->result = 0;  // Success
            break;
        }

        default:
            mailbox->error_code = ERR_INVALID_COMMAND;
            mailbox->result = 0xFFFFFFFF;
            break;
    }

    // Signal completion
    mailbox->status &= ~MAILBOX_STATUS_BUSY;
    mailbox->status |= MAILBOX_STATUS_COMPLETE;
}
```

### Performance-Accurate Timing

```c
// i860 CPU state with cycle counter
typedef struct {
    uint64_t cycle_count;       // Total cycles executed
    uint32_t clock_mhz;         // 33 MHz
} nd_cpu_state_t;

nd_cpu_state_t cpu = {
    .cycle_count = 0,
    .clock_mhz = 33
};

// Add cycles for operation
void add_cycles(uint32_t cycles) {
    cpu.cycle_count += cycles;
}

// Estimate fill_rect cycles (pessimistic)
uint32_t estimate_fill_cycles(uint16_t width, uint16_t height) {
    // Assume 2 cycles per pixel (FPU store + overhead)
    // Plus setup/loop overhead
    return (width * height * 2) + 100;
}

// Estimate blit cycles
uint32_t estimate_blit_cycles(uint16_t width, uint16_t height) {
    // Load + store = 4 cycles per pixel
    return (width * height * 4) + 200;
}

// Estimate update_fb cycles (includes NeXTBus latency)
uint32_t estimate_update_cycles(uint16_t width, uint16_t height) {
    // Dominated by NeXTBus transfer time
    uint32_t bytes = width * height * 4;
    uint32_t ns_per_byte = 1000000000 / (80 * 1024 * 1024);  // 80 MB/s
    uint32_t total_ns = bytes * ns_per_byte;
    uint32_t cycles = (total_ns * cpu.clock_mhz) / 1000;
    return cycles;
}

// Execute fill_rect with timing
void emulate_fill_rect_timed(uint16_t x, uint16_t y, uint16_t width, uint16_t height, uint32_t color) {
    emulate_fill_rect(x, y, width, height, color);
    add_cycles(estimate_fill_cycles(width, height));
}
```

---

## Performance Benchmarks

### Reference Measurements

**Hardware**: NeXTdimension with i860XR @ 33 MHz, NeXTBus @ 33 MHz

| Operation | Size | Estimated Time | Performance | Notes |
|-----------|------|----------------|-------------|-------|
| Fill screen (solid) | 1120×832 (3.73 MB) | ~47 ms | ~79 MB/s | Limited by NeXTBus |
| Fill rect 640×480 | 1,228,800 bytes | ~16 ms | ~77 MB/s | Sequential writes |
| Blit 640×480 | 1,228,800 bytes | ~21 ms | ~58 MB/s | Read+write overhead |
| Host→VRAM 640×480 | 1,228,800 bytes | ~26 ms | ~47 MB/s | NeXTBus + polling |
| Clear screen | 3,727,360 bytes | ~47 ms | ~79 MB/s | Optimized fill |
| Scroll (blit full screen) | 3,727,360 bytes | ~64 ms | ~58 MB/s | Overlapping regions |

### Frame Rate Analysis

**Typical WindowServer Operations**:

```
Operation: Repaint 640×480 window
  1. Host renders to bitmap:     ~20 ms (68040 DPS rendering)
  2. Transfer bitmap to i860:    ~26 ms (CMD_UPDATE_FB)
  3. Total:                       ~46 ms (21 fps)

Operation: Scroll 1120×832 display
  1. Blit framebuffer:            ~64 ms (CMD_BLIT)
  2. Fill exposed region:         ~8 ms (CMD_FILL_RECT)
  3. Total:                       ~72 ms (13 fps)

Operation: Drag window (200×300)
  1. Blit window region:          ~3 ms
  2. Redraw background:           ~2 ms
  3. Total:                       ~5 ms (200 fps)
```

**Conclusion**: Small operations fast, full-screen operations slower (~20-30 fps).

### Comparison with Contemporary Hardware

| System | Year | CPU | Fill Rate | Blit Rate | Notes |
|--------|------|-----|-----------|-----------|-------|
| **NeXTdimension** | **1991** | **i860XR 33 MHz** | **~30 Mpix/s** | **~15 Mpix/s** | **Software rendering** |
| Macintosh IIci | 1989 | 68030 25 MHz | ~10 Mpix/s | ~8 Mpix/s | Software only |
| Sun SPARCstation 2 + GX | 1992 | SPARC 40 MHz + accel | ~50 Mpix/s | ~40 Mpix/s | Hardware acceleration |
| SGI Indigo | 1991 | R3000 33 MHz + GR | ~80 Mpix/s | ~60 Mpix/s | Dedicated graphics ASIC |
| IBM RS/6000 + GXT | 1990 | POWER 25 MHz + accel | ~40 Mpix/s | ~30 Mpix/s | Hardware blitter |

**NeXTdimension Position**: Mid-range performance for era. Outperforms software-only systems, but slower than dedicated graphics accelerators.

**Unique Strength**: True color (32-bit) at high resolution (1120×832) was uncommon in 1991.

---

## Cross-References

### Related Documentation

- **HOST_I860_PROTOCOL_SPEC.md**: Complete mailbox command protocol
- **ND_MACHDRIVER_ANALYSIS.md**: i860 kernel structure analysis
- **ROM_BOOT_SEQUENCE_DETAILED.md**: RAMDAC configuration and boot sequence
- **nextdimension.h**: Hardware register definitions

### Hardware References

- **Bt463 RAMDAC**: Brooktree 168 MHz triple DAC datasheet
- **Intel i860XR**: Microprocessor architecture manual
- **NeXTBus**: NeXT Bus Specification

---

## Appendices

### Appendix A: i860 Graphics Optimization Patterns

#### Pattern 1: Dual-Issue Fill Loop

```assembly
; Maximum throughput fill using dual-issue
optimized_fill:
    orh     0x1000,%r0,%r10         ; VRAM base
    ixfr    %r20,%f16               ; Load color to FPU

.loop:
    fst.d   %f16,0(%r10)            ; FPU: Store 8 bytes
    adds    8,%r10,%r10             ; CORE: Advance pointer (parallel)
    fst.d   %f16,0(%r10)            ; FPU: Store 8 bytes
    subs    2,%r11,%r11             ; CORE: Counter -= 2 (parallel)
    bc      .loop                   ; CORE: Branch if count > 0
    adds    8,%r10,%r10             ; CORE: Advance (delay slot)

    bri     %r1
    nop

; Achieves ~1.6 IPC with 16 bytes per 5 cycles = 105 MB/s theoretical
```

#### Pattern 2: Unrolled Blit Loop

```assembly
; 4× unrolled blit for better pipelining
optimized_blit:
    shr     2,%r18,%r18             ; count /= 4

.loop:
    fld.d   0(%r16),%f0             ; Load 8 bytes
    fld.d   8(%r16),%f8             ; Load 8 bytes (pipeline)
    fld.d   16(%r16),%f16           ; Load 8 bytes (pipeline)
    fld.d   24(%r16),%f24           ; Load 8 bytes (pipeline)

    fst.d   %f0,0(%r17)             ; Store 8 bytes
    fst.d   %f8,8(%r17)             ; Store 8 bytes
    fst.d   %f16,16(%r17)           ; Store 8 bytes
    fst.d   %f24,24(%r17)           ; Store 8 bytes

    adds    32,%r16,%r16            ; src += 32
    adds    32,%r17,%r17            ; dst += 32

    subs    1,%r18,%r18
    bc      .loop
    nop

    bri     %r1
    nop

; Achieves ~70-90 MB/s depending on cache hit rate
```

### Appendix B: Framebuffer Memory Map Details

```
VRAM Organization @ 0x10000000

Offset      Size        Usage
----------  ----------  ----------------------------------------
0x00000000  3,727,360   Main framebuffer (1120×832×32bpp)
0x0038F480    327,360   Unused VRAM (~320 KB)
                        - Can store off-screen buffers
                        - Cursor images (32×32×32bpp = 4 KB)
                        - Small textures/tiles
                        - Pattern fills

Address Calculation Examples:
  Pixel (0, 0):     0x10000000
  Pixel (100, 50):  0x10000000 + (50 * 4480) + (100 * 4) = 0x10037CD0
  Pixel (1119, 831): 0x10000000 + (831 * 4480) + (1119 * 4) = 0x1038F47C
  End of FB:        0x1038F480
  End of VRAM:      0x103FFFFF
```

### Appendix C: Bt463 RAMDAC Configuration

From ROM_BOOT_SEQUENCE_DETAILED.md, the Bt463 is configured for:

```
Display Mode:        1120×832 @ 68.7 Hz
Pixel Clock:         ~100 MHz
DAC Speed:           168 MHz (triple DAC, 3×8-bit)
Color Depth:         24-bit RGB (8:8:8) + 8-bit unused
Horizontal Timing:   1472 total, 1120 active
Vertical Timing:     870 total, 832 active
Sync Polarity:       Negative H/V sync
```

**Key Registers** (28 total programmed by ROM):
- Command registers: Display control, blink rate, cursor control
- Color palette: 256-entry LUT (unused in 24-bit mode)
- Cursor: 64×64 2-bit cursor with 3 colors + transparent

### Appendix D: Video Timing Calculations

**Pixel Clock Calculation**:
```
Horizontal total: 1472 pixels
Vertical total:   870 lines
Refresh rate:     68.7 Hz

Pixel clock = 1472 × 870 × 68.7 Hz
            = 87,959,520 Hz
            ≈ 88 MHz (documented as ~100 MHz - need verification)
```

**Blanking Intervals**:
```
Horizontal blanking: 1472 - 1120 = 352 pixels (23.9% of line)
Vertical blanking:   870 - 832 = 38 lines (4.4% of frame)

Visible time per frame: 1120 × 832 / (1472 × 870) = 72.7%
```

**VBlank Duration**:
```
Frame time: 1000 ms / 68.7 Hz = 14.55 ms
VBlank time: 38 lines / 870 lines × 14.55 ms = 0.64 ms

Available for VBlank operations: ~640 µs
At 80 MB/s: Can transfer ~51 KB during VBlank
```

### Appendix E: Emulator Implementation Checklist

**Minimum Implementation** (for basic NeXTSTEP compatibility):

- [ ] Framebuffer at 0x10000000 (1120×832×32bpp)
- [ ] Memory-mapped read/write handlers
- [ ] CMD_FILL_RECT command
- [ ] CMD_BLIT command
- [ ] CMD_UPDATE_FB command
- [ ] Mailbox protocol (status, command, result registers)
- [ ] Display update at 60 Hz

**Enhanced Implementation** (for better accuracy):

- [ ] Cycle-accurate timing for operations
- [ ] VBlank interrupt generation (68.7 Hz)
- [ ] CMD_VIDEO_CAPTURE emulation
- [ ] CMD_GENLOCK_EN/DIS emulation
- [ ] Cursor rendering (64×64 hardware cursor)
- [ ] Off-screen buffer support

**Advanced Implementation** (for research/accuracy):

- [ ] Actual i860 instruction emulation
- [ ] Cache simulation (4 KB data cache)
- [ ] Write buffer simulation (4-entry)
- [ ] NeXTBus bandwidth simulation
- [ ] Detailed RAMDAC emulation
- [ ] Video input/output emulation

---

## Conclusion

The NeXTdimension graphics acceleration architecture reflects NeXT's engineering philosophy: **leverage powerful general-purpose compute (i860) for specialized tasks** rather than building custom ASICs. The result is a flexible, programmable graphics subsystem that, while not matching dedicated GPUs of the era, provided excellent 32-bit color performance at high resolution.

**Key Takeaways for Emulation**:

1. **Simple Command Set**: Only 5-6 graphics commands needed (fill, blit, update)
2. **Host-Side Rendering**: No need to emulate DPS interpreter or rasterization
3. **Bandwidth-Limited**: Focus on accurate NeXTBus timing, not CPU instruction accuracy
4. **Direct Framebuffer**: Simple memory-mapped architecture, no complex GPU state

**Emulator Priority**: Get framebuffer access and basic commands working first. Cycle-accurate timing can be approximated initially, then refined based on real software behavior.

This concludes the comprehensive analysis of NeXTdimension graphics acceleration.

---

**Document Status**: ✅ Complete
**Validation**: Based on hardware specifications, protocol analysis, and i860 architecture
**Next Steps**: Implement emulator graphics subsystem using this specification
