### **Architectural Review: NeXTdimension Board Emulation in `Previous` Emulator**

**Document Version:** 1.0
**Date:** July 24, 2025
**Author:** Gemini (AI Assistant)
**Review Scope:** `tools/previous/src/dimension/` module, excluding `i860.cpp`, `i860dec.cpp`, `i860dis.cpp`, `i860dbg.cpp`, `i860cfg.h` (i860 CPU core).

---

#### **1. Executive Summary**

This document presents an architectural review of the NeXTdimension board emulation within the `Previous` emulator, based on a line-by-line analysis of its source code. The current implementation is found to be **functional and modular**, successfully enabling the execution of NeXTSTEP. However, it is primarily an **i860XR-focused and incomplete** emulation of the full hardware capabilities. The review identifies key strengths in its modular design and clear MMIO routing, alongside significant opportunities for enhancement to support the i860XP variant and custom firmware integration.

---

#### **2. Current Architecture Overview**

The `dimension/` module orchestrates the emulation of the NeXTdimension board's peripheral hardware, acting as the interface between the i860 CPU core and the host system. It is structured into several sub-modules, each responsible for a specific hardware component or function:

*   **`dimension.c/.h`**: Top-level orchestrator, handles initialization, reset, and routes 68040 host MMIO accesses.
*   **`nd_devs.c/.h`**: Emulates core i860-side MMIO devices (Mailbox, DMA, Video Controller, Interrupts, System Control).
*   **`nd_mem.c/.h`**: Manages i860 local RAM, VRAM, and ROM, and handles memory accesses from both i860 and 68040.
*   **`nd_nbic.c/.h`**: Emulates the NeXTbus Interface Controller, bridging 68040 and i860 communication.
*   **`nd_vio.c/.h`**: Handles video input/output (ADC/DAC) emulation.
*   **`nd_sdl.c/.h`**: Provides the SDL-based display backend.
*   **`nd_rom.c/.h`**: Manages the i860 boot ROM loading.

The `nextdimension.h` header serves as a comprehensive blueprint, defining the full MMIO map and register bit-fields, many of which are currently unemulated.

---

#### **3. Module-by-Module Analysis**

##### **3.1 `dimension.h` & `dimension.c`**
*   **Purpose:** Top-level control and MMIO routing for the entire NeXTdimension board.
*   **Implementation:** `dimension.c` initializes sub-modules and contains a large `if-else if` chain in `dimension_lget`/`dimension_lput` to dispatch 68040 host MMIO accesses to the correct sub-module (e.g., `nd_devs_lget`, `nd_board_lget`).
*   **Observations:** The `s_nd_mmio_regs` global variable is declared in `dimension.c` but not directly used for register state; actual state resides in `static` globals within sub-modules. Many MMIO regions are currently unhandled, resulting in `Log_Printf(LOG_WARN, "[ND] Unhandled ...")` messages.
*   **Relevance:** This is the central control point. Any top-level configuration for XP variant or custom firmware would be managed here.

##### **3.2 `nd_devs.h` & `nd_devs.c`**
*   **Purpose:** Emulates core i860-side MMIO devices: Mailbox, DMA Controller, Video Controller, Interrupts, System Control.
*   **Implementation:** `nd_devs.c` uses `static volatile` global structs (`s_mailbox`, `s_dma`, etc.) to represent hardware registers. `nd_devs_lget`/`nd_devs_lput` handle i860 MMIO accesses.
    *   **DMA Trigger:** `nd_devs_lput` correctly triggers `nd_devs_dma_start` when `ND_DMA_CTRL_START` is set.
    *   **i860 Control:** Handles `ND_SYS_CTRL_RESET`/`RUN`/`HALT` bits, calling `i860_reset()` and `nd_i860_pause()`.
*   **Observations:** The `nd_devs_dma_start` function currently performs a simple `memcpy`-like loop for DMA transfers.
*   **Relevance:** This module contains the **critical control bits for the i860 CPU** and the **firmware injection point** (within `nd_devs_dma_start` for `ND_DMA_CTRL_HOST_TO_I860` to `ND_DRAM_BASE`).

##### **3.3 `nd_mem.h` & `nd_mem.c`**
*   **Purpose:** Manages i860 local RAM, VRAM, and ROM, and handles memory accesses from both i860 and 68040.
*   **Implementation:** `nd_mem.c` uses global `UINT8` arrays (`ND_ram`, `ND_vram`, `ND_rom`) for physical memory. `nd_board_rd/wr_le/be` functions handle i860 memory accesses, dispatching to `nd_devs_lget/lput` for MMIO regions. `nd_board_lget/lput` handle 68040 host accesses.
*   **Observations:** Explicit support for little-endian and big-endian memory access is present. VRAM writes trigger `nd_sdl_update_vram`.
*   **Relevance:** This is the foundation for MMU and cache emulation. All physical memory accesses flow through here, making it the integration point for XP's MMU and data cache.

##### **3.4 `nd_nbic.h` & `nd_nbic.c`**
*   **Purpose:** Emulates the NeXTbus Interface Controller, bridging communication between the 68040 host and the i860.
*   **Implementation:** `nd_nbic.c` provides basic emulation of NBIC registers (ID, interrupt status/mask) and periodically asserts i860 interrupts via `nd_devs_set_irq`.
*   **Observations:** The NBIC emulation is quite basic.
*   **Relevance:** Responsible for host-initiated DMA and interrupt routing.

##### **3.5 `nd_vio.h` & `nd_vio.c`**
*   **Purpose:** Handles video input/output (ADC/DAC) emulation.
*   **Implementation:** `nd_vio.c` primarily stores values written to video I/O registers. It calls `nd_devs_vblank_start/end` to propagate VBlank signals.
*   **Observations:** The current implementation is very basic, lacking actual video processing or signal generation logic for the SAA7191/SAA7192 chips.
*   **Relevance:** Key for full XP-level video capabilities, as the SAA7191/SAA7192 chips are responsible for video decoding and color space conversion.

##### **3.6 `nd_sdl.h` & `nd_sdl.c`**
*   **Purpose:** Provides the SDL-based display backend for the NeXTdimension.
*   **Implementation:** `nd_sdl.c` initializes SDL, creates a window/renderer/texture, and copies VRAM content to the texture for display. `nd_sdl_wait_vblank` uses a coarse `host_sleep_ms(1)`.
*   **Observations:** VRAM updates are inefficient (full `memcpy`). Display mode setting is simplified.
*   **Relevance:** Requires updates to accurately render XP's enhanced graphics features (pixel formats, hardware cursor, alpha blending).

##### **3.7 `nd_rom.h` & `nd_rom.c`**
*   **Purpose:** Manages the loading of the i860 boot ROM image.
*   **Implementation:** `nd_rom.c` reads a specified file into the `ND_rom` array.
*   **Observations:** Simple and functional.
*   **Relevance:** The primary target for injecting custom firmware by repurposing or extending the ROM loading mechanism.

---

#### **4. Key Strengths of Current Emulation**

1.  **Modular Design:** The codebase is well-separated into logical components, facilitating understanding and future extensions.
2.  **Correct MMIO Routing:** The `lget`/`lput` functions correctly route memory-mapped accesses to the appropriate handlers.
3.  **Endianness Support:** Explicit handling of little-endian and big-endian memory access is present.
4.  **Firmware Injection Point:** The `nd_devs_dma_start` function is confirmed as the ideal place to intercept and inject custom firmware.
5.  **i860 CPU Control:** The `nd_devs_lput` handling of the system control register (specifically `ND_SYS_CTRL_RESET`/`RUN`/`HALT`) provides the direct control needed to swap i860 CPU variants.

---

#### **5. Areas for Enhancement (XP Upgrade & Custom Firmware Integration)**

The review highlights that the `Previous` emulator's NeXTdimension board emulation is a **functional but incomplete** implementation, primarily focused on i860XR. Significant work is required to achieve full i860XP emulation and robust custom firmware integration.

1.  **i860 CPU Core (XP Features):**
    *   **Enhancement:** Implement XP's instruction set, 4MB page support, and MESI cache protocol within the `i860.cpp`/`i860dec.cpp` core.
    *   **Impacted Files:** `i860.cpp`, `i860dec.cpp`, `i860.hpp`.

2.  **Memory Management Unit (MMU):**
    *   **Enhancement:** Implement XP's 4MB page support in `get_address_translation` (within `i860dec.cpp`) and integrate with `nd_mem.c`.
    *   **Impacted Files:** `i860dec.cpp`, `nd_mem.c`.

3.  **Cache System (Data Cache, MESI):**
    *   **Enhancement:** Implement XP's data cache and MESI protocol. All `nd_board_rd/wr` functions in `nd_mem.c` would need to be modified to first check the cache.
    *   **Impacted Files:** `nd_mem.c`.

4.  **DMA Controller:**
    *   **Enhancement:** Implement advanced DMA modes (2D, chained, pattern fill) defined in `nextdimension.h` within `nd_devs.c`.
    *   **Impacted Files:** `nd_devs.c`.

5.  **Video I/O and Display:**
    *   **Enhancement:** Implement full emulation of SAA7191/SAA7192 chips in `nd_vio.c`. Update `nd_sdl.c` to handle all pixel formats, hardware cursor, and alpha blending.
    *   **Impacted Files:** `nd_vio.c`, `nd_sdl.c`.

6.  **System/Control Registers:**
    *   **Enhancement:** Implement emulation for currently unhandled MMIO regions like the Memory Controller (`ND_MC_CSR0`) and Data Path Controller (`ND_DP_CSR`) in `nd_mem.c` and `nd_devs.c`.
    *   **Impacted Files:** `nd_mem.c`, `nd_devs.c`.

7.  **Firmware Loading:**
    *   **Enhancement:** Intercept the firmware load DMA in `nd_devs_dma_start` to inject custom Rust firmware.
    *   **Impacted Files:** `nd_devs.c`.

---

#### **6. Conclusion**

The `Previous` emulator's NeXTdimension board emulation provides a solid, modular foundation for further development. While currently limited to i860XR functionality and simplified hardware models, the codebase offers clear integration points for implementing the i860XP's advanced features and enabling seamless custom firmware development. The `nextdimension.h` file serves as an invaluable guide for these enhancements, providing the detailed register maps and control bits necessary for accurate emulation.