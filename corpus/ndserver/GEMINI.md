# Gemini Context: NDserver Reverse Engineering Project

This directory contains the complete reverse engineering analysis of the **NDserver** binary, the host-side driver for the NeXTdimension graphics board (Intel i860-based) from NeXTSTEP 3.3.

## Project Overview

*   **Target:** `NDserver` (m68k Mach-O binary, ~816KB).
*   **Architecture:** Motorola 68040 host communicating with an Intel i860 graphics processor.
*   **Status:** ✅ **100% COMPLETE**. All 88 identified functions have been analyzed.
*   **Goal:** Documentation of the host-to-board protocol, graphics command dispatch, and hardware initialization.

## Directory Structure

*   `docs/functions/`: Comprehensive analysis reports for all 88 functions (Markdown).
*   `disassembly/functions/`: Annotated m68k assembly for each function.
*   `ghidra_export/`: Programmatic metadata (`functions.json`, `call_graph.json`).
*   `database/`: Structured JSON data for call graphs, hardware accesses, and OS library calls.
*   `scripts/`: Python and Shell scripts used for automation, analysis, and monitoring.
*   `extracted/`: Binaries and data sections extracted from the main executable (e.g., `i860_kernel.bin`).
*   `logs/`: Progress logs and background monitor status from the analysis waves.

## Key Technical Findings

### 1. Two-Way IPC Bridge (Architecture Revealed)
The binary is split into two distinct functional halves, facilitating bidirectional communication between the 68040 host and the i860 board:
*   **MIG Clients (0x3cdc - 0x59f8):** 31 Display PostScript operators (Opcodes 100-130) that the host uses to send graphics commands to the i860.
*   **MIG Servers (0x6000 - 0x6d24):** Server-side unmarshalling stubs and demuxers (Opcodes 1800+) that allow the i860 to request services from the host (e.g., `vm_allocate`, console printing).
    *   **Demuxer:** `FUN_000061f4` acts as the dispatcher for subsystem 1800.
    *   **Stubs:** Functions like `FUN_00006b7c` are MIG-generated validation wrappers, **not** locking algorithms.

### 2. Hardware Synchronization
*   **Hardware Spinlock (0x5c70):** Implements a software spinlock using shared memory because the NeXTbus lacked atomic locking between the 68040 and i860.
    *   **Algorithm:** Reads lock word, masks bits, loops with `usleep(100000)` backoff if busy.
    *   **Timeout:** 179 retries (~17.9 seconds) before failure.

### 3. Display PostScript (DPS) Acceleration
*   **Dispatch Table:** A 28-operator table (addresses `0x3cdc` to `0x59f8`) handles graphics primitives.
*   **Operators:** Color allocation, graphics state (gsave/grestore), BitBlit, image rendering, and font management.
*   **MakeFont (0x4f64):** Acts as a proxy descriptor builder, marshaling font names and matrices to the i860 for native instantiation.

### 4. Firmware Loading & Hardware Quirks
*   **Mach-O Loader (0x709c):** A custom loader for the i860 firmware (`i860_kernel.bin`).
*   **Byte-Lane Swap:** Uses an `addr ^ 4` XOR hack (`eori.w #0x4`) to handle 32-bit (68040) to 64-bit (i860/NeXTbus) endianness/lane mismatches during boot loading.

## Documentation Usage

*   **Function Analysis:** Start with `docs/functions/0x00002dc6_ND_GetBoardList.md` (the entry point).
*   **Reference Guides:** 
    *   `docs/POSTSCRIPT_OPERATORS_REFERENCE.md`: Deep dive into graphics commands.
    *   `docs/PROJECT_COMPLETION_SUMMARY.md`: High-level technical overview.
    *   `docs/FUNCTION_INDEX.md`: Master list of all functions and their purposes.
*   **Call Graph:** Use `database/call_graph_complete.json` for programmatic relationship analysis.

## Development Tools

The project utilized specialized scripts for the analysis workflow:
*   `scripts/annotate_functions.py`: Automated the generation of function docs.
*   `scripts/analyze_call_graph.py`: Processed Ghidra exports into the database.
*   `scripts/background_monitor.sh`: Tracked parallel analysis tasks during "Waves".

## Historical Context

This analysis provides critical insights for emulator development (e.g., for the `Previous` emulator) and preserves technical details of the high-end NeXTdimension graphics subsystem, which was a pioneer in dual-processor workstation graphics.
