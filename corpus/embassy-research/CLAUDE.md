# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Previous is a NeXT Computer emulator that boots NeXTStep 0.x to 4.0 beta and OpenStep 4.2. It's based on the Atari emulator Hatari, uses the WinUAE m68k emulation core, and includes an i860 emulator for NeXTdimension graphics board support.

## Build Commands

### Standard Build
```bash
# From repository root
mkdir -p build
cd build
cmake ..
make -j$(nproc)
```

The executable will be created at `build/src/Previous`.

### Configuration Options

Use the `./configure` wrapper script for common options:
```bash
./configure --help                    # Show all options
./configure --enable-debug            # Debug build (with some optimization)
./configure --disable-tracing         # Disable tracing for debugging
./configure --disable-osx-bundle      # Disable macOS app bundle
./configure --prefix=/usr/local       # Set install prefix
```

Or use CMake directly:
```bash
cmake . -DCMAKE_BUILD_TYPE=Release    # Release build
cmake . -DCMAKE_BUILD_TYPE=Debug      # Debug build
cmake . -DENABLE_TRACING:BOOL=0       # Disable tracing
```

### Platform-Specific Builds

**macOS Bundle:**
```bash
cmake . -DENABLE_OSX_BUNDLE=1
make
# Creates Previous.app bundle
```

**Windows Cross-Compile (from Linux):**
```bash
cmake . -DCMAKE_TOOLCHAIN_FILE=cmake/Toolchain-mingw32.cmake
make
```

### Installation
```bash
make install
```

## Architecture Overview

Previous is a **cycle-accurate, event-driven emulator** with several key architectural components:

### Core Emulation Loop

**Main thread execution flow:**
1. M68000 CPU executes instructions (`src/cpu/newcpu.c`)
2. After each instruction, `M68000_AddCycles()` increments cycle counter
3. When cycle threshold reached, `CycInt_SetNewInt()` fires pending interrupt
4. Interrupt handlers trigger device operations
5. Every 500µs, event loop processes SDL events (keyboard, mouse, quit)

**Threading model:**
- **Main thread**: 68000 CPU emulation (single-threaded, blocking on events)
- **NeXTdimension thread**: Optional i860 processor (runs in parallel if ND enabled)
- **Synchronization**: Uses volatile `mainPauseEmulation` flag, no mutexes

### Component Organization

**CPU Emulation** (`src/cpu/`):
- UAE-based Motorola 68000/68030/68040 core from WinUAE
- `gencpu.c` and `build68k.c` generate instruction handlers at build time from `table68k` specifications
- Generates ~200K+ lines of optimized C code in `cpuemu.c`
- MMU support: `cpummu.c` (68040), `cpummu030.c` (68030)
- FPU variants: `fpp.c` (68881/68882), separate handlers for 68040
- SoftFloat library (`src/softfloat/`) provides cross-platform FP emulation

**Cycle-Accurate Interrupt System** (`src/cycInt.c`):
- Single "pending interrupt" pattern - only nearest-in-time event is tracked
- 17 interrupt sources: VBL, hardclock, mouse, SCSI, DMA, sound, network, floppy, printer, NeXTdimension
- Three time bases: CPU cycles, ticks, microseconds
- Devices schedule interrupts as side-effects via `CycInt_AddRelativeInterruptUs()`

**Memory Architecture**:
- `src/nextMemory.c`: Main RAM (128MB), ROM (128KB), I/O space (128KB at 0x02000000)
- `src/cpu/memory.c`: UAE memory abstraction layer with endianness conversion
- Inline accessors for fast-path RAM, function dispatch for I/O intercepts

**I/O Interception** (`src/ioMem.c`, `src/ioMemTabNEXT.c`, `src/ioMemTabTurbo.c`):
- Two dispatch tables: `pInterceptReadTable[]` and `pInterceptWriteTable[]`
- Function pointers for each 128KB I/O address range
- Devices register handlers during `IoMem_Init()`
- Device mapping: DMA (0x02000000), Video/RAMDAC, SCC serial, ESP SCSI, Ethernet, Sound, Printer, Floppy, RTC/NVRAM

**Hardware Device Controllers**:
- DMA: `src/dma.c` - 12-channel DMA coordination
- SCSI: `src/scsi.c` + `src/esp.c` - ESP SCSI controller + hard disk
- MO Drive: `src/mo.c` - Magneto-optical removable media
- Floppy: `src/floppy.c` - 3.5" floppy drive
- Ethernet: `src/ethernet.c` + `src/slirp/` - Network via SLIRP stack
- Sound: `src/snd.c` - DMA-driven audio
- Video: `src/video.c`, `src/fast_screen.c`, `src/ramdac.c` - Display with VBL interrupts

**NeXTdimension Graphics Board** (`src/dimension/`):
- Separate Intel i860 RISC processor emulation (`i860.cpp` - C++ class-based)
- Independent 64MB RAM + 128KB ROM + 4MB VRAM address space
- Runs in dedicated SDL thread with event synchronization
- NBIC bridge (`nd_nbic.c`) handles main-bus communication
- Debugger support: `i860dbg.cpp`

**DSP Emulation** (`src/dsp/`):
- Motorola 56001 digital signal processor
- Dual-port memory shared with 68000
- Runs at 4x CPU frequency (20MHz when 68000 @ 25MHz)
- Components: `dsp_core.c` (engine), `dsp_cpu.c` (instructions), `dsp_disasm.c` (debug)

**GUI Layers**:
- `src/gui-sdl/`: Primary cross-platform SDL2-based GUI
- `src/gui-osx/`: macOS-specific Cocoa UI with .nib files
- `src/gui-win/`: Windows console support

**Configuration & State**:
- `src/configuration.c`: Config file parsing and management
- `src/options.c`: Command-line option handling
- `src/reset.c`: Clean reset handling

### Key Data Flow Patterns

**CPU → Device Communication:**
1. CPU instruction writes to I/O address (e.g., 0x02008000 for video)
2. UAE memory layer calls `IoMem_WriteWord/Long/Byte()`
3. Dispatch table lookup finds device handler (e.g., `Video_RAMDAC_Write`)
4. Device updates internal state, may schedule interrupt via `CycInt_Add*()`

**Device → CPU Interrupts:**
1. Device schedules callback: `CycInt_AddRelativeInterruptUs(500, INTERRUPT_SCSI)`
2. When CPU cycle counter reaches threshold, `CycInt_SetNewInt()` triggers
3. Interrupt handler runs (e.g., `SCSI_InterruptHandler()`)
4. Handler may raise CPU interrupt via `M68000_Exception()`

**NeXTdimension Synchronization:**
```c
volatile int mainPauseEmulation;  // 0=none, 1=pause, 2=unpause
// Main thread sets flag when i860 debugger active
// ND thread checks flag each iteration
```

### Build System Details

**CMake structure:**
- Root `CMakeLists.txt`: Platform detection, library finding (SDL2, libpng, zlib)
- `src/CMakeLists.txt`: Main executable linking
- Subdirectory builds: `cpu/`, `debug/`, `dsp/`, `dimension/`, `slirp/`, `softfloat/`, `gui-sdl/`

**Code generation during build:**
1. `build68k` reads `cpu/table68k` instruction specs
2. `gencpu` generates `cpuemu.c` with handlers for all 68000 opcodes
3. Generated code compiled into `UaeCpu` static library
4. Linked into final `Previous` executable

**Dependencies:**
- **Required**: SDL2 (≥2.0.5), libpng, zlib
- **Optional**: readline (debugger), X11 (Linux clipboard)
- **Platform libs**: ws2_32 + Iphlpapi (Windows sockets), network (Haiku)

### Debugging Support

**Built-in debugger** (`src/debug/`):
- Activate with F12 → Debugger menu
- CPU disassembly, memory inspection, breakpoints
- DSP debugger support
- i860 debugger for NeXTdimension

**Tracing:**
- Enable with `-DENABLE_TRACING=1` (default on)
- Log messages throughout codebase for debugging hardware emulation
- Can be disabled for performance builds

**Key debug files:**
- `src/debug/debugcpu.c`: M68000 debugger
- `src/debug/debugdsp.c`: DSP debugger
- `src/dimension/i860dbg.cpp`: i860 debugger

### Development Workflow Tips

**Modifying CPU behavior:**
1. Edit instruction specs in `src/cpu/table68k` (rare)
2. Or modify generated code handlers in `src/cpu/cpuemu_*.c`
3. Rebuild `UaeCpu` library: `cd build/src/cpu && make`
4. Relink: `cd build/src && make`

**Adding new hardware device:**
1. Create handler file (e.g., `src/mydevice.c`)
2. Add to `src/CMakeLists.txt` SOURCES list
3. Register handlers in `src/ioMemTabNEXT.c` or `src/ioMemTabTurbo.c`
4. Add interrupt enum to `src/includes/cycInt.h`
5. Implement interrupt handler, schedule with `CycInt_Add*()`

**Testing changes:**
- No automated test suite currently
- Manual testing with NeXTStep OS images required
- Boot ROMs needed (not included): Rev 1.0 v41, Rev 2.5 v66, Rev 3.3 v74

**Common build flags:**
- `-DCMAKE_BUILD_TYPE=Debug`: Debug symbols with minimal optimization (`-O`)
- `-DCMAKE_BUILD_TYPE=Release`: Full optimization
- `-DENABLE_TRACING=0`: Disable trace messages for performance

### File Organization

**Root structure:**
```
src/
  *.c              - Main emulation logic (DMA, SCSI, floppy, etc.)
  cpu/             - M68000 CPU core + code generator
  dsp/             - M56001 DSP emulation
  dimension/       - NeXTdimension i860 board
  debug/           - Debugger UI and commands
  slirp/           - TCP/IP stack for networking
  softfloat/       - IEEE 754 floating-point library
  gui-sdl/         - SDL2 GUI (primary)
  gui-osx/         - macOS native UI
  gui-win/         - Windows specific
  includes/        - All header files
  convert/         - File conversion utilities

cmake/            - CMake modules and toolchain files
python-ui/        - Python-based UI alternative
dist/             - Distribution files (.desktop, icons)
etc/              - Sample configuration files
```

## Known Limitations & Issues

- CPU timing is not cycle-exact (may differ from real hardware performance)
- DSP sound has timing issues in some scenarios (playscore, ScorePlayer)
- NeXTdimension does not work on big-endian hosts
- Serial and ADB controllers are dummy implementations
- Changing network settings while guest OS running can cause lost connections
- 68882 transcendental FPU results match 68040 FPSP, slightly differ from real 68882

## NeXTdimension Hardware Documentation

### Overview

The NeXTdimension is a color graphics expansion board featuring an Intel i860 RISC processor @ 33MHz with its own Mach microkernel. It provided 32-bit color at 1120x832 resolution for NeXT workstations. Previous includes comprehensive documentation to aid in understanding and debugging NeXTdimension emulation.

### Available Documentation Resources

#### 1. ROM Analysis (`src/ROM_ANALYSIS.md`)

**Comprehensive 5000+ line analysis** of the NeXTcube/NeXTstation System ROM Rev 2.5 v66 (NOT the NeXTdimension board ROM). This document provides:

- **Complete boot sequence**: Step-by-step trace of ROM initialization from power-on to main loop
- **Memory map**: Detailed mapping of ROM, RAM, VRAM, and hardware registers
- **Hardware register reference**: CSR0-CSR14, RAMDAC, DMA controller addresses and functions
- **Function reference**: 50+ documented ROM subroutines with addresses and purposes
- **Data structures**: Exception frames, config tables, stack layout
- **Integration guide**: How ROM behavior maps to Previous emulator code
- **Debugging tips**: Common failure points and how to trace ROM execution

**Key Sections**:
- Boot sequence phases 1-9 with assembly annotations
- CSR register bit definitions and initialization values
- Memory detection algorithm and configuration table lookup
- **NeXTdimension detection and initialization** (from host perspective)
- RTC, video, and DMA initialization procedures
- Cross-references to emulator code in `src/dimension/`

**⚠️ CRITICAL**: This ROM runs on the **main 68040 CPU** of the NeXTcube/NeXTstation, NOT on the NeXTdimension's i860 processor. It contains code to detect and initialize the NeXTdimension as an expansion card.

**Use Cases**:
- Understanding how the host system boots and detects expansion boards
- Learning how NeXTdimension is initialized from the host side
- Verifying emulator's slot detection and memory window configuration
- Debugging host ↔ NeXTdimension communication setup

#### 2. Hardware Register Definitions (`src/includes/nextdimension_hardware.h`)

**1070+ line header file** with complete hardware interface definitions. This is a modern reverse-engineering effort providing:

- **Memory map**: i860 local DRAM, MMIO registers, VRAM, host shared memory, boot ROM
- **MMIO register structures**: Mailbox, DMA, video, interrupts, system control, timing, genlock, JPEG codec
- **Communication protocols**: Mailbox command definitions for host ↔ i860 communication
- **Hardware features**: Video I/O devices (SAA7191/7192), Intel 28F010 Flash ROM, board detection
- **Utility macros**: Register access with memory barriers, pixel addressing, DMA alignment
- **Function prototypes**: Firmware API (initialization, mailbox, DMA, video, interrupts, ROM ops)

**Comprehensive Register Coverage**:
- **Mailbox**: 16-byte structure with status, command, data pointer, result, signals, 4 args
- **DMA**: Source/dest addresses, length, control (2D/chained/burst), status, line pitch/count
- **Video**: Control, timing, blanking, page flipping, cursor, input/output, 32/16/8-bit modes
- **Interrupts**: 10 sources (mailbox, DMA, VBL, HBL, video in, genlock loss, JPEG, host, timer)
- **System**: Board ID, reset control, memory config (8/16/32/64MB), clock control, temperature
- **Diagnostics**: Self-test (BIST), pattern generators, loopback modes, error logging

**Advanced Features Documented**:
- **FPGA mezzanine**: JPEG/GIF/H.264/LZ4 accelerators (modern hardware additions)
- **Clock management**: PLL control, pixel clock selection, phase adjustment
- **Video I/O**: NTSC/PAL standards, ADC/DAC control, genlock input, sampling phase
- **Audio DSP**: 56001 mailbox, DMA, format control (16/24-bit, stereo, 44.1/48kHz)

**Cross-Reference with ROM**:
The header file addresses can be correlated with ROM assembly. For example:
- ROM writes `0x020c0004` → Header defines as `ND_MC_CSR1` (Memory Controller CSR1)
- ROM reads `0x0200c800` → Header defines as board configuration location
- ROM sets `0x02118180/90` → Header defines as `ND_RAMDAC_*` registers

#### 3. NeXT System ROM Disassembly (`src/ROMV66-0001E-02588.ASM`)

**15,266 lines of reverse-engineered 68040 assembly code** for NeXTcube/NeXTstation System ROM Rev 2.5 v66.

**⚠️ IMPORTANT**: This is the **main system ROM**, NOT the NeXTdimension board ROM.

**Major Sections**:
- `0x0100001e - 0x01000742`: Boot vectors and initialization (~1.8KB)
- `0x01000742 - 0x01010854`: Runtime functions (~65KB)
- `0x01010854 - 0x0101ffff`: Configuration data tables (~61KB)

**Notable Entry Points**:
- `0x0100001e`: Reset vector (cold boot)
- `0x010002dc`: Bus error exception handler
- `0x0100006c`: NeXTdimension detection (reads slot 2 config)
- `0x010048f2`: RTC validation
- `0x010095b4`: Screen clear + RTC read
- `0x01000af8`: NeXT logo display

Use `ROM_ANALYSIS.md` for human-readable annotations. The raw assembly is available for detailed low-level analysis with disassemblers.

#### 4. NeXTdimension Board ROM (`src/ND_step1_v43_eeprom.bin`)

**128KB binary ROM image** for the NeXTdimension board's Intel i860XR processor.

**⚠️ THIS is the actual NeXTdimension ROM** that runs on the i860 processor.

**Purpose**:
- Boots the i860 processor when released from reset by host
- Initializes i860 caches, MMU, FPU
- Tests NeXTdimension RAM (8-64MB) and VRAM (4MB)
- Loads and starts the "GaCK" Mach microkernel
- Configures RAMDAC for 1120x832 @ 68Hz, 32-bit color
- Establishes mailbox communication with host
- Waits for graphics commands from host

**Memory Map** (i860 view):
- `0xFFF00000 - 0xFFFFFFFF`: Boot ROM (this file)
- `0x00000000 - 0x03FFFFFF`: Local DRAM
- `0x10000000 - 0x103FFFFF`: Local VRAM (frame buffer)
- `0x08000000 - 0x0BFFFFFF`: Shared memory window to host
- `0x02000000 - 0x02000FFF`: MMIO registers

**Emulation**:
- Loaded and executed by `src/dimension/i860.cpp`
- Runs in separate thread from main 68040 emulation
- Communicates with host via mailbox and shared memory

**Binary Analysis**: See detailed structure analysis in `src/ND_ROM_STRUCTURE.md`.

#### 4b. NeXTdimension ROM Binary Structure (`src/ND_ROM_STRUCTURE.md`)

**Comprehensive binary analysis** of the NeXTdimension i860 ROM using hexdump, binwalk, and pattern analysis tools.

**Key Findings**:
- **10.9 KB of actual code** (8.3% of ROM) - rest is zeros
- **9 distinct code regions** from 0x00000 to 0x02900
- **Reset vector block** at 0x1FFE0 (end of ROM)
- **Position-independent code** with PC-relative addressing
- **Heavy MMIO interaction** with registers at 0x02000000 base
- **Boot sequence**: Reset vector → Boot entry → Init → Hardware detect → Device config → Main loop

**Memory Map**:
```
0x00000: Boot vector & initialization    (880 bytes)
0x00380: Early init code                 (432 bytes)
0x00540: Core init routines             (1136 bytes)
0x009c0: Hardware detection              (528 bytes)
0x00be0: Device initialization          (2448 bytes)
0x01580: Main runtime code              (4048 bytes) ★ Largest
0x02560: Service routines                (928 bytes)
0x1fd60: Data tables & constants         (480 bytes)
0x1ffe0: Reset vector block               (32 bytes) ★ Critical
```

**Analysis Tools Used**: hexdump, strings, binwalk, ent (entropy), Python byte frequency analysis

**Note**: Full instruction-level disassembly now available - see section 4c below.

#### 4c. NeXTdimension ROM Complete Disassembly

**Disassembly File**: `src/ND_step1_v43_eeprom.asm` (32,802 lines)
**Analysis Document**: `src/ND_ROM_DISASSEMBLY_ANALYSIS.md`
**Tool Used**: MAME i860 disassembler (standalone build)

**Complete instruction-level disassembly** of all 128KB (32,768 instructions) with region markers and annotations.

**Critical Discoveries from Disassembly**:

1. **Reset Vector Location**: `0xFFF1FF20` (not 0x1FFE0 as initially suspected)
   - Branches to `0x00000020` to start boot sequence
   - Reset vector data at 0x1FFE0-0x1FFFC contains CPU config (PSR, DIRBASE, FSR values)

2. **Boot Sequence Confirmed**:
   ```
   Reset (0x1FF20) → Branch to 0x00020 → PSR/EPSR setup → FPU init →
   Memory init (×3 calls) → Hardware detect → RAMDAC program (28-iteration loop) →
   Main loop at 0x01580 (mailbox polling + kernel loader)
   ```

3. **Firmware Download Mechanism CONFIRMED**:
   - Main loop at `0x01580` polls mailbox status register (`0x02000000`)
   - Kernel loader at `~0x01600` handles `CMD_LOAD_KERNEL` command
   - DMA transfer from shared memory to i860 DRAM
   - Final branch jumps to `0x00000000` (downloaded kernel entry point)
   - ROM never returns - control permanently transfers to DRAM

4. **Function Identification**:
   - `0x00020`: Boot entry point
   - `0x00380`: Memory initialization subroutine (called 3× with different params)
   - `0x007A0`: Hardware detection routine
   - `0x009C4`: Device initialization
   - `0x01580`: Main runtime loop (mailbox polling + command dispatch)
   - `0x02560`: Service routines (memcpy, memset, math helpers)

5. **MMIO Register Access** (confirmed mappings):
   - `0x02000000`: MAILBOX_STATUS (heavily polled)
   - `0x02000004`: MAILBOX_COMMAND
   - `0x020014E4`: RAMDAC_LUT_DATA (28-iteration write loop)
   - `0x020118E4`: GRAPHICS_DATA
   - `0x02000070`: CONTROL_STATUS

6. **Bootstrap Timing**: ~3 milliseconds from reset to mailbox ready

**Disassembler Tool**: `tools/mame-i860/i860disasm`
```bash
# Usage:
./i860disasm -r -z -a ND_step1_v43_eeprom.bin > output.asm

# Options:
#   -r  Mark code regions
#   -z  Skip zero-filled blocks
#   -a  Annotate MMIO register accesses
#   -b  Set base address (default 0xFFF00000)
```

#### 5. Historical Documentation (`src/dimension/nd-firmware.md`)

**Comprehensive historical analysis** of NeXTdimension firmware preservation, reverse engineering, and technical specifications. Covers:

- Firmware preservation story (ROM images at Macintosh Repository)
- Boot process and dual initialization (68040 + i860)
- Software evolution across NeXTSTEP 2.1 through 3.3
- Previous emulator's reverse engineering achievements (version 1.4+)
- Technical specs: i860 @ 33MHz, 8-64MB RAM, 4MB VRAM, 1120x832 @ 68Hz
- Incomplete features (Display PostScript on i860, C-Cube JPEG chip)
- Documentation sources and preservation efforts

**Historical Context**:
- Product timeline: Announced 1990, shipped 1991 ($3,995), discontinued ~1995
- ROM remained static throughout lifetime (no version updates)
- Driver software evolved with NeXTSTEP releases
- "GaCK OS" - informal name for stripped-down Mach kernel on i860

### Using NeXTdimension Documentation for Development

#### Understanding Emulation Accuracy

Compare ROM behavior against emulator implementation:

```c
// ROM does (from ROM_ANALYSIS.md):
// 0x01000042: MOVE.L #$c7000000,$020c0004  (CSR1)

// Emulator should (src/dimension/nd_mem.c):
void nd_mc_csr_write(uint32_t addr, uint32_t val) {
    if (addr == 0x020c0004) {  // CSR1
        nd_mc_csr1 = val;
        // Enable memory controller, DRAM refresh, burst mode
        // as defined in ROM_ANALYSIS.md CSR1 bit definitions
    }
}
```

#### Cross-Referencing Hardware Registers

**Example**: Finding RAMDAC initialization

1. **ROM disassembly** shows writes to `0x02118180` and `0x02118190`
2. **ROM_ANALYSIS.md** documents these as RAMDAC Control and Data registers
3. **nextdimension_hardware.h** defines:
   ```c
   #define ND_RAMDAC_START    0xFF200000  // i860 view
   // (Different address space - need to map 68040 → i860 addresses)
   ```
4. **Emulator** (`src/dimension/nd_devs.c`) should implement handlers

#### Debugging Boot Failures

**Scenario**: Emulator hangs during NeXTdimension boot

**Debug Process**:
1. Check `ROM_ANALYSIS.md` → "Common Boot Failure Points"
2. Trace ROM execution to find hang point (e.g., `0x0100006c`)
3. ROM_ANALYSIS shows this reads board config at `0x0200c800`
4. Verify emulator returns valid config word (format documented in ROM_ANALYSIS)
5. Check `nextdimension_hardware.h` for `ND_MC_SID` register definition
6. Compare expected vs actual emulator response

**Tracing Example**:
```
[ND-ROM] 0x0100001e: Reset entry reached
[ND-ROM] 0x01000042: CSR1 <- 0xc7000000 ✓
[ND-ROM] 0x0100006c: Read config @ 0x0200c800
[ND-EMU] Returned: 0x00000000 ✗ (should be 0x3600xxxx for 4Mbit DRAMs)
```

#### Enhancing NeXTdimension Emulation

**Adding Missing Features**:

1. **Check hardware definition**: Look in `nextdimension_hardware.h` for register structure
2. **Understand ROM usage**: See if `ROMV66-0001E-02588.ASM` accesses this hardware
3. **Read ROM_ANALYSIS**: Find initialization sequence and expected behavior
4. **Implement in emulator**: Add handlers in `src/dimension/`
5. **Test against ROM**: Verify emulator responses match ROM expectations

**Example - Adding Mailbox Support**:
- Header defines `nd_mailbox_regs_t` structure (12 registers)
- ROM doesn't directly use mailbox (that's i860-side)
- But emulator needs to provide mailbox for i860 ↔ 68040 communication
- Implement based on header definitions + expected protocol

### NeXTdimension Architecture Summary

**Dual Processor System with Separate ROMs**:

**Host System (NeXTcube/NeXTstation)**:
- **Processor**: Motorola 68040 @ 25MHz
- **ROM**: `ROMV66-0001E-02588.ASM` (128KB system ROM)
- **Role**: Main computer, boots OS, detects expansion boards, sends graphics commands

**NeXTdimension Board**:
- **Processor**: Intel i860XR @ 33MHz
- **ROM**: `ND_step1_v43_eeprom.bin` (128KB board ROM)
- **Role**: Graphics processing, runs GaCK Mach kernel, executes graphics commands

**Memory Spaces**:

*Host (68040) View*:
- **System ROM**: 128KB at `0x01000000`
- **Main DRAM**: 8-128MB at `0x04000000`
- **ND RAM Window**: 64MB at `0xF8000000` (maps to ND's local RAM)
- **ND VRAM Window**: 4MB at `0xFE000000` (maps to ND's frame buffer)
- **ND I/O Registers**: `0xFF800000` range
- **System Registers**: `0x020c0000` (memory controller), `0x02118000` (RAMDAC)

*NeXTdimension (i860) View*:
- **ND Boot ROM**: 128KB at `0xFFF00000`
- **ND Local DRAM**: 8-64MB at `0x00000000`
- **ND VRAM**: 4MB at `0x10000000`
- **Host Window**: 64MB at `0x08000000` (shared memory with host)
- **ND MMIO**: `0x02000000` range

**Communication**:
- Shared memory regions
- Mailbox protocol (documented in header)
- Interrupt signaling
- DMA transfers

**Previous Emulator Integration**:
- `src/dimension/dimension.c`: Main NeXTdimension emulation
- `src/dimension/nd_mem.c`: Memory controller and CSR registers
- `src/dimension/nd_devs.c`: RAMDAC, NBIC, peripherals
- `src/dimension/i860.cpp`: i860 processor emulation
- `src/dimension/nd_nbic.c`: NeXTBus interface

**Key Synchronization**:
```c
volatile int mainPauseEmulation;  // Coordinate 68040 ↔ i860 threads
```

### Quick Reference

| Need to... | Consult... |
|------------|-----------|
| Understand **host system** boot sequence | `ROM_ANALYSIS.md` § Complete Boot Sequence (68040 ROM) |
| Learn how host **detects NeXTdimension** | `ROM_ANALYSIS.md` § NeXTdimension Detection and Initialization |
| Find ND hardware register address | `nextdimension_hardware.h` + `ROM_ANALYSIS.md` § Hardware Register Reference |
| Debug host boot hang | `ROM_ANALYSIS.md` § Debugging Notes |
| Debug ND detection failure | `ROM_ANALYSIS.md` § NeXTdimension Detection § Debugging |
| Learn about CSR registers (host) | `ROM_ANALYSIS.md` § Hardware Initialization |
| Understand i860 ROM boot process | `ROM_ANALYSIS.md` § i860 ROM Boot Process + `ND_step1_v43_eeprom.bin` |
| Implement new ND hardware feature | `nextdimension_hardware.h` (defines) → `dimension/*.c` (code) |
| Understand i860 ↔ 68040 communication | `nextdimension_hardware.h` § Mailbox + `ROM_ANALYSIS.md` § Communication Protocol |
| Historical context | `dimension/nd-firmware.md` |
| Raw **system** ROM disassembly | `ROMV66-0001E-02588.ASM` (68040, use with IDA/Ghidra) |
| Raw **NeXTdimension** ROM binary | `ND_step1_v43_eeprom.bin` (i860, binary blob) |

### Development Checklist for NeXTdimension Work

**Understanding the System**:
1. ✓ Understand there are TWO separate ROMs (host 68040 + ND i860)
2. ✓ Read `ROM_ANALYSIS.md` § NeXTdimension Detection to understand host-side init
3. ✓ Review `ROM_ANALYSIS.md` § i860 ROM Boot Process to understand ND-side init
4. ✓ Review memory maps for both host and i860 perspectives

**Implementing Features**:
5. ✓ Check `nextdimension_hardware.h` for register definitions
6. ✓ Determine if feature is host-side or i860-side (or both)
7. ✓ For host-side: Check if system ROM accesses these registers (search `ROMV66-0001E-02588.ASM`)
8. ✓ For i860-side: Feature runs on i860, uses `ND_step1_v43_eeprom.bin` ROM
9. ✓ Implement handlers in appropriate `dimension/*.c` file
10. ✓ Add logging to track register accesses (both host and i860)

**Testing**:
11. ✓ Test host detection: Does system ROM find ND in slot 2?
12. ✓ Test i860 boot: Does ND ROM start and initialize?
13. ✓ Test communication: Can host send commands to i860?
14. ✓ Test with NeXTSTEP boot, compare against expected behavior
15. ✓ Cross-verify with Previous v1.4+ release notes for known issues

## Resources

- NeXT International Forums: http://www.nextcomputers.org/forums
- Project website: http://previous.alternative-system.com
- Boot ROM files: Required but not included (copyright reasons)
  - Place in same directory as executable or system ROM directory
  - Supported: Rev 0.8 v31, Rev 1.0 v41, Rev 2.5 v66, Rev 3.3 v74
- NeXTdimension ROM Preservation: https://www.macintoshrepository.org/52628-next-hardware-roms
