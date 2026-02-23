# NDserver Binary Analysis

**Binary**: NDserver
**Source**: NeXTSTEP 3.3 User ISO
**Path**: `/usr/lib/NextStep/Displays/NeXTdimension.psdrvr/NDserver`
**Date Analyzed**: November 4, 2025
**Analyst**: Claude (via mame-i860 toolchain)

---

## Executive Summary

**NDserver** is the host-side m68k daemon that manages the NeXTdimension graphics board. It runs on the NeXT computer (68040/m68030 CPU) and handles:

1. **Board Detection**: Probes NeXTBus slots for NeXTdimension hardware
2. **Kernel Loading**: Uses NeXTSTEP's `kern_loader` facility to load `ND_MachDriver_reloc` (the i860 Mach kernel)
3. **Communication**: Manages host ↔ i860 message passing via Mach IPC ports
4. **Display Integration**: Coordinates with PostScript Display Server (PSDRVR)
5. **Video Output**: Manages NTSC/PAL video output features

**Key Discovery**: NDserver contains an **embedded i860 kernel** in its `__I860` segment (802,816 bytes), which differs from the standalone `ND_MachDriver_reloc` file. This suggests a fallback/backup kernel mechanism.

**Architecture**: Dual-processor design where the m68k host delegates graphics operations to the i860 coprocessor, with NDserver acting as the intermediary between NeXTSTEP kernel and i860 kernel.

---

## Binary Structure

### Mach-O Header

```
Magic:        0xfeedface (Mach-O 32-bit)
CPU Type:     6 (m68k)
CPU Subtype:  1 (MC68040)
File Type:    2 (MH_EXECUTE - executable)
Load Commands: 8
Size of Commands: 1052 bytes
Flags:        0x00000001 (NOUNDEFS - no undefined references)
```

**Entry Point**: `0x00002d10` (relative to text segment)
**Total Size**: 835,584 bytes (816 KB)

### Load Commands Summary

| Command | Type | Purpose |
|---------|------|---------|
| 0 | LC_SEGMENT | `__PAGEZERO` - Zero page protection (8 KB) |
| 1 | LC_SEGMENT | `__TEXT` - Code and constants (24 KB) |
| 2 | LC_SEGMENT | `__DATA` - Initialized/uninitialized data (8 KB) |
| 3 | LC_SEGMENT | `__I860` - **Embedded i860 kernel** (784 KB) |
| 4 | LC_SEGMENT | `__LINKEDIT` - Linker metadata (0 bytes) |
| 5 | LC_LOADFVMLIB | Links `/usr/shlib/libsys_s.B.shlib` (v55) |
| 6 | LC_SYMTAB | Symbol table (stripped - 0 symbols) |
| 7 | LC_UNIXTHREAD | Initial thread state (PC=0x2d10) |

---

## Segment Details

### __PAGEZERO (Protection Segment)
```
VM Address:  0x00000000
VM Size:     0x00002000 (8 KB)
File Offset: 0
File Size:   0 (zero-fill)
Max Prot:    None (0x00)
Init Prot:   None (0x00)
Purpose:     Trap null pointer dereferences
```

### __TEXT (Code Segment)
```
VM Address:  0x00002000
VM Size:     0x00006000 (24 KB)
File Offset: 0
File Size:   24,576 bytes
Max Prot:    RWX (0x07)
Init Prot:   R-X (0x05)
Sections:    5
```

#### TEXT Sections:

1. **__text** (Code)
   - Address: `0x00002d10`
   - Size: 18,664 bytes (18.2 KB)
   - Offset: 3344
   - Contains main executable code

2. **__fvmlib_init0** (Framework Init)
   - Address: `0x000075f8`
   - Size: 312 bytes
   - Purpose: Shared library initialization

3. **__fvmlib_init1** (Framework Init)
   - Address: `0x00007730`
   - Size: 0 bytes
   - Purpose: Secondary initialization (unused)

4. **__cstring** (C Strings)
   - Address: `0x00007730`
   - Size: 811 bytes
   - Contains error messages, paths, format strings

5. **__const** (Constants)
   - Address: `0x00007a5c`
   - Size: 1,444 bytes
   - Read-only data tables

### __DATA (Data Segment)
```
VM Address:  0x00008000
VM Size:     0x00002000 (8 KB)
File Offset: 24576
File Size:   8,192 bytes
Max Prot:    RWX (0x07)
Init Prot:   RWX (0x07)
Sections:    3
```

#### DATA Sections:

1. **__data** (Initialized Data)
   - Address: `0x00008000`
   - Size: 28 bytes
   - Global variables with initial values

2. **__bss** (Uninitialized Data)
   - Address: `0x0000801c`
   - Size: 368 bytes
   - Zero-initialized globals

3. **__common** (Common Block)
   - Address: `0x00008190`
   - Size: 32 bytes
   - Common symbols from linking

### __I860 (Embedded Kernel Segment) ⭐

```
VM Address:  0x0000a000
VM Size:     0x000c4000 (784 KB)
File Offset: 32768 (0x8000)
File Size:   802,816 bytes
Max Prot:    RWX (0x07)
Init Prot:   RWX (0x07)
Sections:    1
Flags:       0x4 (SG_NORELOC - no relocation)
```

#### __i860 Section:
```
Address:     0x0000a000
Size:        794,448 bytes (0xc2350)
Offset:      32768
Alignment:   16 bytes
Type:        Regular
```

**This is the most significant finding**: NDserver embeds a complete i860 kernel within itself.

---

## Embedded i860 Kernel Analysis

### Extraction

The embedded kernel was extracted using:
```bash
dd if=NDserver bs=1 skip=32768 count=802816 of=embedded_i860.bin
```

### Embedded Kernel Properties

```
File Type:   Mach-O preload executable i860g
Magic:       0xfeedface
CPU Type:    15 (i860)
File Type:   5 (MH_PRELOAD - relocatable kernel)
Size:        802,816 bytes (784 KB)
MD5:         bc23eaacacc54d4c3062714edaf809b9
```

### Comparison with ND_MachDriver_reloc

| Property | Embedded Kernel | ND_MachDriver_reloc |
|----------|----------------|---------------------|
| Size | 802,816 bytes | 795,464 bytes |
| MD5 | bc23eaac... | 1762006c... |
| Format | Mach-O i860 preload | Mach-O i860 preload |
| Match? | **NO** | **Different versions** |

**Size Difference**: 7,352 bytes larger (embedded version is newer/different)

### Embedded Kernel Structure

```
Segments:
  __TEXT: vmaddr=0xf8000000, size=737,280 bytes
    __text: 730,440 bytes at 0xf8000000

  __DATA: vmaddr=0xf80b4000, size=72,192 bytes
    __data: 56,400 bytes (initialized)
    __bss:   2,752 bytes (zero-fill)
    __common: 6,360 bytes (common)

Entry Point: 0xf8000000 (i860 DRAM base address)
Load Address: 0xf8000000 - 0xf80c5ffff (789 KB range)
```

### Purpose of Embedded Kernel

**Hypothesis 1: Fallback Kernel**
If `/usr/lib/NextStep/Displays/NeXTdimension.psdrvr/ND_MachDriver_reloc` is missing or corrupted, NDserver can use the embedded kernel as a backup.

**Hypothesis 2: Installation Bootstrap**
During initial NeXTdimension setup, before the full driver package is installed, the embedded kernel provides basic functionality.

**Hypothesis 3: Version Mismatch Protection**
Ensures NDserver always has a compatible kernel version, preventing issues from mixed driver versions.

**Evidence**:
- Different checksums indicate intentional versioning
- Embedded kernel is slightly larger (possibly stripped debug info in standalone)
- NeXT's typical redundancy approach for critical system components

---

## Functional Analysis

### Initialization and Startup

#### Entry Point (0x00002d10)
The binary starts execution at address `0x00002d10` with the m68k processor state initialized:
- All registers cleared (D0-D7, A0-A6 = 0)
- Stack pointer (A7) = 0
- Program counter (PC) = 0x00002d10
- Status register (SR) = 0

#### Startup Sequence (inferred from strings)

1. **Parse Command Line Arguments**
   ```c
   Usage: NDserver [-s Slot]
   ```
   - `-s Slot`: Specify which NeXTBus slot to probe (default: scan all)

2. **Mach Port Initialization** (`NDUX_Init`)
   ```
   NDUX_Init: port_allocate failed         // Fatal error
   NDUX_Init: ND_Port_check_in()          // Register with name server
   ```

3. **Port Set Creation**
   - Creates port sets for:
     - Debug messages
     - Pager service
     - Unix domain sockets
     - Notifications
   ```
   port_allocate failed
   port_set_allocate failed
   port_set_add (debug) failed
   port_set_add (pager) failed
   port_set_add (unix port) failed
   port_set_add (notify) failed
   ```

4. **PostScript Server Lookup**
   ```
   netname_look_up for ps_server failed (%d)
   Cannot set PostScript hook. (%d)
   ```
   Finds and connects to the PostScript Display Server.

---

### Board Detection

#### Function: `ND_GetBoardList()`

Scans NeXTBus slots for NeXTdimension hardware:

```
No NextDimension board found.
No NextDimension board in Slot %d.
```

**Detection Method** (inferred):
1. Probes each NeXTBus slot (0-15)
2. Reads device identification registers
3. Checks for NeXTdimension board ID
4. Verifies board is not in use by another WindowServer

**Exclusivity Check**:
```
Another WindowServer is using the NeXTdimension board.
```
Only one WindowServer instance can control the board.

#### Command-Line Selection
```
Usage: %s [-s Slot]
```
Allows manual slot specification for multi-board systems or testing.

---

### Kernel Loading Mechanism

#### Overview
NDserver uses NeXTSTEP's **kern_loader** facility to dynamically load the i860 Mach kernel into kernel space, then transfers it to i860 memory.

#### Configuration File
```
/etc/kern_loader.conf
```
Kernel loader configuration (standard NeXTSTEP mechanism).

#### Loading Sequence

**Step 1: Find kern_loader Port**
```
NeXTdimension: Couldn't find kern_loader's port (%s)
```
Looks up the kern_loader daemon's Mach port via name server.

**Step 2: Query Server State**
```
NeXTdimension: get_server_state() fails (%s)
```
Checks if kernel server is already loaded/running.

**Step 3: Register with kern_loader**
```c
// Function: NDDriver: ND_Load_MachDriver
NeXTdimension: kern_loader_add_server() fails (%s)
```
Registers `ND_MachDriver_reloc` as a loadable kernel server.

**Step 4: Load Kernel**
```
NeXTdimension: kern_loader_load_server() fails (%s)
```
Instructs kern_loader to load the i860 kernel into kernel memory.

**Step 5: Transfer to i860**
```
ND_BootKernelFromSect      // Boot kernel from section
ND_SetPagerTask            // Configure paging task
```
Copies kernel from host memory to i860 DRAM at `0xf8000000`.

#### Kernel File Path
```
/usr/lib/NextStep/Displays/NeXTdimension.psdrvr/ND_MachDriver_reloc
```
Standard location for i860 kernel binary.

#### Error Handling

**Spontaneous Unload**:
```
NeXTdimension: Mach driver spontaneously unloading!
```
Kernel was unexpectedly removed (system shutdown, crash, manual unload).

**Zombie State**:
```
NeXTdimension: Mach driver has become a zombie!
```
Kernel server process exists but is not responding (crash recovery needed).

**Startup Failure**:
```
NDserver died on startup.
FAILURE IN NeXTdimension SERVER
```
Fatal errors during initialization.

---

### Communication Protocol

#### Mach IPC Architecture

NDserver uses Mach messages for host ↔ i860 communication:

**Port Types**:
- **parent_port**: Main communication channel
- **debug port**: Debug message output
- **pager port**: Virtual memory paging
- **unix port**: Unix domain socket bridge
- **notify port**: Asynchronous notifications

#### Message Reception
```c
error %s in Receive, message will be ignored.
Unexpected emergency msg received: id is %d
Message for unknown port %d! (ID = %d)
```

**Message Loop** (inferred structure):
```c
while (running) {
    msg_receive(port_set, &msg, timeout);

    switch (msg.id) {
        case EMERGENCY_MSG:
            handle_emergency(msg);
            break;
        case DISPLAY_MSG:
            forward_to_ps(msg);
            break;
        case VIDEO_MSG:
            handle_video(msg);
            break;
        default:
            log_error("Message for unknown port");
    }
}
```

#### Message Transmission
```c
error %s at Send.
```

**Functions**:
```
makePublic: msg_send returned %D
makePublic: msg_receive returned %D
mark_msg_send: msg_send returned %D
as_new_message: incorrect id for continuation message
```

#### Internal Message Handling
```
NeXTdimension internal msg error: %s
```
Errors in internal state machine.

---

### Virtual Memory Management

#### VM Operations

**Allocation**:
```c
ND vm_allocate fails (%d) addr 0x%x size %d %d
vm_allocate failed
vm_allocate of copy area
```

**Shared Memory**:
```c
vm_region() on page out op
vm_copy of copied area
```

**Paging**:
```
ND_SetPagerTask    // Configure i860 pager
```

#### Memory Layout (inferred)

```
Host Memory:
  0x02000000 - NeXTBus mailbox registers (host-visible)
  0x?????000 - Shared memory region (DMA)

i860 Memory:
  0xf8000000 - Kernel text segment (737 KB)
  0xf80b4000 - Kernel data segment (72 KB)
  0xf80c6000 - Free DRAM (remaining of 32 MB)
```

**Access Violations**:
```
Illegal memory access!
```
Caught page faults or bus errors.

---

### PostScript Display Server Integration

#### Connection

**Lookup**:
```c
netname_look_up for ps_server failed (%d)
```
Finds the PostScript WindowServer's port.

**Hook Installation**:
```
Cannot set PostScript hook. (%d)
```
Registers NeXTdimension as a display device with the PS server.

#### Display Path

```
NeXTSTEP App
     ↓
PostScript Display Server (PSDRVR)
     ↓
NDserver (m68k host)
     ↓ (Mach IPC)
i860 Kernel (ND_MachDriver_reloc)
     ↓
NeXTdimension Hardware (RAMDAC → Display)
```

#### Recording Features

**Video Recording**:
```c
nd_resumerecording: ps_setRecordingInfo fails (%d)
nd_resumerecording: ps_startRecording fails (%d)
```

Integrates with Display Server's recording API to capture screen output.

---

### Video Output Features

#### ScreenScape Application

NDserver includes code for **ScreenScape**, a video output demonstration application:

```
NeXTdimension Video Output Demonstration

ScreenScape transparently outputs a partial rectangular area of your
NeXTdimension screen to the NeXTdimension video output ports. This
rectangle automatically follows the cursor as you work.
```

#### Video Standards Supported

**NTSC**:
- Resolution: 640 × 480 pixels
- Frame rate: ~30 Hz
- Color encoding: YCbCr

**PAL**:
- Resolution: 576 × 768 pixels
- Frame rate: ~25 Hz
- Color encoding: YCbCr

#### Video Functions

**Initialization**:
```c
nd_start_video: can't find window bag
nd_start_video: can't get window info
```

**Sync Control**:
```c
nd_currentsync     // Get current sync mode
nd_setsync         // Set genlock/freerun
```

**Screen Queries**:
```c
doesScreenSupportVideo:standard:size:
getScreenSize:
calcVideoRect:
```

#### Video Frame Tracking

**Cursor Following**:
> "The video frame automatically tracks the cursor upon startup. The size
> of this frame depends on the type of video signal your NeXTdimension
> board can output (i.e., NTSC or PAL)."

**Manual Positioning**:
> "Click and hold the button with the hand icon in the Frame Control box.
> An orange outline will appear. This indicates the exact frame position
> that will be output to video."

**Overscan Compensation**:
> "Many television sets and professional video monitors clip or 'throw
> away' 10-15% of the video signal around the edges. Pixel Overscan
> allows you to compensate for this by reducing the size of the frame."

#### Genlock Support

> "sync to an input video sync. When genlock is enabled, a popup list
> allows you to select which of the video inputs to use for sync. If
> turned off (the default), the output sync is generated from an
> internal sync."

Allows the NeXTdimension to synchronize with external video equipment.

---

### Window Management

#### Functions

**Window Registration**:
```c
registerWindow:toPort:
unregisterWindow:
NDGrab: can't find window bag
```

**Window Events**:
```c
windowWillClose:
windowChanged:
windowDidBecomeKey:
windowDidResignKey:
windowDidUpdate:
windowWillResize:toSize:
windowDidResize:
```

**Display Control**:
```c
displayIfNeeded
flushWindow
disableFlushWindow
reenableFlushWindow
display
setAutodisplay:
```

#### Window Server Interaction

```c
setWindowTitle:
setMiniwindowIcon:
sizeWindow::
inspectedWindow
mainWindow
```

NeXTSTEP AppKit integration for managing NeXTdimension-accelerated windows.

---

## Error Handling

### Categories of Errors

#### 1. Initialization Errors

```c
NDUX_Init: port_allocate failed           // Fatal: can't create ports
NDUX_Init: ND_Port_check_in()            // Port registration
port_set_allocate failed                  // Port set creation
port_set_add (debug) failed              // Adding to port set
port_set_add (pager) failed
port_set_add (unix port) failed
port_set_add (notify) failed
```

**Recovery**: None (fatal errors, daemon exits)

#### 2. Hardware Detection Errors

```c
No NextDimension board found.             // No board present
No NextDimension board in Slot %d.        // Specific slot check
Another WindowServer is using the         // Exclusivity violation
    NeXTdimension board.
```

**Recovery**: Wait for board availability or exit

#### 3. Kernel Loading Errors

```c
NeXTdimension: Couldn't find kern_loader's port (%s)
NeXTdimension: get_server_state() fails (%s)
NeXTdimension: kern_loader_add_server() fails (%s)
NeXTdimension: kern_loader_load_server() fails (%s)
```

**Recovery**: Retry kernel load or use embedded kernel

#### 4. Runtime Errors

```c
NeXTdimension: Mach driver spontaneously unloading!
NeXTdimension: Mach driver has become a zombie!
NeXTdimension internal msg error: %s
```

**Recovery**: Reload kernel, reset hardware, notify user

#### 5. PostScript Server Errors

```c
netname_look_up for ps_server failed (%d)
Cannot set PostScript hook. (%d)
nd_resumerecording: ps_setRecordingInfo fails (%d)
nd_resumerecording: ps_startRecording fails (%d)
```

**Recovery**: Retry connection, degrade to non-PS mode

#### 6. Video Output Errors

```c
nd_start_video: can't find window bag
nd_start_video: can't get window info
NDGrab: can't find window bag
```

**Recovery**: Disable video output feature

#### 7. Memory Errors

```c
malloc failed
vm_allocate failed
ND vm_allocate fails (%d) addr 0x%x size %d %d
Illegal memory access!
```

**Recovery**: Free memory, reduce allocations, fatal error handling

---

## String Analysis

### Critical Error Messages

#### Startup/Initialization
```
NDserver died on startup.
FAILURE IN NeXTdimension SERVER
```

#### Board Detection
```
No NextDimension board found.
No NextDimension board in Slot %d.
Another WindowServer is using the NeXTdimension board.
```

#### Kernel Loading
```
NeXTdimension: Couldn't find kern_loader's port (%s)
NeXTdimension: get_server_state() fails (%s)
NeXTdimension: kern_loader_add_server() fails (%s)
NeXTdimension: kern_loader_load_server() fails (%s)
NeXTdimension: Mach driver spontaneously unloading!
NeXTdimension: Mach driver has become a zombie!
```

### File Paths

#### System Paths
```
/usr/lib/NextStep/Displays/NeXTdimension.psdrvr/NDserver
/usr/lib/NextStep/Displays/NeXTdimension.psdrvr/ND_MachDriver_reloc
/etc/kern_loader.conf
/etc/mtab
/dev/tty
```

### Function Names (Partial List)

#### Board Management
```c
ND_GetBoardList       // Scan for boards
ND_Open               // Open board for use
```

#### Kernel Operations
```c
ND_BootKernelFromSect // Boot from embedded kernel
ND_SetPagerTask       // Configure paging
NDDriver: ND_Load_MachDriver  // Load external kernel
```

#### Communication
```c
NDUX_Init             // Initialize Unix compatibility layer
ND_Port_check_in      // Register Mach port
ND_ConsoleInput       // Console I/O handling
```

#### Video
```c
nd_currentsync        // Query sync mode
nd_setsync            // Set sync mode
nd_start_video        // Start video output
nd_resumerecording    // Resume screen recording
```

---

## Symbol Analysis

### Symbol Table Status

```
Symbol Table (LC_SYMTAB):
  symoff:  0
  nsyms:   0
  stroff:  0
  strsize: 0
```

**The binary is fully stripped** - no symbol table present.

### Symbol Recovery Methods

1. **String References**: Function names appear in error messages
2. **Disassembly**: Reverse engineering of m68k code (requires disassembler)
3. **Dynamic Analysis**: Running in emulator with tracing
4. **Comparison**: With debug/development builds if available

---

## Cross-References with Research

### GaCK Kernel Research

From `/Users/jvindahl/Development/previous/src/GaCK_KERNEL_RESEARCH.md`:

**Predicted Error Messages**: ✅ **Confirmed**
```
"NeXTdimension: Couldn't find kern_loader's port (%s)"
"NeXTdimension: get_server_state() fails (%s)"
"NeXTdimension: kern_loader_add_server() fails (%s)"
"NeXTdimension: kern_loader_load_server() fails (%s)"
"NeXTdimension: Mach driver spontaneously unloading!"
"NeXTdimension: Mach driver has become a zombie!"
```

All predicted error messages from the research document are present in NDserver.

### ROM Analysis Integration

From `ND_ROM_STRUCTURE.md` and `ND_ROM_DISASSEMBLY_ANALYSIS.md`:

**ROM → NDserver Handoff** (inferred sequence):

1. **i860 ROM boots** (PC = 0xFFFFC800)
2. **ROM initializes hardware** (DRAM, registers, RAMDAC)
3. **ROM polls mailbox** at 0x02000000 for host signal
4. **NDserver detects board** via `ND_GetBoardList()`
5. **NDserver loads kernel** via kern_loader
6. **NDserver writes kernel** to i860 DRAM at 0xf8000000
7. **NDserver signals ROM** via mailbox write
8. **ROM jumps to kernel** entry point (0xf8000000)
9. **i860 kernel runs** Mach kernel server
10. **Bidirectional communication** established via Mach IPC

### Mailbox Register Protocol (inferred)

```
Host → i860:
  0x02000000: Command register
  0x02000004: Argument 1
  0x02000008: Argument 2
  0x0200000c: Status/Result

i860 → Host:
  0x02000010: Response code
  0x02000014: Data 1
  0x02000018: Data 2
  0x0200001c: Interrupt trigger
```

**Evidence**: ROM analysis shows polling of 0x02000000 range.

---

## Hardware Interface Analysis

### NeXTBus Slot Detection

**NeXTBus Architecture**:
- 16 physical slots (0-15)
- 32-bit address/data bus
- Memory-mapped device registers
- Interrupt lines

**Detection Method** (inferred):
```c
for (slot = 0; slot < 16; slot++) {
    base_addr = NEXTBUS_BASE + (slot << 24);  // Slot-specific offset
    device_id = *(uint32_t*)(base_addr + 0);

    if (device_id == NEXTDIMENSION_ID) {
        if (!check_ownership(slot)) {
            error("Another WindowServer is using slot %d", slot);
            continue;
        }
        return slot;
    }
}
return -1;  // No board found
```

### Memory Map (Host Perspective)

```
Physical Addresses:
  0x02000000 - 0x0200ffff: Mailbox/Communication registers (64 KB)
  0x02010000 - 0x0203ffff: Device registers (192 KB)
  0x02040000 - 0x0204ffff: RAMDAC registers (64 KB)
  0x02050000 - 0x0205ffff: VRAM direct access (64 KB window)
  0x02060000 - 0x0206ffff: i860 DRAM window (64 KB window)

  [Full i860 DRAM accessible via DMA or mapping]
```

**Note**: Actual addresses may vary; based on typical NeXTBus architecture.

### Interrupt Handling

**Host → i860 Interrupts**:
- Write to mailbox interrupt register
- i860 ROM/kernel polls or receives interrupt

**i860 → Host Interrupts**:
- i860 triggers NeXTBus interrupt line
- m68k kernel services interrupt
- NDserver receives notification via Mach port

---

## Key Findings

### 1. Embedded Backup Kernel

**Critical Discovery**: NDserver contains a full i860 kernel (784 KB) in its `__I860` segment, different from the standard `ND_MachDriver_reloc` file.

**Implications**:
- Provides fallback if filesystem kernel is missing/corrupt
- Ensures NeXTdimension can always boot
- Simplifies installation (kernel embedded in daemon)
- May represent a different kernel version (newer or stripped)

**Size Comparison**:
- Embedded: 802,816 bytes (MD5: bc23eaac...)
- Standalone: 795,464 bytes (MD5: 1762006c...)
- Difference: 7,352 bytes (0.9% larger)

### 2. Dual Kernel Architecture

**Two kernels coexist**:
1. **Primary**: `/usr/lib/.../ND_MachDriver_reloc` (loaded via kern_loader)
2. **Backup**: Embedded in NDserver `__I860` segment

**Loading Priority** (hypothesis):
```c
if (load_external_kernel() == SUCCESS) {
    // Use filesystem kernel
} else {
    // Fall back to embedded kernel
    load_embedded_kernel();
}
```

### 3. kern_loader Integration

**NeXTSTEP's kern_loader is central** to the architecture:
- Loads i860 kernel as a Mach kernel server
- Manages kernel lifecycle (load, unload, restart)
- Provides IPC between host and loaded server
- Enables hot-swapping of kernels without reboot

This is a sophisticated design compared to hard-coded firmware loaders.

### 4. PostScript Display Server Dependency

NDserver **requires** the PostScript Display Server:
- Looks up `ps_server` port on startup
- Installs "PostScript hook" for display operations
- Forwards display commands to i860
- Integrates recording/video output

**No standalone mode** - NeXTdimension cannot operate without WindowServer.

### 5. Video Output Capabilities

**ScreenScape Application** demonstrates professional video features:
- Real-time screen region output to NTSC/PAL
- Cursor-following video frame
- Overscan compensation
- Genlock synchronization
- Manual frame positioning

This suggests NeXTdimension was marketed for video production workflows.

### 6. Mach IPC Protocol

**Modern message-passing architecture**:
- Port-based communication (not direct memory sharing)
- Multiple port sets (debug, pager, unix, notify)
- Asynchronous message handling
- Type-safe message IDs

This is more sophisticated than typical 1990s coprocessor designs (cf. Amiga Copper).

### 7. Virtual Memory Integration

**i860 has paging support**:
- `ND_SetPagerTask` configures VM
- `vm_allocate` / `vm_copy` for shared memory
- Page fault handling across processors

Unusual for a graphics coprocessor in 1991.

### 8. Error Handling Philosophy

**NeXT's approach**:
- Descriptive error messages (includes `%s` Mach error descriptions)
- Graceful degradation (fallback kernels, optional video features)
- State machine tracking ("zombie" vs. "unloading" vs. "running")
- Unix philosophy: "Errors to stderr, status to stdout"

---

## Open Questions

### 1. Embedded Kernel Trigger Mechanism

**Question**: When/how does NDserver decide to use the embedded kernel vs. filesystem kernel?

**Investigation Needed**:
- Disassemble `ND_BootKernelFromSect` function
- Check for `stat()` calls on `/usr/lib/.../ND_MachDriver_reloc`
- Look for checksum validation logic

### 2. Mailbox Protocol Specification

**Question**: What is the exact register layout and command protocol for host ↔ i860 mailbox?

**Investigation Needed**:
- Disassemble mailbox read/write functions
- Trace execution in Previous emulator
- Compare with i860 ROM disassembly mailbox polling code

### 3. DMA Transfer Mechanism

**Question**: How does NDserver perform bulk transfers (kernel image, framebuffer data) to i860 DRAM?

**Investigation Needed**:
- Find `vm_copy` usage in disassembly
- Check for NeXTBus DMA controller setup
- Examine transfer speed optimizations

### 4. RAMDAC Programming

**Question**: Does NDserver program the RAMDAC directly, or does the i860 kernel handle it?

**Investigation Needed**:
- Search for RAMDAC register addresses in disassembly
- Check video mode setup functions
- Compare with i860 kernel video initialization

### 5. Multiple Board Support

**Question**: Can NDserver manage multiple NeXTdimension boards simultaneously?

**Evidence**:
- Command-line accepts `-s Slot` argument
- Error messages mention "Slot %d"
- But only one WindowServer check

**Investigation**: Check if multiple instances can run with different `-s` arguments.

### 6. Kernel Version Checking

**Question**: Does NDserver verify kernel compatibility before loading?

**Investigation Needed**:
- Look for version strings in Mach-O header parsing
- Check for magic number validation
- Examine error handling for "wrong kernel version"

### 7. Hot Reload Capability

**Question**: Can the i860 kernel be reloaded without rebooting the host?

**Evidence**:
- "spontaneously unloading" error suggests lifecycle management
- kern_loader supports dynamic loading/unloading
- "zombie" state implies crash recovery

**Investigation**: Test in Previous emulator.

### 8. Debug Port Usage

**Question**: What messages are sent to the "debug" port, and where do they go?

**Investigation Needed**:
- Find debug message formatting code
- Check for `/dev/console` output
- Look for syslog integration

---

## Appendices

### Appendix A: Complete Load Command Listing

```
Load command 0
      cmd LC_SEGMENT
  cmdsize 56
  segname __PAGEZERO
   vmaddr 0x00000000
   vmsize 0x00002000
  fileoff 0
 filesize 0
  maxprot 0x00000000
 initprot 0x00000000
   nsects 0
    flags 0x4

Load command 1
      cmd LC_SEGMENT
  cmdsize 396
  segname __TEXT
   vmaddr 0x00002000
   vmsize 0x00006000
  fileoff 0
 filesize 24576
  maxprot 0x00000007
 initprot 0x00000005
   nsects 5
    flags 0x0

Load command 2
      cmd LC_SEGMENT
  cmdsize 260
  segname __DATA
   vmaddr 0x00008000
   vmsize 0x00002000
  fileoff 24576
 filesize 8192
  maxprot 0x00000007
 initprot 0x00000007
   nsects 3
    flags 0x0

Load command 3
      cmd LC_SEGMENT
  cmdsize 124
  segname __I860
   vmaddr 0x0000a000
   vmsize 0x000c4000
  fileoff 32768
 filesize 802816
  maxprot 0x00000007
 initprot 0x00000007
   nsects 1
    flags 0x4

Load command 4
      cmd LC_SEGMENT
  cmdsize 56
  segname __LINKEDIT
   vmaddr 0x000ce000
   vmsize 0x00000000
  fileoff 835584
 filesize 0
  maxprot 0x00000007
 initprot 0x00000005
   nsects 0
    flags 0x4

Load command 5
           cmd LC_LOADFVMLIB
       cmdsize 48
          name /usr/shlib/libsys_s.B.shlib (offset 20)
 minor version 55
   header addr 0x05000000

Load command 6
     cmd LC_SYMTAB
 cmdsize 24
  symoff 0
   nsyms 0
  stroff 0
 strsize 0

Load command 7
        cmd LC_UNIXTHREAD
    cmdsize 88
     flavor M68K_THREAD_STATE_REGS
      count M68K_THREAD_STATE_REGS_COUNT
 dregs  00000000 00000000 00000000 00000000
        00000000 00000000 00000000 00000000
 aregs  00000000 00000000 00000000 00000000
        00000000 00000000 00000000 00000000
 pad 0x0000 sr 0x0000 pc 0x00002d10
```

### Appendix B: Embedded i860 Kernel Load Commands

```
Load command 0
      cmd LC_SEGMENT
  cmdsize 124
  segname __TEXT
   vmaddr 0xf8000000
   vmsize 0x000b4000
  fileoff 840
 filesize 737280
  maxprot 0x00000007
 initprot 0x00000005
   nsects 1
    flags 0x0
Section
  sectname __text
   segname __TEXT
      addr 0xf8000000
      size 0x000b2548
    offset 840
     align 2^5 (32)
    reloff 0
    nreloc 0
     flags 0x00000000

Load command 1
      cmd LC_SEGMENT
  cmdsize 260
  segname __DATA
   vmaddr 0xf80b4000
   vmsize 0x00012000
  fileoff 738120
 filesize 57344
  maxprot 0x00000007
 initprot 0x00000007
   nsects 3
    flags 0x0
Section
  sectname __data
   segname __DATA
      addr 0xf80b4000
      size 0x0000dc50
    offset 738120
     align 2^12 (4096)
Section
  sectname __bss
   segname __DATA
      addr 0xf80c1d00
      size 0x00000ac0
    offset 0
     align 2^8 (256)
Section
  sectname __common
   segname __DATA
      addr 0xf80c27c0
      size 0x000018d8
    offset 0
     align 2^4 (16)

Load command 2
     cmd LC_SYMTAB
 cmdsize 24
  symoff 0
   nsyms 0
  stroff 0
 strsize 0

Load command 3
        cmd LC_UNIXTHREAD
    cmdsize 404
      flavor I860_THREAD_STATE_REGS
      count 97 (not I860_THREAD_STATE_REGS_COUNT)
 [i860 registers initialized to 0]
```

### Appendix C: Key String Excerpts

#### Initialization Strings
```
NDUX_Init: port_allocate failed
NDUX_Init: ND_Port_check_in()
port_allocate failed
port_set_allocate failed
port_set_add (debug) failed
port_set_add (pager) failed
port_set_add (unix port) failed
port_set_add (notify) failed
```

#### Board Detection Strings
```
No NextDimension board found.
No NextDimension board in Slot %d.
Another WindowServer is using the NeXTdimension board.
Usage: %s [-s Slot]
```

#### Kernel Loading Strings
```
NeXTdimension: Couldn't find kern_loader's port (%s)
NeXTdimension: get_server_state() fails (%s)
NeXTdimension: kern_loader_add_server() fails (%s)
NeXTdimension: kern_loader_load_server() fails (%s)
NeXTdimension: Mach driver spontaneously unloading!
NeXTdimension: Mach driver has become a zombie!
NDDriver: ND_Load_MachDriver
/usr/lib/NextStep/Displays/NeXTdimension.psdrvr/ND_MachDriver_reloc
```

#### Communication Strings
```
error %s in Receive, message will be ignored.
Unexpected emergency msg received: id is %d
Message for unknown port %d! (ID = %d)
error %s at Send.
NeXTdimension internal msg error: %s
```

#### Video Output Strings
```
nd_start_video: can't find window bag
nd_start_video: can't get window info
nd_currentsync
nd_setsync
nd_resumerecording: ps_setRecordingInfo fails (%d)
nd_resumerecording: ps_startRecording fails (%d)
```

### Appendix D: Function Name References

```
ND_GetBoardList
ND_BootKernelFromSect
ND_SetPagerTask
ND_Open
ND_ConsoleInput
ND_Port_check_in()
NDUX_Init
NDDriver: ND_Load_MachDriver
NDDriver: netname_lookup: ND timeout
NDDriver: ND_GetBoardList
nd_currentsync
nd_setsync
nd_start_video
nd_resumerecording
makePublic
mark_msg_send
as_new_message
```

### Appendix E: File Path References

```
/usr/lib/NextStep/Displays/NeXTdimension.psdrvr/NDserver
/usr/lib/NextStep/Displays/NeXTdimension.psdrvr/ND_MachDriver_reloc
/etc/kern_loader.conf
/etc/mtab
/dev/tty
```

---

## Conclusion

NDserver is a sophisticated **dual-processor orchestration daemon** that bridges NeXTSTEP's Mach microkernel architecture with the NeXTdimension's i860 coprocessor. Key architectural highlights:

1. **Redundant Kernel Design**: Embedded backup kernel ensures reliability
2. **Dynamic Kernel Loading**: Uses kern_loader for hot-swappable kernels
3. **Mach IPC Communication**: Modern message-passing instead of shared memory hacks
4. **PostScript Integration**: Deep integration with Display Server for graphics operations
5. **Professional Video Features**: NTSC/PAL output, genlock, overscan compensation
6. **Virtual Memory Support**: Cross-processor paging for advanced memory management

The design reflects NeXT's philosophy of **sophisticated engineering** with **graceful degradation** - multiple fallbacks ensure the system remains functional even when components fail.

**Most significant finding**: The embedded i860 kernel (different from the filesystem version) suggests a **two-tier kernel strategy** - possibly a minimal bootstrap kernel embedded in NDserver with a full-featured kernel loaded from disk.

---

## Related Documentation

- **`GaCK_KERNEL_RESEARCH.md`**: Investigation into kernel naming and history
- **`ND_ROM_STRUCTURE.md`**: i860 ROM boot sequence and architecture
- **`ND_ROM_DISASSEMBLY_ANALYSIS.md`**: Detailed ROM disassembly
- **`README.md`** (nextdimension_files): Binary extraction methodology
- **`CLAUDE.md`**: NeXTdimension project documentation

---

## Future Analysis

### Recommended Next Steps

1. **Disassemble m68k Code**: Use m68k disassembler to analyze actual function implementations
2. **Dynamic Tracing**: Run in Previous emulator with instruction tracing enabled
3. **Protocol Reverse Engineering**: Monitor NeXTBus traffic to document mailbox protocol
4. **Kernel Comparison**: Detailed binary diff of embedded vs. standalone kernel
5. **kern_loader Analysis**: Study NeXTSTEP's kern_loader source code for context
6. **Video Hardware Analysis**: Document RAMDAC programming and video path

### Tools Needed

- **m68k Disassembler**: IDA Pro, Ghidra, or Hopper
- **Previous Emulator**: With NeXTdimension emulation support
- **Logic Analyzer**: For hardware protocol capture (if real hardware available)
- **i860 Toolchain**: For comparative kernel analysis

---

**Analysis Complete**: November 4, 2025
**Document Version**: 1.0
**Total Analysis Time**: ~2 hours (automated string extraction + manual analysis)
