# NDserver Initial Findings - Phase 1

**Date**: November 7, 2025
**Analysis Tool**: strings, otool
**Status**: Phase 1 - String Analysis Complete

---

## Executive Summary

**Critical Discoveries from String Analysis:**

1. ✅ **Kernel loading via kern_loader facility** (not mailbox!)
2. ✅ **Key function names preserved** (ND_GetBoardList, ND_BootKernelFromSect, etc.)
3. ✅ **Embedded i860 kernel path**: `/usr/lib/NextStep/Displays/NeXTdimension.psdrvr/ND_MachDriver_reloc`
4. ✅ **PostScript operations** - extensive Display PostScript code
5. ✅ **Video output support** - NeXTtv demonstration app
6. ✅ **Mach IPC ports** for communication

---

## Key Function Names Discovered

### Board Management
```
ND_GetBoardList          - Enumerate NeXTdimension boards
ND_BootKernelFromSect    - Boot i860 kernel from section
ND_SetPagerTask          - Set up paging task
NDPingKernel             - Ping i860 kernel
ND_Load_MachDriver       - Load Mach driver
ND_Port_check_in()       - Register Mach port
```

### Video Operations
```
nd_currentsync           - Get current sync mode
nd_setsync               - Set sync mode (NTSC/PAL)
nd_start_video           - Start video output
nd_resumerecording       - Resume recording
```

### Communication
```
NDUX_Init                - Initialize Unix interface
ND_ConsoleInput          - Console input handler
```

---

## Critical Path: Kernel Loading

**Key Discovery**: NDserver uses NeXTSTEP's **kern_loader** facility, not a mailbox protocol!

### String Evidence:
```
NeXTdimension: Couldn't find kern_loader's port (%s)
NeXTdimension: get_server_state() fails (%s)
NeXTdimension: kern_loader_add_server() fails (%s)
NeXTdimension: kern_loader_load_server() fails (%s)
NeXTdimension: Mach driver spontaneously unloading!
NeXTdimension: Mach driver has become a zombie!
```

**Kernel path**:
```
/usr/lib/NextStep/Displays/NeXTdimension.psdrvr/ND_MachDriver_reloc
```

**This means**:
1. NDserver finds kern_loader's Mach port
2. Registers the ND_MachDriver_reloc as a loadable server
3. Uses kern_loader_load_server() to load it onto i860
4. Communicates via Mach IPC, not hardware mailbox!

---

## Display PostScript Operations

**Extensive PostScript code found** - NDserver contains Display PostScript primitives!

### Graphics Operations (from strings):
```postscript
% Path operations
/moveto  (pl moveto)
/lineto  (pl lineto)
/curveto (pl curveto)

% Painting operations
/fill    (F)
/stroke  (S)
/clip    (clip newpath)

% State operators
/gsave   (_pola 0 eq {gsave} if)
/grestore (_pola 0 eq {grestore} if)

% Graphics state
/setlinewidth
/setlinecap
/setlinejoin
/setmiterlimit
/setdash
```

**This suggests**: NDserver translates Display PostScript to i860 commands!

**Protocol hypothesis**:
```
PostScript Operation → NDserver → Serialized Command → i860 Kernel → Render
```

---

## Video Output Subsystem

### NeXTtv Demonstration App

**Discovered**: NeXTdimension includes a TV output demo called "NeXTtv"

**Strings**:
```
NeXTtv.nib
NeXTtv_main.m
NeXTtv.app
Port: NeXTtv
Menu Item: NeXTtv/Output Selection
ScreenScape transparently outputs a partial rectangular area of your NeXTdimension screen to the NeXTdimension video output ports.
```

**Purpose**: Demonstrates video output by sending a rectangular region to NTSC/PAL outputs, tracking the cursor.

**This reveals**:
- Video output is a core feature
- Cursor tracking capability
- NTSC/PAL support confirmed

---

## Error Messages (Protocol Insights)

### Board Detection
```
No NextDimension board found.
No NextDimension board in Slot %d.
Another WindowServer is using the NeXTdimension board.
```

**Implies**:
- Slot-based detection (likely NeXTBus slot scanning)
- Multi-board support (slot number parameter)
- Exclusive access (only one WindowServer can use it)

### Kernel Loading Errors
```
NeXTdimension: Couldn't find kern_loader's port (%s)
NeXTdimension: get_server_state() fails (%s)
NeXTdimension: kern_loader_add_server() fails (%s)
NeXTdimension: kern_loader_load_server() fails (%s)
NeXTdimension: Mach driver spontaneously unloading!
NeXTdimension: Mach driver has become a zombie!
```

**Sequence**:
1. Find kern_loader port
2. Get server state
3. Add server to kern_loader
4. Load server onto i860
5. Monitor for unexpected unload/zombie state

### Runtime Errors
```
FAILURE IN NeXTdimension SERVER
NeXTdimension internal msg error: %s
Illegal memory access!
vm_region() on page out op
vm_allocate of copy area
vm_copy of copied area
ND vm_allocate fails (%d) addr 0x%x size %d %d
```

**Memory management**:
- Uses Mach VM primitives
- Page out operations
- Shared memory allocation (vm_allocate, vm_copy)

---

## Mach IPC Infrastructure

### Port Management
```
port_allocate failed
parent_port
/dev/tty
port_set_allocate failed
port_set_add (debug) failed
port_set_add (pager) failed
port_set_add (unix port) failed
port_set_add (notify) failed
```

**Port types**:
- **debug port**: Debugging interface
- **pager port**: Memory paging
- **unix port**: Unix IPC bridge
- **notify port**: Notifications

### Message Handling
```
error %s in Receive, message will be ignored.
Unexpected emergency msg received: id is %d
Message for unknown port %d! (ID = %d)
error %s at Send.
```

**Implies**:
- Message ID system
- Emergency message handling
- Unknown port rejection
- Send/receive error handling

---

## Embedded Data

### Copyright & Version
```
Copyright 1991, NeXT Computer, Inc.  All Rights Reserved.
NeXTSTEP Release 3
%%NXNextStepVersion: 3.0
%%BeginProcSet: /usr/lib/NextStep/printPackage.ps 3.0
```

**Release**: NeXTSTEP 3.0 (1991)

### File Paths
```
/usr/lib/NextStep/Displays/NeXTdimension.psdrvr/NDserver
/usr/lib/NextStep/Displays/NeXTdimension.psdrvr/ND_MachDriver_reloc
/usr/shlib/libNeXT_s.C.shlib
/dev/tty
```

### Debugging Artifacts
```
* simple.el (append-next-kill):
use c-backward-to-noncomment to find next real text.
Delete whitespace only next to commas.
* simple.el (next-complex-command): fix one-off about
```

**Surprise!** Emacs Lisp strings embedded (likely developer artifacts)

---

## Protocol Hypothesis

Based on strings analysis:

### Communication Flow

```
1. Board Detection:
   NeXTBus slot scan → Find NeXTdimension → Check slot ID

2. Kernel Loading:
   Find kern_loader port → Register ND_MachDriver_reloc →
   Load kernel onto i860 → Verify kernel alive

3. Communication Setup:
   Allocate Mach ports → Set up port sets →
   Register debug/pager/unix/notify ports

4. Graphics Operations:
   Display PostScript → NDserver translation →
   Mach message to i860 → i860 renders → Signal completion

5. Video Output:
   Configure sync (NTSC/PAL) → Start video →
   Track cursor rectangle → Output to ports
```

### NOT a Mailbox Protocol!

**Critical Insight**: Our hardware capture showed NO mailbox activity because:
- Communication is via **Mach IPC messages**, not hardware mailbox
- The "mailbox" at 0x02000000 may be for i860→host interrupts only
- Host→i860 commands go through **shared memory + Mach messages**

**This explains**:
- Why we saw only CSR0/CSR1 polling
- Why no command structures in hardware logs
- Why "mailbox" registers were never accessed

---

## Next Steps

### Phase 1B: Binary Structure (Ongoing)
- [ ] Extract __I860 segment (embedded kernel)
- [ ] Map function locations with otool
- [ ] Identify entry point and call graph

### Phase 2: Disassembly (Week 2)
- [ ] Disassemble key functions:
  - `ND_GetBoardList`
  - `ND_BootKernelFromSect`
  - `ND_Load_MachDriver`
- [ ] Trace board detection sequence
- [ ] Understand kern_loader interaction

### Phase 3: Mach IPC Protocol (Week 3)
- [ ] Find Mach message structures
- [ ] Identify message IDs
- [ ] Map operation codes
- [ ] Discover parameter formats

### Phase 4: Dynamic Analysis (Week 4)
- [ ] Correlate with hardware logs
- [ ] Trace Mach messages in emulator
- [ ] Capture shared memory accesses
- [ ] Verify protocol understanding

---

## Tools for Next Phase

**For m68k disassembly**:
```bash
# Hopper Disassembler (commercial but good for m68k)
# or Ghidra (free, supports m68k)
# or IDA Pro (best but expensive)
```

**For Mach-O analysis**:
```bash
otool -tV NDserver > disassembly/full_disasm.txt
otool -lv NDserver > analysis/segments.txt
nm -pa NDserver > analysis/symbols.txt (if not stripped)
```

**For segment extraction**:
```bash
# Extract __I860 segment
otool -s __I860 __i860 NDserver -X > extracted/i860_kernel_hex.txt
# Convert to binary
```

---

## Critical Questions to Answer

1. **How does ND_GetBoardList() scan NeXTBus?**
   - What addresses does it probe?
   - How does it identify NeXTdimension?

2. **How does ND_BootKernelFromSect() work?**
   - Where is the kernel in the binary?
   - How is it transferred to i860?

3. **What Mach messages are sent?**
   - Message structure?
   - Operation codes?
   - Parameter encoding?

4. **How are graphics commands serialized?**
   - PostScript → binary format?
   - Command queue structure?
   - Synchronization mechanism?

5. **How does video output work?**
   - Cursor tracking algorithm?
   - Frame buffer selection?
   - Sync configuration (NTSC/PAL)?

---

## Immediate Action Items

1. **Extract embedded i860 kernel**
   ```bash
   otool -s __I860 __i860 NDserver -X > i860_kernel.hex
   ```

2. **Map function addresses**
   ```bash
   otool -tV NDserver | grep "ND_" > nd_functions.txt
   ```

3. **Find board detection code**
   ```bash
   # Search for "No NextDimension board found" string reference
   # Trace back to function that checks it
   ```

4. **Understand kern_loader interface**
   ```bash
   # Look for kern_loader_* function calls
   # Find message structures
   ```

---

**Document Status**: PHASE 1 COMPLETE
**Date**: November 7, 2025
**Findings**: 3,869 strings analyzed
**Key Discovery**: Communication via Mach IPC + kern_loader, NOT hardware mailbox!
**Next Phase**: Binary structure and disassembly
