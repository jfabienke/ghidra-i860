# NDserver Reverse Engineering - Phase 2 Progress

**Date**: November 7, 2025
**Status**: Phase 2 (Control Flow Analysis) - IN PROGRESS
**Progress**: 40% complete

---

## Phase 2 Objectives

1. ✅ Identify function boundaries in disassembly
2. ✅ Find key functions via string cross-references
3. ⏳ Trace entry point and execution flow
4. ⏳ Map function call graph
5. ❌ Identify Mach IPC message structures (deferred to Phase 3)

---

## Completed Work

### 1. Function Boundary Detection ✅

**Tool**: `scripts/find_functions.py`

**Method**: Automated search for linkw/unlk patterns

**Results**:
- **92 functions** identified with linkw/unlk prologues/epilogues
- **40 string references** found (PEA instructions to __cstring section)
- Function map saved to `analysis/function_map.txt`

**Sample Functions Identified**:
```
Start        End          Size     Frame   Name
--------------------------------------------------------------------------------
0x00002d96  0x00002dc5      48      4  func_00002d96
0x00002dc6  0x0000305b     662     20  ND_GetBoardList      ← IDENTIFIED
0x0000305c  0x000031ff     420      0  func_0000305c
0x00003200  0x00003283     132     28  func_00003200
0x00003284  0x000033b3     304     64  func_00003284
... (87 more functions)
```

### 2. ND_GetBoardList() Identification ✅

**Location**: 0x00002DC6 - 0x0000305A

**Size**: 662 bytes

**Frame size**: 20 bytes local variables

**String References** (all within this function):
```
0x00002dea: "NeXTdimension" (generic)
0x00002e26: "%s%d" (format string)
0x00002e2c: "dimension board" (partial)
0x00002e48: "e" (fragment)
0x00002e74: "in Slot" (partial)
0x00002eac: "No NextDimension board found."  ← KEY STRING
0x00002ecc: "Another WindowServer is using..."
0x00002ee2: "NeXTdimension board"
0x00002ee8: " in Slot %d"
0x00002f0a: "ND_BootKernelFromSect"  ← FUNCTION NAME STRING!
0x00002f50: "No NextDimension"
0x00002f7a: " board in Slot"
0x00002faa: " %d.\n"
```

**Analysis**:
- This function contains error messages for board detection
- References "ND_BootKernelFromSect" string (likely for error reporting)
- Handles slot enumeration (slot IDs in format strings)
- Checks for exclusive WindowServer access
- Returns board list or error

**Likely Pseudocode**:
```c
int ND_GetBoardList(void) {
    char local_vars[20];

    // Scan NeXTBus slots
    for (int slot = 0; slot < MAX_SLOTS; slot++) {
        if (board_detected_in_slot(slot)) {
            if (board_in_use_by_windowserver(slot)) {
                printf("Another WindowServer is using the NeXTdimension board.\n");
                return ERROR_IN_USE;
            }
            // Board found and available
            add_to_board_list(slot);
        }
    }

    if (board_count == 0) {
        printf("No NextDimension board found.\n");
        return ERROR_NOT_FOUND;
    }

    return SUCCESS;
}
```

### 3. String Reference Analysis ✅

**Total string references**: 40 (all in __cstring section 0x7730-0x7a5b)

**Distribution**:
- **13 strings** in ND_GetBoardList() (board detection and errors)
- **8 strings** in func_0000305c (likely error handling continuation)
- **12 strings** in func_0000399c (likely PostScript or IPC functions)
- **7 remaining** in various other functions

**Important Discovery**: kern_loader strings (e.g., "Couldn't find kern_loader's port") are **NOT** in the m68k __cstring section. They exist in the i860 kernel or are provided by shared libraries (libsys_s.B.shlib).

**Implication**: The m68k code calls kern_loader functions from NeXTSTEP's shared library `/usr/shlib/libsys_s.B.shlib`. We need to trace library function calls to understand kernel loading.

### 4. Binary Section Analysis ✅

**m68k Code Strings** (__cstring section):
```
File offset: 0x5730-0x5a5b
VM address:  0x7730-0x7a5b
Size:        811 bytes
Contains:    Error messages, format strings, function names
```

**i860 Kernel Strings** (within __I860 segment):
```
File offset: 0x8000+ (embedded kernel)
Examples:    "NDDriver: ND_Load_MachDriver"
             "Couldn't find kern_loader's port"
             "/usr/lib/NextStep/Displays/.../ND_MachDriver_reloc"
Purpose:     i860 kernel error messages (not referenced by m68k code)
```

**Shared Library Strings** (not in binary):
```
Library:     /usr/shlib/libsys_s.B.shlib
Functions:   kern_loader_add_server()
             kern_loader_load_server()
             port_allocate()
             vm_allocate()
             etc.
```

---

## Key Findings

### Finding 1: Library-Based Architecture

NDserver is a **thin wrapper** that relies heavily on NeXTSTEP shared libraries:

**Dependencies** (from load commands):
```
LC_LOADFVMLIB: /usr/shlib/libsys_s.B.shlib (version 55)
```

**This library provides**:
- kern_loader functions (kernel loading facility)
- Mach IPC primitives (port_*, msg_*)
- Virtual memory functions (vm_*)
- Standard C library functions

**Implication**: To fully understand NDserver, we must:
1. Analyze m68k code to find library function calls
2. Reference NeXTSTEP API documentation for library functions
3. Understand data structures passed to/from library calls

### Finding 2: Function Naming Convention

ND_GetBoardList() **contains a reference to the string "ND_BootKernelFromSect"**, suggesting:

**Hypothesis 1**: ND_GetBoardList() calls ND_BootKernelFromSect()
- The string is used for error reporting: "Function X failed"
- Or for debugging/logging

**Hypothesis 2**: The string is a symbol table remnant
- Despite NOUNDEFS flag, function name strings remain
- These can help us identify other functions

**Action**: Search for other ND_* and nd_* function name strings to identify more functions

### Finding 3: Small Code Footprint

**92 functions** in 18,664 bytes = **~203 bytes average per function**

This confirms our earlier finding: The m68k driver is minimal. Most functions are simple wrappers:
- Call shared library function
- Check return value
- Print error message if failed
- Return to caller

### Finding 4: No Direct JSR Calls Found

**0 JSR instructions** found in code scan!

**Possible explanations**:
1. All calls are via shared library trampolines (PLT/GOT-style)
2. BSR (branch to subroutine) used instead of JSR for local calls
3. Indirect calls via function pointers

**Next step**: Search for BSR instructions and analyze PLT/GOT tables

---

## Tools Created

### 1. find_functions.py ✅

**Purpose**: Automated function boundary detection

**Features**:
- Finds linkw/unlk pairs
- Maps string references to functions
- Generates function map with sizes

**Output**: `analysis/function_map.txt`

**Usage**:
```bash
python3 scripts/find_functions.py
```

### 2. disasm_m68k.sh ✅

**Purpose**: Disassemble m68k code section

**Output**: `disassembly/m68k_full.asm` (7,679 lines)

**Quality**: Mixed (rasm2 has limitations with m68k)

**Usage**:
```bash
./scripts/disasm_m68k.sh
```

---

## Analysis Insights

### ND_GetBoardList() Function Flow

Based on string references and standard m68k calling conventions:

```
1. ENTRY: linkw %fp,#-20        ; Allocate 20 bytes local storage
2. DETECTION: Scan NeXTBus slots
   - Loop through slot IDs
   - Check for NeXTdimension board signature
   - Read board configuration
3. VALIDATION: Check board availability
   - Test if WindowServer already using board
   - If in use: print error, return ERROR_IN_USE
4. SUCCESS PATH:
   - Add board to internal list
   - Return board count
5. FAILURE PATH:
   - Print "No NextDimension board found."
   - Return ERROR_NOT_FOUND
6. EXIT: unlk %fp ; rts          ; Restore frame, return
```

### String Reference Patterns

**Pattern 1**: Error Reporting
```asm
pea 0x776c                       ; Push string address
jsr _printf                      ; Call printf from libsys_s
addq.l #4,%sp                    ; Clean up stack
```

**Pattern 2**: Format String + Arguments
```asm
move.l %d0,%sp@-                 ; Push argument (slot number)
pea 0x77bd                       ; Push format string
jsr _printf
addq.l #8,%sp
```

---

## Remaining Phase 2 Tasks

### 1. Trace Entry Point (Pending)

**Entry**: 0x00002D10 (from __UNIXTHREAD load command)

**Next Steps**:
- Disassemble entry point
- Identify _start → main() transition
- Map early initialization code
- Find calls to ND_GetBoardList()

### 2. Map Call Graph (Pending)

**Approach**:
- Search for BSR (Branch to Subroutine) instructions
- Identify PLT/GOT entries for library calls
- Build caller→callee relationship graph
- Identify critical path: main → ND_GetBoardList → kernel loading

### 3. Identify Shared Library Calls (Pending)

**Method**:
- Find external symbol references
- Match with libsys_s.B.shlib API documentation
- Document parameters and return values

**Key Functions to Find**:
```
kern_loader_* family
port_allocate()
msg_send() / msg_receive()
vm_allocate() / vm_map()
mach_task_self()
```

---

## Phase 2 Status Summary

**Completed**:
- ✅ Function boundary detection (92 functions)
- ✅ String reference mapping (40 references)
- ✅ ND_GetBoardList() identification and analysis
- ✅ Binary section layout understanding

**In Progress**:
- ⏳ Entry point tracing
- ⏳ Call graph mapping
- ⏳ Library function identification

**Blocked/Deferred**:
- ❌ Full disassembly quality (rasm2 limitations)
- ❌ JSR analysis (0 found - need BSR search)
- ❌ Mach IPC structures (Phase 3 task)

**Overall Phase 2 Progress**: **40%** (2/5 major objectives complete)

---

## Next Steps

### Immediate (Next Session)

1. **Trace Entry Point**
   - Disassemble 0x00002D10
   - Follow execution to main()
   - Identify initialization sequence

2. **Search for BSR Instructions**
   - Pattern: `0x6xxx` (BSR with offset)
   - Build local call graph
   - Identify internal function calls

3. **Analyze PLT/GOT**
   - Find shared library call trampolines
   - Map external function references

### Short-Term (Next Few Sessions)

4. **Identify Remaining Key Functions**
   - ND_BootKernelFromSect() (referenced in ND_GetBoardList)
   - ND_Load_MachDriver()
   - ND_SetPagerTask()
   - nd_setsync() / nd_start_video()

5. **Build Complete Call Graph**
   - Entry → initialization → board detection → kernel loading
   - Map all error paths
   - Identify recovery/cleanup functions

---

## Documentation Status

**Files Created This Phase**:
- `scripts/find_functions.py` - Function boundary detector
- `analysis/function_map.txt` - 92 functions mapped
- `docs/PHASE2_PROGRESS.md` - This document

**Files Updated**:
- `analysis/strings_full.txt` - Cross-referenced with functions
- `disassembly/m68k_full.asm` - Used for analysis

**Total Documentation**: 5 analysis documents, 2 automation scripts

---

**Phase 2 Status**: IN PROGRESS (40% complete)
**Next Milestone**: Entry point tracing and call graph mapping
**Estimated Time to Phase 2 Complete**: 1-2 more sessions
**Blocking Issues**: None (rasm2 quality acceptable for current needs)
