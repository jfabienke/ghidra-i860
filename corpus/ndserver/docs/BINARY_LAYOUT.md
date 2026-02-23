# NDserver Binary Layout Analysis

**Date**: November 7, 2025
**Tool**: otool
**Binary**: NDserver (m68k Mach-O, 835,584 bytes total)

---

## Complete Memory Map

```
Address Range        Size      Segment       Purpose
----------------------------------------------------------
0x00000000-0x00001FFF   8 KB   __PAGEZERO    Null pointer trap
0x00002000-0x00007FFF  24 KB   __TEXT        m68k code + data
0x00008000-0x00009FFF   8 KB   __DATA        Global variables
0x0000A000-0x000CDFFF 784 KB   __I860        Embedded i860 kernel ★
0x000CE000-0x000CE000   0 KB   __LINKEDIT    Link metadata (empty)
```

**Total**: 824 KB (835,584 bytes)

---

## Segment Details

### 1. __PAGEZERO (Protection)
```
VM Address:  0x00000000
VM Size:     0x00002000 (8 KB)
File Offset: 0
File Size:   0 (zero-fill)
Protection:  None (trap null pointers)
```

### 2. __TEXT (m68k Code - 24 KB)
```
VM Address:  0x00002000
VM Size:     0x00006000 (24 KB)
File Offset: 0
File Size:   24,576 bytes
Protection:  r-x (read + execute)
Sections:    5
```

#### __TEXT Sections:

**2a. __text (Main Code - 18.2 KB)**
```
Address:  0x00002D10
Size:     0x000048E8 (18,664 bytes)
Offset:   3,344 bytes
Purpose:  m68k executable code
```

**Key insight**: Only ~18KB of m68k code! Very small driver.

**2b. __fvmlib_init0 (Framework Init - 312 bytes)**
```
Address:  0x000075F8
Size:     0x00000138 (312 bytes)
Offset:   22,008 bytes
Purpose:  Shared library initialization
```

**2c. __fvmlib_init1 (Secondary Init - 0 bytes)**
```
Address:  0x00007730
Size:     0x00000000 (unused)
Purpose:  Secondary initialization (empty)
```

**2d. __cstring (C Strings - 811 bytes)**
```
Address:  0x00007730
Size:     0x0000032B (811 bytes)
Offset:   22,320 bytes
Purpose:  C string literals
```

This contains all the strings we extracted!

**2e. Unknown Section (1,444 bytes)**
```
Address:  0x00007A5C
Size:     0x000005A4 (1,444 bytes)
Offset:   23,132 bytes
Purpose:  Additional data
```

### 3. __DATA (Globals - 8 KB)
```
VM Address:  0x00008000
VM Size:     0x00002000 (8 KB)
File Offset: 24,576
File Size:   8,192 bytes
Protection:  rw- (read + write)
Sections:    3
```

Contains:
- Global variables
- Initialized data
- BSS (uninitialized data)

### 4. __I860 (Embedded Kernel - 784 KB) ★★★
```
VM Address:  0x0000A000
VM Size:     0x000C4000 (802,816 bytes = 784 KB)
File Offset: 32,768
File Size:   802,816 bytes
Protection:  rwx (read + write + execute)
Sections:    1
```

**This is the i860 GaCK kernel!**

**Size**: 802,816 bytes (vs ROM's 128KB = 6.27× larger!)

**Location in file**: Starts at byte 32,768 (0x8000)

### 5. __LINKEDIT (Empty)
```
VM Address:  0x000CE000
VM Size:     0 bytes
File Offset: 835,584
File Size:   0 bytes
Purpose:     Link metadata (stripped)
```

---

## Size Breakdown

```
Component            Size       Percentage
---------------------------------------------
m68k Code (__text)   18.2 KB      2.2%
m68k Data (__DATA)    8.0 KB      1.0%
i860 Kernel           784  KB     93.7%
Strings/Misc          2.8 KB      0.3%
Overhead              22.6 KB      2.7%
---------------------------------------------
Total                835.6 KB    100.0%
```

**Critical Finding**: The m68k driver is only **~26KB** (code + data), while the i860 kernel is **784KB**!

**This means**:
- m68k code is minimal (just a loader/interface)
- Real functionality is in the i860 kernel
- NDserver is primarily a **kernel delivery mechanism**

---

## m68k Code Analysis

### Entry Point
```
Address:  0x00002D10
Location: __TEXT.__text section
```

**This is where NDserver starts execution!**

### Code Size
```
Start:  0x00002D10
End:    0x000075F8 (approximate)
Size:   ~18.2 KB
```

**Functions to find**:
1. `main()` - Entry point
2. `ND_GetBoardList()` - Board detection
3. `ND_BootKernelFromSect()` - Kernel loading
4. `ND_Load_MachDriver()` - Mach driver setup
5. Mach IPC handlers
6. PostScript translation

### String References

**All strings are in**:
```
Address:  0x00007730-0x00007A5B
Size:     811 bytes
Count:    ~3,869 strings (from our extraction)
```

**To find function using a string**:
1. Find string address in __cstring section
2. Search code for references to that address
3. Trace back to function

**Example**: To find board detection code:
```
String: "No NextDimension board found." @ 0x00007XXX
→ Search for "movea.l #0x00007XXX" in code
→ Find function that references it
→ That's ND_GetBoardList()!
```

---

## i860 Kernel Extraction

### Method 1: Direct Binary Copy
```bash
dd if=NDserver of=i860_kernel.bin bs=1 skip=32768 count=802816
```

**Result**: 784KB i860 kernel binary

### Method 2: otool Hex Dump
```bash
otool -s __I860 __i860 NDserver -X > i860_kernel_hex.txt
# Then convert hex to binary
```

### Comparison with ROM

| Binary | Size | Source |
|--------|------|--------|
| ND_step1_v43_eeprom.bin | 128 KB | Boot ROM |
| i860_kernel.bin (extracted) | 784 KB | NDserver __I860 |

**The embedded kernel is 6× larger!**

**Why?**
- ROM: Minimal bootstrap (loads GaCK from host)
- Kernel: Full GaCK Mach kernel with:
  - Display PostScript interpreter
  - Graphics primitives
  - Memory management
  - Mach IPC handlers
  - Video output drivers
  - Font cache
  - etc.

---

## RE Strategy Update

### Focus on m68k Code (26KB)

**Priority 1**: Understand the small m68k driver:
1. **Board detection** - How does it find NeXTdimension?
2. **Kernel loading** - How does it extract and load __I860 segment?
3. **Communication setup** - Mach ports and IPC
4. **Message handling** - What messages does it send to i860?

**Tools**:
```bash
# Disassemble m68k code only
otool -tV NDserver | head -10000 > disassembly/m68k_code.asm

# Or use Ghidra/IDA for GUI analysis
```

### Defer i860 Kernel Analysis

**We already analyzed** the boot ROM (128KB) extensively.

**The embedded kernel (784KB)** can wait because:
- It's huge (weeks of work)
- m68k driver tells us HOW to communicate
- We can test protocol without understanding kernel internals
- Kernel functionality already documented in previous RE docs

**Strategy**:
1. ✅ Understand m68k driver (host→i860 protocol)
2. ❌ Skip detailed i860 kernel RE (already documented elsewhere)
3. ✅ Focus on message format and communication

---

## Immediate Next Steps

### 1. Extract i860 Kernel
```bash
cd /Users/jvindahl/Development/nextdimension/ndserver_re
dd if=NDserver of=extracted/i860_kernel.bin bs=1 skip=32768 count=802816
```

### 2. Verify Extraction
```bash
ls -lh extracted/i860_kernel.bin
file extracted/i860_kernel.bin
hexdump -C extracted/i860_kernel.bin | head -50
```

### 3. Compare with ROM
```bash
# Quick check: Do they share any code?
cmp -l extracted/i860_kernel.bin /Users/jvindahl/Downloads/NeXTROMS/NeXTDimension/dimension_eeprom.bin | head -20
```

### 4. Disassemble m68k Code
```bash
# Use Ghidra or Hopper (better than otool for m68k)
# Or: otool -tV NDserver > disassembly/m68k_full.asm
```

### 5. Find Key Functions
```bash
# Locate string references
grep -n "No NextDimension board found" analysis/strings_full.txt
# Find that address in disassembly
# Trace to function
```

---

## Summary

**Binary composition**:
- 93.7% i860 kernel (can mostly skip - already analyzed)
- 2.2% m68k code (**this is what we need to RE**)
- 4.1% data/overhead

**RE effort**:
- ✅ Strings analysis: DONE
- ✅ Binary structure: DONE
- ⏳ m68k disassembly: IN PROGRESS
- ⏸️  i860 kernel: DEFERRED (already documented)

**Next session**: Disassemble and analyze the 18KB of m68k code to understand host→i860 protocol!

---

**Document Status**: BINARY LAYOUT COMPLETE
**Date**: November 7, 2025
**Key Finding**: Only ~26KB m68k code to analyze (not 816KB!)
**Next Phase**: m68k disassembly and function identification
