# NeXTcube ROM v3.3 - Reverse Engineering Analysis Plan

**Date**: 2025-11-12
**ROM**: Rev_3.3_v74.bin (128KB)
**Architecture**: Motorola 68040
**Methodology**: Based on proven NeXTdimension RE process
**Status**: Phase 1 - Planning

---

## Executive Summary

This document outlines the systematic reverse engineering plan for NeXTcube ROM v3.3 (Rev 74), leveraging proven methodologies from the NeXTdimension firmware analysis project. The goal is to achieve complete functional understanding of all 351 identified functions and document the ROM Monitor, boot sequence, hardware initialization, and device drivers.

---

## Objectives

### Primary Goals

1. **Complete Function Analysis**: Document all 351 functions with:
   - Purpose and functionality
   - Call graph position
   - Parameter conventions
   - Hardware registers accessed
   - Integration with boot sequence

2. **ROM Monitor Documentation**: Full reverse engineering of:
   - Command dispatch table
   - All interactive commands (expect ~14 based on v2.5)
   - Command syntax and parameters
   - Error handling
   - Password protection mechanism

3. **Boot Sequence Mapping**: Complete flow from:
   - Entry point (0x0000001E)
   - Hardware detection and initialization
   - Memory configuration
   - Device enumeration
   - Boot device selection
   - OS loading

4. **Hardware Driver Identification**: Document drivers for:
   - SCSI (disk, optical, tape)
   - Ethernet (thin and twisted pair)
   - Floppy disk
   - Serial ports
   - Video/display
   - Sound (input/output)
   - Keyboard/mouse

5. **Version Comparison**: Compare to ROM v2.5 to identify:
   - New features
   - Bug fixes
   - Hardware support changes
   - Protocol updates

---

## Methodology

### Wave-Based Function Analysis

Following the NeXTdimension NDserver methodology, functions will be organized into waves based on dependencies and complexity:

**Wave 1: Entry Point and Bootstrap** (Priority: CRITICAL)
- FUN_0000001e (0x1E, 36 bytes) - Entry point
- Early initialization functions (0x000005AE - 0x00000EC6)
- Hardware detection primitives

**Wave 2: Major Initialization Functions** (Priority: HIGH)
- FUN_00000ec6 (0xEC6, 2,486 bytes) - Largest function, likely main init
- FUN_000018d4 (0x18D4, 1,562 bytes) - Second largest, major subsystem
- FUN_0000361a (0x361A, 930 bytes) - Third largest, complex operations

**Wave 3: Mid-Range Functions** (Priority: MEDIUM)
- 120+ medium functions (100-300 bytes)
- Device drivers
- Memory management
- I/O utilities

**Wave 4: Small Utility Functions** (Priority: LOW)
- 150+ small functions (20-100 bytes)
- Register accessors
- Helper routines
- Math primitives

**Wave 5: ROM Monitor Functions** (Priority: HIGH)
- Command dispatcher
- All 14+ commands (boot, examine, fill, etc.)
- Command parsing and validation
- User interaction

### Analysis Template

Each function will receive an 18-section comprehensive analysis (adapted from NDserver template):

```markdown
# Function: <NAME> (0x<ADDRESS>)

## 1. Function Overview
- Address: 0x<ADDRESS>
- Size: <BYTES> bytes
- Classification: <ENTRY|INIT|DRIVER|UTILITY|COMMAND>
- Confidence: <HIGH|MEDIUM|LOW>

## 2. Technical Details
- Calling convention: <DESCRIPTION>
- Stack frame size: <BYTES>
- Register usage: <D0-D7, A0-A7>
- Return value: <DESCRIPTION>

## 3. Disassembly (Annotated)
<Full annotated 68040 disassembly with comments>

## 4. Decompiled Pseudocode
<C-like pseudocode showing logic>

## 5. Control Flow Analysis
- Entry points: <LIST>
- Exit points: <LIST>
- Branches: <COUNT>
- Loops: <IDENTIFIED>

## 6. Data Flow Analysis
- Inputs: <REGISTERS/MEMORY>
- Outputs: <REGISTERS/MEMORY>
- Side effects: <HARDWARE/MEMORY>

## 7. Hardware Access Patterns
- MMIO registers accessed: <LIST WITH ADDRESSES>
- DMA operations: <IF ANY>
- Interrupt handling: <IF ANY>

## 8. Call Graph Position
- Called by: <LIST OF CALLERS>
- Calls to: <LIST OF CALLEES>
- Depth: <LEVEL FROM ENTRY>

## 9. Algorithm Description
<High-level description of what function does>

## 10. Error Handling
- Error codes returned: <LIST>
- Validation performed: <DESCRIPTION>
- Recovery mechanisms: <IF ANY>

## 11. Boot Sequence Integration
- Phase: <EARLY|MID|LATE|RUNTIME>
- Required for boot: <YES|NO>
- Dependencies: <LIST>

## 12. ROM Monitor Integration
- Command: <IF ROM MONITOR COMMAND>
- Syntax: <COMMAND SYNTAX>
- Examples: <USAGE EXAMPLES>

## 13. String References
- Strings accessed: <LIST WITH OFFSETS>
- Error messages: <LIST>
- Debug output: <IF ANY>

## 14. Comparison to v2.5
- Present in v2.5: <YES|NO|CHANGED>
- Differences: <DESCRIPTION>
- New functionality: <IF ANY>

## 15. Performance Characteristics
- Execution time estimate: <CYCLES>
- Critical path: <YES|NO>
- Optimization opportunities: <IF ANY>

## 16. Security Considerations
- Input validation: <DESCRIPTION>
- Buffer overflow risk: <ASSESSMENT>
- Privilege requirements: <SUPERVISOR|USER>

## 17. Testing Strategy
- Test cases: <LIST>
- Expected outputs: <DESCRIPTION>
- Edge cases: <LIST>

## 18. References
- Ghidra address: <LINK>
- Disassembly line: <LINE NUMBER>
- Related functions: <LIST>
- Documentation: <EXTERNAL REFS>
```

---

## Tools and Resources

### Primary Tools

1. **Ghidra 11.4.2** (Already configured)
   - Project: `/Users/jvindahl/Development/previous/reverse-engineering/nextdimension-files/ghidra-projects/nextdimension_rom_v3.3/`
   - 351 functions identified
   - 7,592 cross-references mapped

2. **Disassembly Files** (Already generated)
   - Complete disassembly: `nextcube_rom_v3.3_disassembly.asm` (7.2MB, 87,143 lines)
   - Full hex dump: `nextcube_rom_v3.3_hexdump.txt` (732KB, 8,293 lines)
   - String database: `nextcube_rom_v3.3_data_sections.md` (54KB, 472 strings)

3. **68040 Reference Materials**
   - Motorola 68040 User's Manual
   - NeXT Hardware Reference (for I/O registers)
   - ROM v2.5 analysis for comparison

### Analysis Scripts

#### Script 1: Function Extractor
```python
#!/usr/bin/env python3
"""
Extract individual function disassembly from complete listing
"""
import sys
import re

def extract_function(disasm_file, function_address, output_file):
    """
    Extract a single function's disassembly based on address
    """
    with open(disasm_file, 'r') as f:
        lines = f.readlines()

    in_function = False
    function_lines = []

    target = f"ram:{function_address:08x}"

    for line in lines:
        if target in line.lower():
            in_function = True

        if in_function:
            function_lines.append(line)

            # End of function (next function marker or return)
            if 'FUNCTION:' in line and len(function_lines) > 1:
                function_lines = function_lines[:-1]  # Remove next function marker
                break

    with open(output_file, 'w') as f:
        f.writelines(function_lines)

    print(f"Extracted {len(function_lines)} lines to {output_file}")

if __name__ == '__main__':
    extract_function(sys.argv[1], int(sys.argv[2], 16), sys.argv[3])
```

#### Script 2: Call Graph Builder
```python
#!/usr/bin/env python3
"""
Build function call graph from Ghidra disassembly
"""
import re
import json

def build_call_graph(disasm_file):
    """
    Extract function calls to build dependency graph
    """
    with open(disasm_file, 'r') as f:
        content = f.read()

    # Find all functions
    function_pattern = r';FUNCTION: (FUN_[0-9a-f]+)'
    functions = re.findall(function_pattern, content, re.IGNORECASE)

    call_graph = {}

    # For each function, find calls
    for func in functions:
        # Extract function section
        func_start = content.find(f';FUNCTION: {func}')
        func_end = content.find(';FUNCTION:', func_start + 1)
        if func_end == -1:
            func_end = len(content)

        func_body = content[func_start:func_end]

        # Find JSR (jump to subroutine) and BSR (branch to subroutine)
        calls = []
        for match in re.finditer(r'(jsr|bsr)\s+FUN_([0-9a-f]+)', func_body, re.IGNORECASE):
            called_func = f"FUN_{match.group(2)}"
            if called_func not in calls:
                calls.append(called_func)

        call_graph[func] = {
            'address': func.replace('FUN_', '0x'),
            'calls': calls
        }

    return call_graph

if __name__ == '__main__':
    graph = build_call_graph('nextcube_rom_v3.3_disassembly.asm')

    with open('call_graph.json', 'w') as f:
        json.dump(graph, f, indent=2)

    print(f"Call graph built: {len(graph)} functions")
```

#### Script 3: Hardware Register Analyzer
```python
#!/usr/bin/env python3
"""
Analyze hardware register access patterns in function
"""
import re

def analyze_hardware_access(disasm_text):
    """
    Find all MMIO register accesses in function
    """
    # Pattern for 68040 absolute addressing (memory-mapped I/O)
    mmio_pattern = r'\$?(0x)?0?([0-9a-f]{7,8})'

    registers = {}

    for match in re.finditer(mmio_pattern, disasm_text, re.IGNORECASE):
        addr_str = match.group(2)
        addr = int(addr_str, 16)

        # Filter for NeXT I/O space (0x02000000 - 0x03000000)
        if 0x02000000 <= addr <= 0x03000000:
            if addr not in registers:
                registers[addr] = {'address': addr, 'accesses': 0}
            registers[addr]['accesses'] += 1

    return sorted(registers.items())

if __name__ == '__main__':
    import sys
    with open(sys.argv[1], 'r') as f:
        text = f.read()

    regs = analyze_hardware_access(text)

    print("Hardware registers accessed:")
    for addr, data in regs:
        print(f"  0x{addr:08X}: {data['accesses']} accesses")
```

---

## Phase 1: Critical Path Analysis

### Week 1: Entry Point and Bootstrap (COMPLETE FIRST)

**Objective**: Understand ROM startup sequence from power-on to main init

**Functions to Analyze** (Priority order):
1. **FUN_0000001e** (0x1E, 36 bytes) - ENTRY POINT
   - Sets up stack pointer
   - Jumps to main initialization
   - **Must complete first** - everything depends on this

2. **Initial Hardware Setup** (0x005AE - 0x00C9C)
   - Early register initialization
   - CPU mode setup
   - Cache/MMU configuration

3. **FUN_00000ec6** (0xEC6, 2,486 bytes) - MAIN INIT
   - Largest function in ROM
   - Likely master initialization routine
   - Hardware detection and enumeration
   - Boot device selection

**Deliverable**: Complete boot sequence flow diagram showing:
- Entry point → Hardware init → Device detection → Boot selection

**Timeline**: 3-4 days

---

## Phase 2: Major Subsystems (WEEK 2)

### Device Drivers and I/O

**Functions to Analyze**:
1. **FUN_000018d4** (0x18D4, 1,562 bytes) - Major subsystem
   - Based on size, likely comprehensive driver
   - Candidates: SCSI, Ethernet, Display

2. **SCSI Driver Functions**
   - String references: "SCSI DMA intr?", "SCSI Bus Hung", "no SCSI disk"
   - Functions near string offsets: 0x00013AAF, 0x00014091, 0x000140A0

3. **Ethernet Driver Functions**
   - String references: "Ethernet address", "Ethernet (try thin interface)"
   - Functions near offsets: 0x00013385, 0x00013CD4

4. **Display/Video Functions**
   - Most accessed register: 0x02400008 (13 accesses)
   - Find all functions accessing this register

**Deliverable**: Complete driver documentation with:
- Initialization sequences
- Command protocols
- Error handling
- Hardware register usage

**Timeline**: 5-7 days

---

## Phase 3: ROM Monitor (WEEK 3)

### Interactive Command System

**Objective**: Full documentation of user-facing ROM Monitor

**Approach**:
1. **Find Command Dispatch Table**
   - Search disassembly for jump table patterns
   - Look near string "NeXT ROM monitor commands:" (0x00014CD8)
   - Compare to v2.5 dispatch table location (0x0100E6DC)

2. **Identify All Commands**
   - Boot command (string at 0x00012F79)
   - Examine command
   - Fill command
   - Help command ("?" handler)
   - Password commands
   - Test commands (DRAM, SCSI, Sound)

3. **Analyze Each Command Handler**
   - Parameter parsing
   - Validation
   - Execution
   - Output formatting
   - Error messages

**Expected Commands** (based on v2.5):
- `b` - boot
- `e` - examine memory
- `f` - fill memory
- `m` - memory test
- `p` - power on test
- `t` - trace
- `s` - step
- `c` - continue
- `r` - reset
- `?` - help
- `ej` - eject optical
- `ef` - eject floppy
- `p` - set password
- `ec` - error codes

**Deliverable**: Complete ROM Monitor reference guide

**Timeline**: 4-5 days

---

## Phase 4: Utility Functions and Helpers (WEEK 4)

### Supporting Functions

**Objective**: Document all helper and utility functions

**Categories**:
1. **Memory Operations**
   - memcpy, memset, memmove
   - Memory test functions
   - Cache management

2. **String Operations**
   - String compare, copy
   - Printf-like formatting
   - String parsing

3. **Math Operations**
   - Division, multiplication helpers
   - Bit manipulation
   - CRC/checksum

4. **Register Accessors**
   - Small functions (< 20 bytes)
   - Simple read/write wrappers
   - Hardware abstraction

**Deliverable**: Utility function library documentation

**Timeline**: 3-4 days

---

## Phase 5: Version Comparison (WEEK 5)

### Compare v2.5 vs v3.3

**Objective**: Identify all changes between ROM versions

**Method**:
1. **String Comparison**
   - v2.5: 154 strings (documented)
   - v3.3: 472 strings (extracted)
   - Find new strings → new features
   - Find missing strings → removed features

2. **Function Count Comparison**
   - v2.5: Unknown (need to analyze)
   - v3.3: 351 functions
   - Map corresponding functions

3. **I/O Register Changes**
   - v2.5: Known register usage
   - v3.3: 86 unique registers
   - Identify new hardware support

4. **Bug Fix Analysis**
   - Look for error message changes
   - Compare error handling code
   - Check for patch patterns

**Deliverable**: Comprehensive change log:
- New features
- Bug fixes
- Hardware updates
- Protocol changes

**Timeline**: 5-7 days

---

## Key Questions to Answer

### Boot Sequence
1. How does ROM detect installed RAM?
2. What is the DRAM configuration sequence?
3. How is boot device priority determined?
4. What is the SCSI scan procedure?
5. How does Ethernet boot work (BOOTP)?

### Hardware Detection
1. Which hardware is mandatory vs optional?
2. How are device interrupts configured?
3. What is the DMA setup procedure?
4. How is the video mode initialized?
5. What is the keyboard/mouse detection flow?

### ROM Monitor
1. What is the exact command dispatch mechanism?
2. How is password protection implemented?
3. What is the maximum command line length?
4. How are hex addresses parsed?
5. What is the error recovery strategy?

### Memory Management
1. What memory regions are tested?
2. How is parity checking configured?
3. What are the supported memory types (page/nibble mode)?
4. How are memory errors reported?
5. What is the maximum memory size supported?

### Version Changes
1. What new devices are supported in v3.3?
2. Were any ROM Monitor commands added/removed?
3. What bugs were fixed from v2.5?
4. Are there protocol changes?
5. What is the performance impact of changes?

---

## Documentation Structure

All analysis will be organized in:
```
/Users/jvindahl/Development/previous/docs/hardware/nextcube-rom-v3.3-analysis/
├── README.md                                    # Analysis overview
├── FUNCTION_INDEX.md                            # Master function list
├── CALL_GRAPH_COMPLETE.md                       # Full dependency graph
├── BOOT_SEQUENCE_DETAILED.md                    # Complete boot flow
├── ROM_MONITOR_COMPLETE.md                      # All commands documented
├── HARDWARE_INITIALIZATION_GUIDE.md             # Hardware setup reference
├── DRIVER_ANALYSIS/
│   ├── SCSI_DRIVER_COMPLETE.md
│   ├── ETHERNET_DRIVER_COMPLETE.md
│   ├── FLOPPY_DRIVER_COMPLETE.md
│   ├── DISPLAY_DRIVER_COMPLETE.md
│   └── SERIAL_DRIVER_COMPLETE.md
├── FUNCTIONS/                                   # Individual function analyses
│   ├── FUN_0000001e_entry_point.md
│   ├── FUN_00000ec6_main_init.md
│   ├── FUN_000018d4_major_subsystem.md
│   └── [349 more function analyses]
├── COMPARISON/
│   ├── v2.5_vs_v3.3_CHANGES.md
│   ├── NEW_FEATURES_v3.3.md
│   ├── BUG_FIXES_v3.3.md
│   └── STRING_COMPARISON_REPORT.md
└── VERIFICATION/
    ├── BOOT_SEQUENCE_VERIFIED.md
    ├── COMMAND_DISPATCH_VERIFIED.md
    └── HARDWARE_ACCESS_VERIFIED.md
```

---

## Success Criteria

### Completeness
- ✅ All 351 functions analyzed and documented
- ✅ Complete boot sequence flow diagram created
- ✅ All ROM Monitor commands documented with syntax
- ✅ All device drivers identified and mapped
- ✅ All hardware registers documented with purposes

### Accuracy
- ✅ Cross-referenced with known v2.5 behavior
- ✅ Validated against NeXT hardware documentation
- ✅ Tested hypotheses where possible (emulator)
- ✅ Peer review of critical functions

### Usability
- ✅ Clear documentation accessible to developers
- ✅ Previous emulator integration guide created
- ✅ Function reference cards for quick lookup
- ✅ Searchable function database

### Comparison
- ✅ Complete v2.5 vs v3.3 change log
- ✅ New features identified and documented
- ✅ Bug fixes cataloged
- ✅ Hardware updates mapped

---

## Timeline

**Total Estimated Duration**: 5-6 weeks

**Breakdown**:
- Week 1: Entry point and bootstrap (3-4 days)
- Week 2: Device drivers (5-7 days)
- Week 3: ROM Monitor (4-5 days)
- Week 4: Utility functions (3-4 days)
- Week 5: Version comparison (5-7 days)
- Buffer: 1 week for deep dives and corrections

**Milestones**:
- Day 4: Boot sequence documented
- Day 11: All drivers mapped
- Day 16: ROM Monitor complete
- Day 20: All functions categorized
- Day 27: v2.5 comparison complete
- Day 35: Final documentation and verification

---

## Risks and Mitigations

### Risk 1: Function Complexity
**Risk**: Some functions too complex to fully understand
**Mitigation**: Focus on external interface (inputs/outputs/purpose), defer internal algorithm details

### Risk 2: Unknown Hardware
**Risk**: I/O registers without documentation
**Mitigation**: Compare to v2.5, use NeXT hardware manuals, infer from usage patterns

### Risk 3: Time Overrun
**Risk**: 351 functions × detailed analysis = many person-hours
**Mitigation**: Prioritize critical path (Waves 1-2), parallelize utility function analysis

### Risk 4: Missing Context
**Risk**: Code references external components (OS, drivers)
**Mitigation**: Document assumptions, mark "needs verification", cross-reference v2.5

### Risk 5: Tool Limitations
**Risk**: Ghidra may misidentify function boundaries or data
**Mitigation**: Manual verification of critical functions, cross-check with multiple tools

---

## Next Steps

1. **Immediate** (Today):
   - ✅ Create this plan document
   - Start Phase 1: Extract and analyze FUN_0000001e (entry point)
   - Build call graph from Ghidra disassembly

2. **This Week**:
   - Complete bootstrap analysis (Wave 1)
   - Document FUN_00000ec6 (main init)
   - Create initial boot sequence diagram

3. **Next Week**:
   - Begin driver analysis (Wave 2)
   - Identify ROM Monitor dispatch table
   - Start comprehensive function index

---

## References

### NeXTdimension Methodology
- `REVERSE_ENGINEERING_PROCESS.md` - Proven 7-phase approach
- `REVERSE_ENGINEERING_TECHNIQUES_AND_TOOLING.md` - Complete toolchain and techniques
- `PHASE5_EXHAUSTIVE_ANALYSIS.md` - Lessons learned (branch target analysis, sampling bias)
- `NDserver` analysis - 88 functions, 18-section template, wave-based approach

### NeXTcube ROM Documentation
- `nextcube-rom-v3.3-analysis.md` - Initial structure analysis
- `nextcube-rom-v3.3-ghidra-analysis.md` - Function inventory
- `nextcube-rom-v3.3-data-sections.md` - String database
- Previous ROM v2.5 analysis (comparison baseline)

### Tools
- Ghidra project: `nextdimension_rom_v3.3/`
- Disassembly: `nextcube_rom_v3.3_disassembly.asm` (7.2MB)
- Hex dump: `nextcube_rom_v3.3_hexdump.txt` (732KB)

---

**Status**: PLAN COMPLETE - Ready to begin Phase 1
**Confidence**: HIGH (methodology proven on 686KB i860 firmware + 88-function m68k driver)
**Expected Success Rate**: 95%+ accuracy based on NeXTdimension results

---

**Created**: 2025-11-12
**Author**: Systematic analysis based on NeXTdimension RE methodology
**Next**: Begin Wave 1 - Entry Point Analysis
