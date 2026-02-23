# Function Analysis Methodology

**Project**: NeXTSTEP NDserver Driver Reverse Engineering
**Document Version**: 1.0
**Date**: 2025-11-08
**Author**: Claude Code
**Status**: Active - Proven Method (5 functions completed successfully)

---

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Analysis Workflow](#analysis-workflow)
4. [Step-by-Step Process](#step-by-step-process)
5. [Documentation Standards](#documentation-standards)
6. [Quality Checklist](#quality-checklist)
7. [Common Patterns](#common-patterns)
8. [Troubleshooting](#troubleshooting)
9. [Examples](#examples)

---

## Overview

This document describes the **proven methodology** for analyzing individual functions in the NDserver binary. This process has been successfully applied to 5 functions with comprehensive results:

- ND_RegisterBoardSlot (366 bytes)
- ND_ProcessDMATransfer (976 bytes)
- ND_WriteBranchInstruction (352 bytes)
- ND_MessageDispatcher (272 bytes)
- ND_URLFileDescriptorOpen (164 bytes)

**Average Time per Function**: 40 minutes
**Output Quality**: 800-1400 lines of comprehensive documentation per function

---

## Prerequisites

### Required Tools and Files

1. **Ghidra Export Files** (already generated):
   - `ghidra_export/disassembly_full.asm` - Complete disassembly
   - `ghidra_export/functions.json` - Function metadata
   - `ghidra_export/call_graph.json` - Call relationships

2. **Binary File**:
   - `/Users/jvindahl/Downloads/NeXTSTEP/extracted_files/NDserver`

3. **Supporting Documentation**:
   - `docs/FUNCTION_INDEX.md` - Master index (UPDATE after each function)
   - `database/analysis_order.json` - Priority ordering
   - Previous function analyses for reference

### Required Knowledge

- **m68k Assembly**: Motorola 68000 instruction set
- **Calling Conventions**: m68k System V ABI (link frame, stack parameters)
- **NeXTdimension Architecture**: Host (68040) ↔ Board (i860) communication
- **Reverse Engineering Principles**: Control flow, data structures, protocol analysis

---

## Analysis Workflow

### High-Level Process

```
1. SELECT next function from priority list
2. EXTRACT disassembly from Ghidra export
3. ANALYZE control flow and identify patterns
4. DOCUMENT in comprehensive Markdown
5. CREATE annotated assembly file
6. UPDATE function index
7. UPDATE todo list
8. REPEAT for next function
```

### Time Breakdown (per function)

- **Selection & Setup**: 2-3 minutes
- **Control Flow Analysis**: 10-15 minutes
- **Documentation Writing**: 20-30 minutes
- **Annotated Assembly**: 5-10 minutes
- **Index Update**: 2-3 minutes
- **Total**: ~40 minutes average

---

## Step-by-Step Process

### Step 1: Select Next Function

**Goal**: Identify the next function to analyze based on priority

**Actions**:

1. Check `docs/FUNCTION_INDEX.md` under "Layer 0 - Leaf Functions"
2. Select first function with status "Pending" and highest call count
3. Note the address (e.g., `0x00006474`)

**Example**:
```bash
# From FUNCTION_INDEX.md:
| Address  | Name            | Size | Calls | Status |
|----------|-----------------|------|-------|--------|
| 0x00006474 | FUN_00006474  | ?    | 1     | Pending | ← SELECT THIS
```

**Update Todo List**:
```json
{
  "content": "Manually analyze FUN_00006474",
  "status": "in_progress",
  "activeForm": "Analyzing FUN_00006474"
}
```

---

### Step 2: Extract Disassembly

**Goal**: Get complete assembly code for the function

**Actions**:

1. Find function in `ghidra_export/disassembly_full.asm`:
   ```bash
   grep -n "^  0x00006474:" disassembly_full.asm
   ```
   Output: `4254:  0x00006474:  link.w     A6,-0x4`

2. Read the function (line 4254 to next function):
   ```bash
   # Read from line 4254, ~100 lines should capture most functions
   # Next function typically starts with "Function: FUN_xxxxxxxx" comment
   ```

3. Calculate function size:
   ```python
   start_addr = 0x6474
   next_func_addr = 0x6518  # Found from disassembly
   size = next_func_addr - start_addr  # 164 bytes
   ```

**Output**: Complete disassembly text for analysis

---

### Step 3: Analyze Control Flow

**Goal**: Understand function behavior, identify patterns, discover purpose

**Sub-Steps**:

#### 3.1: Identify Function Signature

Look at prologue and parameters:
```m68k
link.w      A6, #-0x4                 ; Stack frame size
move.l      (0x8,A6), D3              ; First parameter
move.l      (0xc,A6), D2              ; Second parameter
```

**Determine**:
- Number of parameters (stack offsets: 0x8, 0xc, 0x10, ...)
- Return value (D0 typically)
- Preserved registers (saved/restored via movem.l)
- Stack locals (negative offsets from A6)

#### 3.2: Trace Control Flow

**Identify**:
- Entry point (after prologue)
- Branch targets (beq, bne, bra, bsr)
- Loops (backward branches)
- Switch statements (jump tables with computed addresses)
- Error paths (early returns with error codes)
- Success paths (normal return with D0 = result)

**Mark Labels**:
```m68k
.error_return_zero:    ; Error exit path
.retry_with_file_open: ; Fallback strategy
.epilogue:             ; Cleanup and return
```

#### 3.3: Identify Library Calls

Functions starting with `0x05xxxxxx` are library functions:

```m68k
bsr.l       0x0500315e    ; atoi() or strtol()
bsr.l       0x05002c54    ; fdopen() or similar
bsr.l       0x050028c4    ; printf()
```

**Common Library Functions**:
- `0x050020xx` - File I/O (open, close, read, write)
- `0x050028xx` - String formatting (printf, sprintf)
- `0x050029xx` - Mach IPC or system calls
- `0x05002cxx` - File descriptor operations
- `0x05003xxx` - String manipulation (strlen, strcpy, etc.)

#### 3.4: Identify Internal Calls

Functions starting with `0x0000xxxx` are internal NDserver functions:

```m68k
bsr.l       0x00004a52    ; FUN_00004a52 - Internal function
bsr.l       0x00005256    ; FUN_00005256 - Internal function
```

**Note**: These are high-priority targets for future analysis

#### 3.5: Discover Data Structures

Look for structure field accesses:
```m68k
move.l      (0x14,A1), D0    ; message->field_0x14
move.l      (0x1c,A4), ...   ; result->field_0x1C
```

**Build Structure Maps**:
```c
typedef struct {
    // ... fields 0x00-0x13 ...
    uint32_t  field_0x14;    // Accessed at +0x14
    // ... fields 0x18-0x1B ...
    int32_t   field_0x1C;    ; Accessed at +0x1C
} discovered_struct_t;
```

#### 3.6: Identify Global Variables

Absolute address accesses:
```m68k
move.l      (0x79f6).l, ...     ; Format string at 0x79f6
move.l      ..., (0x8054).l     ; Global variable at 0x8054
cmp.l       (0x7a5c).l, ...     ; Constant or global at 0x7a5c
```

#### 3.7: Determine Function Purpose

**Ask**:
- What does it initialize? → Initialization function
- What does it validate? → Validation function
- What does it transform? → Parser/converter
- What does it send/receive? → Communication function
- What does it loop over? → Iterator/batch processor

**Name Heuristics**:
- Calls `malloc/calloc` → Allocator
- Calls `open/fdopen` → File opener
- Has jump table → Dispatcher/router
- Writes to hardware → Device controller
- Compares strings → Parser/validator

---

### Step 4: Create Comprehensive Markdown Documentation

**Goal**: Produce 800-1400 line analysis document

**Template Structure** (copy from `docs/FUNCTION_ANALYSIS_EXAMPLE.md`):

#### Required Sections

1. **Executive Summary** (100-200 words)
   - One-paragraph function overview
   - Key characteristics (3-5 bullet points)
   - Likely role in the system

2. **Function Signature**
   - C prototype (reverse-engineered)
   - Parameter table with offsets, types, descriptions
   - Return value semantics
   - Calling convention notes

3. **Complete Annotated Disassembly**
   - Full m68k assembly with inline comments
   - Label all branches (.error_exit, .success_path, etc.)
   - Explain every non-trivial instruction
   - Add section dividers (prologue, main logic, error handling, epilogue)

4. **Stack Frame Layout**
   - ASCII art diagram showing stack structure
   - All local variables with offsets
   - Saved registers
   - Parameters above frame pointer

5. **Hardware Access** (if applicable)
   - Memory-mapped I/O registers
   - Device addresses
   - Port I/O operations
   - Or "None" if no hardware access

6. **OS Functions and Library Calls**
   - Table of all library functions with addresses
   - Likely identity based on calling pattern
   - Evidence for identification
   - Internal function calls (for future analysis)

7. **Reverse-Engineered C Pseudocode**
   - Readable C code showing logic
   - Comments explaining behavior
   - Match assembly structure (don't over-simplify)
   - Include edge cases and error handling

8. **Data Structures**
   - All structures accessed or created
   - Field layouts with offsets
   - Type inference from usage
   - Global variable definitions

9. **Call Graph**
   - "Called By" section (from call_graph.json)
   - "Calls To" section (internal + library)
   - Tree diagram showing relationships

10. **Purpose Classification**
    - Primary function (one clear statement)
    - Secondary functions (bullet list)
    - Likely use case (with examples)

11. **Error Handling**
    - Error codes (values and meanings)
    - Error paths through the function
    - Recovery mechanisms

12. **Protocol Integration**
    - How this function fits in NeXTdimension protocol
    - Message formats or data flows
    - Integration with other analyzed functions

13. **m68k Architecture Details**
    - Register usage table
    - Optimization notes (if interesting)
    - Architecture-specific patterns

14. **Analysis Insights**
    - Key discoveries made during analysis
    - Architectural patterns observed
    - Connections to other functions

15. **Unanswered Questions**
    - What remains unknown
    - Ambiguities in interpretation
    - Areas needing further investigation

16. **Related Functions**
    - Directly called functions (HIGH PRIORITY for analysis)
    - Related by pattern or purpose
    - Suggested analysis order

17. **Testing Notes**
    - Test cases for validation
    - Expected behavior
    - Debugging tips

18. **Function Metrics**
    - Size, instruction count, complexity
    - Cyclomatic complexity estimate
    - Call depth, stack usage
    - Complexity rating (Low/Medium/High)

**File Naming**: `docs/functions/[ADDRESS]_[FunctionName].md`
Example: `docs/functions/00006474_ND_URLFileDescriptorOpen.md`

---

### Step 5: Create Annotated Assembly File

**Goal**: Production-quality commented assembly

**Format**:
```m68k
; ====================================================================================
; ANNOTATED DISASSEMBLY: [FunctionName]
; ====================================================================================
; Address: [0xADDRESS]
; Size: [XXX bytes]
; Purpose: [One-line description]
; Analysis: docs/functions/[ADDRESS]_[FunctionName].md
; ====================================================================================

; FUNCTION: [C signature]
;
; [Multi-line description of what the function does]
;
; PARAMETERS:
;   [param1] ([location]): [description]
;   [param2] ([location]): [description]
;
; RETURNS:
;   [D0 description]
;
; STACK FRAME: [size]
;   [local var descriptions]
;
; ====================================================================================

FUN_[ADDRESS]:
    ; --- PROLOGUE ---
    link.w      A6, #-0xNN               ; Create NN-byte stack frame
    move.l      D3, -(SP)                ; Save D3 (callee-save)

    ; --- [MAJOR SECTION NAME] ---
    ; [Explanation paragraph]
    instruction operands                  ; Inline comment
    instruction operands                  ; Inline comment

    ; --- [NEXT SECTION] ---
    ...

; ====================================================================================
; END OF FUNCTION: [FunctionName]
; ====================================================================================
;
; FUNCTION SUMMARY:
; [Brief summary of behavior]
;
; REVERSE-ENGINEERED C EQUIVALENT:
; [Paste C pseudocode here for reference]
;
; ====================================================================================
```

**File Naming**: `disassembly/annotated/[ADDRESS]_[FunctionName].asm`
Example: `disassembly/annotated/00006474_ND_URLFileDescriptorOpen.asm`

**Guidelines**:
- Comment **every** instruction that isn't trivial
- Use section headers (`; --- SECTION ---`)
- Explain **why**, not just what
- Add labels for all branch targets
- Include summary at end

---

### Step 6: Update Function Index

**Goal**: Keep master index current

**File**: `docs/FUNCTION_INDEX.md`

**Updates Required**:

1. **Header Stats**:
   ```markdown
   **Analyzed**: 5 → 6
   **Remaining**: 83 → 82
   ```

2. **Completed Analyses Table**:
   ```markdown
   | 0x00006474 | ND_URLFileDescriptorOpen | 164  | Low-Medium | [Analysis](...) |
   ```
   Keep sorted by address

3. **Layer 0 Functions Table**:
   ```markdown
   | 0x00006474 | FUN_00006474  | 164  | 1     | ✅ Done |
   ```

4. **Completion Rate**:
   ```markdown
   ### Completion Rate: 6.8% (6/88 functions)

   - Completed: ~4.0 hours
   - Remaining: ~54.7 hours
   ```

5. **Complexity Distribution**:
   ```markdown
   | Low-Medium  | 3     | 50%        |  ← Update percentages
   ```

6. **Cross-References by Category**:
   ```markdown
   **Device/File Operations**:
   - ND_URLFileDescriptorOpen (0x00006474) - Parse URL and open FD
   ```

7. **Revision History**:
   ```markdown
   | 2025-11-08 | Claude Code | Added ND_URLFileDescriptorOpen      | 1  |
   ```

---

### Step 7: Update Todo List

**Goal**: Track progress accurately

**Mark Current Complete**:
```json
{
  "content": "Manually analyze FUN_00006474",
  "status": "completed",
  "activeForm": "Manually analyzing FUN_00006474"
}
```

**Update Remaining Count**:
```json
{
  "content": "Continue remaining 4 functions to complete request of 10",
  "status": "in_progress",
  "activeForm": "Continuing analysis of remaining functions"
}
```

---

## Documentation Standards

### Naming Conventions

**Function Names**:
- Use descriptive names: `ND_URLFileDescriptorOpen` not `parse_url`
- Prefix with `ND_` for NeXTdimension functions
- Use verb + noun: `Register`, `Process`, `Write`, `Open`
- CamelCase: `ND_WriteBranchInstruction`

**File Names**:
- Markdown: `[8-digit-hex-address]_[FunctionName].md`
- Assembly: `[8-digit-hex-address]_[FunctionName].asm`
- Pad address with leading zeros: `00006474` not `6474`

**Structure Names**:
- Suffix with `_t`: `nd_message_t`, `board_info_t`
- Prefix discovered fields: `field_0x14` (before purpose known)
- Update when purpose discovered: `message_type` (after analysis)

### Writing Style

**Documentation**:
- **Clarity over brevity**: Explain thoroughly
- **Assume knowledgeable reader**: Don't explain m68k basics
- **Be specific**: "Port number from URL" not "some parameter"
- **Show evidence**: "Likely printf() based on format string" not "might be printf"

**Comments**:
- **Explain intent**: "Validate message type against max (5)" not "Compare D0 with 5"
- **Note special cases**: "Error code -0x131 (305 decimal)"
- **Cross-reference**: "See ND_RegisterBoardSlot for structure definition"

### Formatting

**Markdown**:
- Use tables for structured data
- Code blocks for assembly/C code
- Bullet lists for enumerations
- ASCII art for memory layouts

**Assembly**:
- Align comments at column 40
- Use semicolon+space: `; Comment`
- Indent labels by 0, instructions by 4 spaces
- Section headers: `; --- SECTION NAME ---`

---

## Quality Checklist

### Before Considering Function Complete

- [ ] **Disassembly extracted** - All instructions captured
- [ ] **Control flow understood** - All branches traced
- [ ] **Library calls identified** - At least categorized if not named
- [ ] **Data structures mapped** - Key fields documented
- [ ] **Purpose determined** - Can explain what it does and why
- [ ] **Markdown document created** - 800+ lines, all sections
- [ ] **Annotated assembly created** - Every instruction commented
- [ ] **Function index updated** - All 7 sections modified
- [ ] **Todo list updated** - Current status reflected
- [ ] **Cross-references added** - Links to related functions
- [ ] **Examples provided** - Test cases or usage scenarios
- [ ] **Uncertainties documented** - "Unanswered Questions" section filled

### Quality Indicators

**Good Analysis**:
- Multiple interpretations considered
- Edge cases identified
- Error paths explained
- Integration with protocol discussed
- Related functions noted for future work

**Incomplete Analysis**:
- "Unknown" without investigation
- No C pseudocode provided
- Library calls not categorized
- No testing notes
- Missing sections from template

---

## Common Patterns

### Pattern 1: Jump Table Dispatcher

**Indicators**:
- Load value into D0/D1
- Load table address into A0
- Indexed load: `movea.l (0x0,A0,D0*4), A0`
- Indirect jump: `jmp (A0)`

**Analysis Approach**:
1. Find comparison that validates range (e.g., `cmp.l #5, D0`)
2. Locate jump table data (often all zeros in binary)
3. Identify case handlers by branch targets
4. Map cases to handlers (may require runtime analysis)

**Example**: ND_MessageDispatcher (0x6e6c)

### Pattern 2: Dual-Strategy Opening

**Indicators**:
- First operation attempt
- Test result
- On failure, try alternative approach
- Cleanup on both paths

**Analysis Approach**:
1. Identify fast path (primary method)
2. Identify slow path (fallback)
3. Note conditions for each path
4. Document why two strategies exist

**Example**: ND_URLFileDescriptorOpen (0x6474)

### Pattern 3: Validation Chain

**Indicators**:
- Series of comparisons
- Each failure branches to error exit
- Success falls through to next check
- Final check leads to success path

**Analysis Approach**:
1. List all validation criteria
2. Document order of checks (often important)
3. Note error codes for each failure
4. Identify what structure/state is validated

**Example**: ND_WriteBranchInstruction (0x746c)

### Pattern 4: Loop with Address Translation

**Indicators**:
- Loop counter initialized
- Array/table indexed by counter
- Address calculation (mask, shift, add)
- Counter incremented
- Compare against limit

**Analysis Approach**:
1. Identify loop bounds
2. Trace address calculation formula
3. Document translation (e.g., host → i860 address)
4. Note what's done with translated address

**Example**: ND_ProcessDMATransfer (0x709c)

### Pattern 5: Structure Allocation & Initialization

**Indicators**:
- Call to malloc/calloc or table lookup
- Series of field writes
- Initialization with constants or parameters
- Return pointer in D0 or via parameter

**Analysis Approach**:
1. Determine structure size
2. Map all field initializations
3. Create structure typedef
4. Note which fields remain uninitialized

**Example**: ND_RegisterBoardSlot (0x36b2)

---

## Troubleshooting

### Issue: Can't Determine Function Purpose

**Solutions**:
1. **Check callers**: Who calls this? What context?
2. **Check calls**: What functions does it call? That hints at purpose
3. **Check parameters**: What types of data? File paths? Addresses?
4. **Check globals**: Writing to hardware registers? Reading config?
5. **Look for strings**: Error messages or format strings hint at purpose
6. **Partial analysis OK**: Document as "Unknown purpose, possibly X or Y"

### Issue: Library Function Unknown

**Solutions**:
1. **Check parameter count**: 1 arg = strlen?, 2 args = strcmp?, 3+ = sprintf?
2. **Check return usage**: Void return? Integer? Pointer?
3. **Check address range**: 0x05002xxx often file I/O, 0x05003xxx often strings
4. **Generic name OK**: Document as "lib_function_0x0500315e - likely string conversion"
5. **Add to future work**: "Identify library call at 0x0500315e"

### Issue: Data Structure Too Complex

**Solutions**:
1. **Partial mapping**: Document fields you understand, note "... more fields ..."
2. **Focus on used fields**: Only document what this function accesses
3. **Incremental refinement**: Update structure as more functions analyzed
4. **Reference existing**: Compare to structures from previous analyses

### Issue: Control Flow Confusing

**Solutions**:
1. **Draw flowchart**: Manually sketch branches on paper
2. **Trace one path**: Follow success case first, errors later
3. **Label everything**: Name all branch targets before analyzing bodies
4. **Simplify in C**: Pseudocode clarifies complex assembly logic

### Issue: Running Low on Time

**Priority Order** (if time-constrained):
1. **Must have**: Function signature, control flow summary, purpose
2. **Should have**: Annotated disassembly, C pseudocode
3. **Nice to have**: All template sections, extensive cross-references
4. **Can defer**: Detailed protocol integration, comprehensive testing notes

**Better**: Complete 4 functions fully than 6 functions partially

---

## Examples

### Example 1: Small Function (164 bytes)

**FUN_00006474 (ND_URLFileDescriptorOpen)**

- **Analysis time**: ~30 minutes
- **Complexity**: Low-Medium
- **Key insight**: Dual-strategy open (fdopen → file open)
- **Documentation**: 1100 lines
- **Challenges**: Format string unknown, library calls ambiguous
- **Solution**: Documented uncertainties, proposed likely interpretations

### Example 2: Medium Function (352 bytes)

**FUN_0000746c (ND_WriteBranchInstruction)**

- **Analysis time**: ~35 minutes
- **Complexity**: Low-Medium
- **Key insight**: Creates i860 entry vector with branch instruction
- **Documentation**: 800 lines
- **Challenges**: i860 instruction encoding unfamiliar
- **Solution**: Researched i860 ISA, documented branch offset calculation

### Example 3: Large Function (976 bytes)

**FUN_0000709c (ND_ProcessDMATransfer)**

- **Analysis time**: ~60 minutes
- **Complexity**: High
- **Key insight**: Mach-O segment parsing with address translation
- **Documentation**: 1400 lines
- **Challenges**: Complex descriptor iteration, multiple validation steps
- **Solution**: Created detailed structure maps, traced address translation formula

### Example 4: Dispatcher (272 bytes)

**FUN_00006e6c (ND_MessageDispatcher)**

- **Analysis time**: ~45 minutes
- **Complexity**: Medium-High
- **Key insight**: Jump table with runtime-initialized targets
- **Documentation**: 1200 lines
- **Challenges**: Jump table all zeros in binary
- **Solution**: Identified cases by control flow, documented table mystery

---

## Success Metrics

### Quantitative

- **Time**: 40 minutes average per function
- **Documentation**: 800-1400 lines per function
- **Coverage**: All template sections completed
- **Accuracy**: High confidence in control flow, medium in semantics

### Qualitative

- **Understanding**: Can explain function to another engineer
- **Usability**: Another analyst can continue work from documentation
- **Completeness**: Future implementation possible from analysis
- **Integration**: Function's role in protocol is clear

---

## Continuous Improvement

### After Each Function

**Ask**:
- What took longest? Can it be streamlined?
- What was unclear? Need better tools/docs?
- What pattern emerged? Add to this document?
- What would help next analyst? Document it!

### After Every 5 Functions

**Review**:
- Consistency across analyses
- Template adherence
- Quality vs. speed trade-offs
- Update this methodology document

---

## Appendix: Quick Reference

### File Locations

```
ndserver_re/
├── docs/
│   ├── FUNCTION_INDEX.md                    ← UPDATE ALWAYS
│   ├── FUNCTION_ANALYSIS_METHODOLOGY.md     ← THIS FILE
│   └── functions/
│       └── [ADDR]_[Name].md                 ← CREATE ONE PER FUNCTION
├── disassembly/
│   └── annotated/
│       └── [ADDR]_[Name].asm                ← CREATE ONE PER FUNCTION
├── ghidra_export/
│   ├── disassembly_full.asm                 ← READ FROM HERE
│   ├── functions.json                       ← METADATA
│   └── call_graph.json                      ← RELATIONSHIPS
└── database/
    └── analysis_order.json                  ← PRIORITY ORDER
```

### Command Snippets

```bash
# Find function in disassembly
grep -n "^  0x00006474:" ghidra_export/disassembly_full.asm

# Calculate function size
python3 -c "print(f'{0x6518 - 0x6474} bytes')"

# Extract function metadata
grep '"address": 25716' ghidra_export/functions.json  # 25716 = 0x6474 decimal

# Check for callers
grep -A5 '"callee": 25716' ghidra_export/call_graph.json
```

### Template Locations

- **Markdown Template**: `docs/FUNCTION_ANALYSIS_EXAMPLE.md`
- **Example Analysis**: `docs/functions/000036b2_ND_RegisterBoardSlot.md`
- **Example Assembly**: `disassembly/annotated/000036b2_ND_RegisterBoardSlot.asm`

---

**Document Maintenance**: Update this methodology as patterns emerge and process improves

**Last Updated**: 2025-11-08
**Next Review**: After function #10 completion
