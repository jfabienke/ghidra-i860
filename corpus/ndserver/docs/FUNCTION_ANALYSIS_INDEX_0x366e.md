# Function Analysis Index: FUN_0000366e

**Analysis Complete**: November 08, 2025
**Function Address**: 0x0000366e (13,934 decimal)
**Classification**: Callback Adapter Function
**Size**: 30 bytes
**Complexity**: LOW
**Priority**: HIGH

---

## Overview

**FUN_0000366e** is a lightweight callback adapter function that chains two external library function calls. It accepts three parameters, passes the first two to an external transformation function, then passes that result through a second external processing function before returning to the caller.

This function is part of a parameter validation and processing framework within the NeXTdimension Server ROM (NDserver).

---

## Documentation Files

### 1. Comprehensive 18-Section Analysis
**File**: `/Users/jvindahl/Development/nextdimension/ndserver_re/docs/functions/ANALYSIS_0x0000366e_COMPREHENSIVE.md`
**Size**: 21 KB
**Sections**: 18 detailed analysis sections

**Contents**:
- Function identity & metadata
- Call graph & relationships
- Complete disassembly with annotations
- Stack frame analysis
- Register usage & modification
- Data flow analysis
- Hardware access analysis
- Control flow & branching
- Function signature & semantics
- Optimization analysis
- Security & robustness assessment
- Purpose & functionality classification
- Cross-reference analysis
- Context & calling environment
- Assembly code quality
- Semantic interpretations
- Known issues & limitations
- Conclusions & recommendations
- Appendices with file references

**Best for**: Deep technical understanding, reverse engineering, optimization

---

### 2. Annotated Assembly File
**File**: `/Users/jvindahl/Development/nextdimension/ndserver_re/docs/assembly/FUN_0000366e_ANNOTATED.asm`
**Size**: 16 KB
**Format**: Detailed assembly comments

**Contents**:
- Complete function header with context
- Caller information and stack frame diagrams
- Instruction-by-instruction annotations
- Addressing mode explanations
- Stack state at each instruction
- Execution traces with example values
- Register modification details
- Function summary and patterns
- Cross-reference to external functions

**Best for**: Assembly programmers, debugging, instruction-level analysis

---

### 3. Quick Reference (Markdown)
**File**: `/Users/jvindahl/Development/nextdimension/ndserver_re/docs/CALLBACK_ANALYSIS_0x366e.md`
**Size**: 9 KB
**Format**: Structured markdown with tables

**Contents**:
- Quick summary of function purpose
- Function signature in C-like pseudocode
- Assembly code (compact)
- Caller context and calling conventions
- Stack layout diagrams
- Parameter semantics
- Data flow visualization
- Control flow diagram
- Register impact table
- Hardware access summary
- Performance characteristics
- Security analysis
- Classification & purpose
- Recommendations
- File references

**Best for**: Quick lookups, presentations, understanding purpose

---

### 4. Visual Summary (Text-based)
**File**: `/Users/jvindahl/Development/nextdimension/ndserver_re/docs/CALLBACK_0x366e_VISUAL_SUMMARY.txt`
**Size**: 29 KB
**Format**: ASCII diagrams and formatted tables

**Contents**:
- Function flow diagram (ASCII art)
- Stack frame visual representation
- Instruction breakdown with timing
- Register usage table
- Parameter analysis table
- External function call details
- Call chain visualization
- Performance analysis with cycle estimates
- Security vulnerability assessment
- Classification evidence
- Control flow analysis
- Data flow tracking
- Cross-reference summary
- Comprehensive summary tables

**Best for**: Visual learners, understanding data flow, presentations, printing

---

## Quick Navigation

### By Use Case

**I want to...**

- **Understand what this function does**
  → Read: Quick Reference (`CALLBACK_ANALYSIS_0x366e.md`)

- **Learn the assembly code**
  → Read: Annotated Assembly (`FUN_0000366e_ANNOTATED.asm`)

- **Analyze data flow and stack usage**
  → Read: Visual Summary (`CALLBACK_0x366e_VISUAL_SUMMARY.txt`)

- **Deep reverse engineering**
  → Read: Comprehensive Analysis (`ANALYSIS_0x0000366e_COMPREHENSIVE.md`)

- **Optimize or modify this function**
  → Read: Sections 10 & 11 of Comprehensive Analysis

- **Understand security implications**
  → Read: Section 11 of Comprehensive Analysis OR Visual Summary Security section

- **Debug issues involving this function**
  → Read: Annotated Assembly + Calling Context section of Comprehensive

### By Document Format

- **Markdown** (quick reference style): `CALLBACK_ANALYSIS_0x366e.md`
- **Detailed Markdown** (18 sections): `ANALYSIS_0x0000366e_COMPREHENSIVE.md`
- **Assembly** (commented code): `FUN_0000366e_ANNOTATED.asm`
- **Text/ASCII** (diagrams): `CALLBACK_0x366e_VISUAL_SUMMARY.txt`

### By Topic

| Topic | Document | Section |
|-------|----------|---------|
| Function signature | Quick Ref | "Function Signature" |
| Assembly code | Both Markdown docs | Disassembly sections |
| Stack layout | Visual Summary | "STACK FRAME DIAGRAM" |
| Registers used | Visual Summary | "REGISTER USAGE TABLE" |
| Data flow | Visual Summary | "DATA FLOW ANALYSIS" |
| Performance | Comprehensive | Section 10 |
| Security | Comprehensive | Section 11 |
| Purpose | Comprehensive | Section 12 |
| Caller context | Comprehensive | Section 14 |
| External functions | All docs | Multiple sections |

---

## Key Findings Summary

### Function Characteristics
- **Type**: Callback Adapter / Utility Wrapper
- **Size**: 30 bytes (8 instructions)
- **Complexity**: LOW (no branches, no loops)
- **Pattern**: Two-stage external function call chain
- **Register impact**: Only A6, SP, D0

### What It Does
1. Accepts 3 parameters from caller
2. Pushes 2 parameters (param2, param3) to stack
3. Calls external function 1 (libfunc_1 @ 0x0500315e)
4. Receives 32-bit result in D0
5. Pushes result to stack
6. Calls external function 2 (libfunc_2 @ 0x050032ba)
7. Returns final result in D0

### Caller & Usage
- **Called by**: FUN_000060d8 (single caller) at offset 0x6132
- **Context**: Parameter validation/processing framework
- **Call frequency**: Once per validation success
- **Result usage**: Stored to output structure at offset +0x1c

### External Dependencies
- **libfunc_1** (0x0500315e): Used by 15+ functions, purpose unknown
- **libfunc_2** (0x050032ba): Used by 11+ functions, purpose unknown
- Both are core utility functions in external library

### Security Assessment
- **Input validation**: NONE (relies on caller validation)
- **Stack safety**: SAFE (balanced LINK/UNLK pair)
- **Overall risk**: LOW (no obvious vulnerabilities)
- **Main risk**: Depends on external function behavior

### Performance
- **Base instruction time**: ~35 cycles (excluding external calls)
- **Bottleneck**: External function calls (unknown cost)
- **Optimization opportunity**: Inlining, register usage

---

## File Locations

All analysis files are located in:
`/Users/jvindahl/Development/nextdimension/ndserver_re/docs/`

### Directory Structure
```
docs/
├── functions/
│   └── ANALYSIS_0x0000366e_COMPREHENSIVE.md    (21 KB - main analysis)
├── assembly/
│   └── FUN_0000366e_ANNOTATED.asm              (16 KB - annotated code)
├── CALLBACK_ANALYSIS_0x366e.md                 (9 KB - quick reference)
├── CALLBACK_0x366e_VISUAL_SUMMARY.txt          (29 KB - visual diagrams)
└── FUNCTION_ANALYSIS_INDEX_0x366e.md           (this file - navigation)
```

### Source Data Files
- **Disassembly**: `/Users/jvindahl/Development/nextdimension/ndserver_re/ghidra_export/disassembly_full.asm`
- **Functions**: `/Users/jvindahl/Development/nextdimension/ndserver_re/ghidra_export/functions.json`
- **Call Graph**: `/Users/jvindahl/Development/nextdimension/ndserver_re/ghidra_export/call_graph.json`

---

## Analysis Metadata

- **Analysis Date**: November 08, 2025
- **Analyzer**: Claude Code (Haiku 4.5 model)
- **Binary**: NDserver (Mach-O m68k executable)
- **Tool Chain**: Ghidra 11.2.1 for disassembly
- **Total Documentation**: ~75 KB across 4 detailed files
- **Coverage**: 100% of 30-byte function (all 8 instructions analyzed)

---

## Recommendations

### For Understanding the Function
1. Start with **Quick Reference** for 5-minute overview
2. Review **Visual Summary** for data flow understanding
3. Read **Annotated Assembly** for instruction details
4. Consult **Comprehensive Analysis** for deep research

### For Development
1. Document the purpose of external functions (0x0500315e, 0x050032ba)
2. Add symbolic names when function behavior is identified
3. Consider parameter validation or document assumptions
4. Add more detailed comments in disassembly

### For Optimization
1. Profile to confirm external functions are bottleneck
2. Consider inlining if external functions are available
3. Evaluate using registers instead of stack for parameters
4. Cache results if parameters repeat frequently

### For Testing
1. Test with boundary value parameters
2. Verify error handling in external functions
3. Check result storage in caller (FUN_000060d8)
4. Test with different input structures

---

## References

### Related Functions
- **FUN_000060d8** (Caller): Structure validation framework
- **FUN_0000368c**: Similar callback pattern (4 parameters)
- **libfunc_1** (0x0500315e): Primary transformation (15+ users)
- **libfunc_2** (0x050032ba): Final processor (11+ users)

### Similar Patterns
- Multiple callback functions in 0x06000000 range
- Dispatch table entries with callback semantics
- Parameter validation pipeline functions

### Documentation Standards
- 18-section analysis template used
- Comprehensive coverage of all aspects
- Cross-referenced sections for easy navigation
- Multiple formats for different use cases

---

## Document Versions

| Document | Version | Size | Date | Status |
|----------|---------|------|------|--------|
| Comprehensive Analysis | 1.0 | 21 KB | 2025-11-08 | Complete |
| Annotated Assembly | 1.0 | 16 KB | 2025-11-08 | Complete |
| Quick Reference | 1.0 | 9 KB | 2025-11-08 | Complete |
| Visual Summary | 1.0 | 29 KB | 2025-11-08 | Complete |
| Index (this file) | 1.0 | TBD | 2025-11-08 | Complete |

---

## Contact & Support

For questions or clarifications about this analysis:
1. Review the relevant documentation file
2. Check the appropriate section listed in "Quick Navigation"
3. Refer to source data files for original disassembly
4. See appendices for file references

---

**Analysis Complete**

All 18-section analysis documentation for function FUN_0000366e has been generated and cross-indexed. Documentation is production-ready for team sharing and reference.

---

*Generated by Claude Code - Anthropic's Official CLI for Claude*
*Analysis Type: Standard 18-Section Deep Dive*
*Classification: Callback Function (Priority HIGH)*
