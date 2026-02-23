# NDserver Function Analysis Index

## PostScript Operator Functions (Display PostScript Dispatch Table)

### FUN_00004f64 - PostScript mfont Operator
- **Address**: 0x00004f64
- **Size**: 276 bytes (69 instructions)
- **Type**: PostScript operator - Font management
- **Opcode**: 0x77 (119)
- **Analysis Status**: Complete (18-section deep analysis)
- **File**: `/docs/functions/00004f64_PostScriptOperator_mfont.md`

**Summary**: Creates font objects for NeXTdimension graphics processor via Display PostScript interface. Validates font name (≤1024 bytes), constructs PostScript object descriptor, allocates graphics resources, performs multi-level validation.

**Key Features**:
- Local buffer: 1068 bytes (0x42c)
- 4 external library calls
- 5 error codes (-0x133, -0x12d, -0x12c, -0xca, 0)
- Complex allocation failure validation path
- PostScript VM state preservation

**Error Codes**:
- `-0x133` (-307): Font name too long
- `-0x12d` (-301): Type mismatch validation
- `-0x12c` (-300): Parameter/global mismatch
- `-0xca` (-202): Allocation failure (cleanup handler)

---

## Related Functions in Dispatch Table

These functions have similar structure and validation logic (likely operators 0x78, 0x79, etc.):
- FUN_00005078 (Address 0x5078, Size 256 bytes) - Similar pattern, opcode 0x78
- FUN_00005178 (Address 0x5178, Size 222 bytes) - Similar pattern, opcode 0x79
- FUN_00005256 (Address 0x5256, Size 262 bytes) - Similar pattern, opcode 0x7a
- FUN_0000535c (Address 0x535c, Size 248 bytes) - Similar pattern, opcode 0x7b

---

## Analysis Methodology

All analyses follow the 18-section template:

1. Function Overview
2. Complete Annotated Disassembly
3. Instruction-by-Instruction Commentary
4. Register Usage Analysis
5. Stack Frame Analysis
6. Memory Access Patterns
7. Library Function Calls
8. PostScript Operator Classification
9. Error Codes and Return Values
10. Control Flow Analysis
11. Reverse-Engineered C Pseudocode
12. Hardware and OS Interaction
13. Comparison with Similar Functions
14. PostScript Dispatch Table Context
15. Integration with NDserver Protocol
16. Data Structure Field Mapping
17. Performance Characteristics
18. Confidence Assessment and Recommendations

---

## Notes

- All analyses use Ghidra 11.2.1 for disassembly (superior to rasm2)
- Global addresses reference PostScript VM state (0x7bc0-0x7bcc range)
- External library calls are from libsys_s.B.shlib (@ 0x05000000+)
- Functions are part of PostScript dispatch table (range 0x3cdc-0x59f8)
- Each operator constructs a PostScript object on stack, then allocates via library call

