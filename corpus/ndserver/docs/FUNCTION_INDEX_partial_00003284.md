# Partial Function Index Entry - For Merging

**Function**: 0x00003284 - ND_LoadKernelSegments
**Date**: 2025-11-08
**Analyst**: Claude Code

---

## Entry for "Completed Analyses" Table

```markdown
| 0x00003284 | ND_LoadKernelSegments        | 912  | High       | [Analysis](functions/00003284_ND_LoadKernelSegments.md) | Kernel segment loader with address translation |
```

---

## Entry for Layer/Priority Table

This function is called by other functions, so it should be categorized appropriately:

**Category**: Layer 1 - Core Utility Functions (called by higher-level functions)

```markdown
| 0x00003284 | ND_LoadKernelSegments | 912  | 1     | ✅ Done |
```

---

## Entry for Cross-References by Category

```markdown
**Kernel Loading Functions**:
- ND_LoadKernelSegments (0x00003284) - Load kernel segments with address translation
```

---

## Metrics Updates

**Add to completion count**: +1 function
**Add to size total**: +912 bytes analyzed
**Complexity distribution**: +1 High complexity function

---

## Related Functions Identified (High Priority for Analysis)

From this analysis, the following functions are critical dependencies:

**CRITICAL (directly called)**:
1. FUN_00004a52 (0x00004a52) - Parameter validation and initialization
2. FUN_00003820 (0x00003820) - Connection setup / file descriptor initialization
3. FUN_00005dea (0x00005dea) - Segment descriptor parsing (likely Mach-O)
4. FUN_000043c6 (0x000043c6) - Core segment loading with address translation
5. FUN_00005da6 (0x00005da6) - Finalization and commit

**HIGH (caller)**:
6. Caller at 0x00002fd6 - Provides usage context

---

## Notes for Index Maintainer

- This is a large, complex orchestrator function (912 bytes, 11 function calls)
- Implements 9-phase kernel loading sequence
- Manages global state at 0x801C, 0x8020, and 0x8024
- Should be cross-referenced with other kernel loading functions
- Five called functions identified as high-priority analysis targets

---

## Revision History Entry

```markdown
| 2025-11-08 | Claude Code | Added ND_LoadKernelSegments (0x3284) | 1  |
```

---

**Instructions**: Merge this information into the main FUNCTION_INDEX.md file, updating:
1. Header statistics (analyzed count, remaining count)
2. Completed Analyses table
3. Appropriate layer table
4. Cross-references section
5. Complexity distribution
6. Revision history
