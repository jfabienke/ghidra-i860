# Partial Function Index Entry for Merging

**Function**: FUN_000033b4
**Date Analyzed**: November 8, 2025

---

## Entry for "Completed Analyses" Table

```markdown
| 0x000033b4 | ND_MemoryTransferDispatcher | 608  | High | [Analysis](functions/000033b4_ND_MemoryTransferDispatcher.md) | DMA dispatcher with address translation |
```

---

## Entry for Cross-References by Category

**DMA/Memory Transfer**:
- ND_MemoryTransferDispatcher (0x000033b4) - DMA coordinator with host-to-i860 address translation, handles 3 command types (0x7c2, 0x7c3, 0x7c4)

---

## Entry for Revision History

```markdown
| 2025-11-08 | Claude Code | Added ND_MemoryTransferDispatcher (0x000033b4) | 1  |
```

---

## Metrics Update

**Add to Completed Count**: +1
**Total Lines of Documentation**: 1,200+ lines
**Complexity Distribution**: High (1)

---

## Function Details

- **Address**: 0x000033b4
- **Size**: 608 bytes
- **Name**: ND_MemoryTransferDispatcher
- **Purpose**: DMA memory transfer dispatcher with host-to-i860 address translation
- **Complexity**: High
- **Called By**: FUN_0000399c (1 caller)
- **Calls**: FUN_000030c2, FUN_000061f4, memcpy(), pthread_mutex_trylock(), indirect call via 0x8020
- **Message Types Handled**: 0x7c2 (source translation), 0x7c3 (destination translation), 0x7c4 (unsupported)
- **Key Features**:
  - 4-region address translation table at 0x8024
  - Batch processing of up to 32 descriptors
  - Dual-mode operation (upload vs download)
  - Atomic DMA-in-progress flag at 0x800c
  - Board lock check at 0x8054
  - Indirect transfer via function pointer at 0x8020

---

## Related Functions for Future Analysis

**High Priority**:
1. FUN_0000399c - Upstream message router that calls this function
2. Function at 0x8020 (indirect) - The actual DMA transfer engine
3. FUN_000061f4 - Fallback handler for unknown message types
4. FUN_000030c2 - Descriptor validator/preprocessor

---

*Generated for function FUN_000033b4 analysis on 2025-11-08*
