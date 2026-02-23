# Function Index - Partial Entry for 00006b7c

**Generated**: 2025-11-08
**Function**: ND_MessageHandler_CMD434
**Address**: 0x00006b7c
**Purpose**: Merge this entry into the main FUNCTION_INDEX.md

---

## Entry for "Completed Analyses" Table

```markdown
| 0x00006b7c | ND_MessageHandler_CMD434 | 204  | Low-Medium | [Analysis](functions/00006b7c_ND_MessageHandler_CMD434.md) |
```

---

## Entry for Layer 0 Functions Table

```markdown
| 0x00006b7c | ND_MessageHandler_CMD434 | 204  | 0     | ✅ Done |
```

---

## Entry for Cross-References by Category

```markdown
**Message Handlers**:
- ND_MessageHandler_CMD434 (0x00006b7c) - Handler for command type 0x434 (1076 bytes)
  - Validates 7 message fields
  - Calls FUN_000063e8 for I/O operation
  - Part of dispatcher jump table family
```

---

## Statistics Updates

**Analyzed Functions**: Add 1 to current count
**Remaining Functions**: Subtract 1 from current count
**Total Bytes Analyzed**: Add 204 bytes

**Complexity Distribution**:
- Low-Medium: Add 1 to count

---

## Revision History Entry

```markdown
| 2025-11-08 | Claude Code | Added ND_MessageHandler_CMD434 (0x6b7c) | 1  |
```

---

## Full Function Details

**Address**: 0x00006b7c
**Name**: ND_MessageHandler_CMD434
**Size**: 204 bytes (0xCC)
**Complexity**: Low-Medium
**Call Depth**: 0 (leaf in static analysis, but called by dispatcher)
**Callers**: 0 (indirect via jump table)
**Calls**: 1 (FUN_000063e8)

**Purpose**: Message handler for Mach IPC command type 0x434. Performs extensive validation (7 checks) before delegating to I/O operation handler.

**Key Features**:
- 7-step validation chain
- Error code -0x130 on validation failure
- Calls FUN_000063e8 with 4 parameters
- Populates 48-byte response on success
- Reads from 4 global configuration values (0x7d64-0x7d70)

**Documentation Files**:
- Analysis: `docs/functions/00006b7c_ND_MessageHandler_CMD434.md`
- Annotated Assembly: `disassembly/annotated/00006b7c_ND_MessageHandler_CMD434.asm`

**Related Functions**:
- Dispatcher: ND_MessageDispatcher (0x6e6c)
- Called function: FUN_000063e8 (0x63e8)
- Sibling handlers: FUN_00006ac2 (cmd 0x42C), FUN_00006c48 (cmd 0x43C), FUN_00006d24 (cmd 0x38)

---

**Merge Instructions**:
1. Add entry to "Completed Analyses" table (sorted by address)
2. Update Layer 0 function status to "✅ Done"
3. Increment analyzed count, decrement remaining count
4. Add to "Message Handlers" cross-reference category
5. Update complexity distribution
6. Add revision history entry
7. Update total bytes analyzed
