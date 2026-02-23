# Function Quick Reference: FUN_000056f0

## At a Glance

| Property | Value |
|----------|-------|
| **Address** | 0x000056f0 |
| **Size** | 140 bytes |
| **Type** | Callback Handler / Message Dispatcher |
| **Stack Frame** | 548 bytes |
| **Calls Made** | 2 external library functions |
| **Called By** | Unknown (entry point?) |
| **Return Value** | 0x00 (success) or -0x133 (error) |
| **Complexity** | MEDIUM |
| **Priority** | HIGH |

---

## Function Signature

```c
int FUN_000056f0(
    uint32_t arg1,              // @ 0x08(A6) - Data/ID/Handle
    uint32_t arg2,              // @ 0x0c(A6) - Configuration/Type
    void*    arg3,              // @ 0x10(A6) - Pointer/Address
    uint32_t arg4_size_or_type  // @ 0x14(A6) - Size (0-512 max)
);
```

---

## What It Does (One Sentence)

Initializes a 548-byte message buffer using global configuration values, calls two library functions in sequence to format and send the message, returning success or error code.

---

## Key Characteristics

1. **Large Stack Frame** - 548-byte allocation suggests complex message structure
2. **Dual Library Calls** - Sequential calls to format and send/route
3. **Size Validation** - Checks parameter against 0x200 (512) limit
4. **Configuration-Driven** - Loads globals 0x7c3c and 0x7c40
5. **Error Code -307** - Returned on size violation

---

## Register Usage

| Register | Usage | Status |
|----------|-------|--------|
| **D0** | Return value | Output |
| **D1** | Temporary (alignment mask) | Clobbered |
| **D2** | Size parameter | Saved/Restored |
| **D3** | Constant offset 0x24 | Saved/Restored |
| **A2** | Buffer base pointer | Saved/Restored |
| **A6** | Frame pointer | Preserved |
| **SP** | Stack | Implicit |

---

## Execution Flow

```
Entry (0x56f0)
    ↓
[Allocate 548 bytes, save registers]
    ↓
[Load parameters and globals into D2, A2, D3]
    ↓
[Size Check: D2 > 0x200?]
    ├─→ YES: Return error (-0x133)
    └─→ NO: Continue
    ↓
[Initialize frame fields]
    ↓
[Library Call #1 @ 0x0500294e: Format/Initialize]
    ├─ Parameter 1: A2 + 0x24 (buffer with offset)
    ├─ Parameter 2: arg3 (caller's third param)
    └─ Parameter 3: D2 (size)
    ↓
[Bitfield insertion, alignment calculation]
    ↓
[More frame field setup]
    ↓
[Library Call #2 @ 0x050029d2: Send/Route]
    ├─ Parameter 1: A2 (message buffer)
    ├─ Parameter 2: 0 (NULL)
    └─ Parameter 3: 0 (NULL)
    ↓
[Restore registers, unwind frame]
    ↓
Return (D0 = library result)
```

---

## Error Conditions

| Error Code | Decimal | Meaning |
|-----------|---------|---------|
| -0x133 | -307 | Size parameter > 512 bytes |
| Other | Varies | Returned from library calls (if applicable) |

---

## Stack Frame Fields (Key Offsets)

```
A6 - 0x224: Bottom of frame (buffer[0])
A6 - 0x220: Calculated aligned offset
A6 - 0x21c: Field (cleared)
A6 - 0x218: Field (cleared)
A6 - 0x214: Copy of arg1
A6 - 0x210: Max value (127)
A6 - 0x20c: Global config 1 (from 0x7c3c)
A6 - 0x208: Copy of arg2
A6 - 0x204: Global config 2 (from 0x7c40)
A6 - 0x202: Bitfield (size bits inserted)
A6 - 0x221: Status flag (0x01)
```

---

## Global Variables Referenced

| Address | Size | Purpose | Access |
|---------|------|---------|--------|
| 0x7c3c | 4 bytes | Config/State 1 | Read → Frame[-0x20c] |
| 0x7c40 | 4 bytes | Config/State 2 | Read → Frame[-0x204] |

---

## Library Functions Called

| Address | Parameters | Purpose (Inferred) | Status |
|---------|-----------|-------------------|--------|
| 0x0500294e | (buf+0x24, arg3, size) | Format/Initialize message | **Unknown** |
| 0x050029d2 | (buf, 0, 0) | Send/Route/Post message | **Unknown** |

---

## Hypothesized Role

**Callback Handler for NeXTdimension IPC/Message Protocol**

```
Event/Command Input
    ↓
[FUN_000056f0]  ← This function builds message
    ↓
[Library Formatter]  ← Populates structure
    ↓
[Library Router]  ← Sends via Mach IPC
    ↓
Remote Service/Kernel
```

---

## Analysis Status

| Aspect | Status | Evidence |
|--------|--------|----------|
| **Disassembly** | ✅ VERIFIED | Ghidra + manual verification |
| **Register Usage** | ✅ VERIFIED | m68k ABI standard |
| **Stack Frame** | ✅ VERIFIED | Explicit link instruction |
| **Purpose** | ❓ INFERRED | Pattern matching, not confirmed |
| **Library Functions** | ❓ UNKNOWN | Addresses identified, purpose unclear |
| **Callers** | ❓ UNKNOWN | No internal callers found |

---

## Next Steps

1. **Identify library functions**: Analyze 0x0500294e and 0x050029d2
2. **Find callers**: Search for references to 0x000056f0
3. **Verify purpose**: Compare with NeXTdimension protocol docs
4. **Refine understanding**: Once libraries identified

---

## Documentation Files

- **Comprehensive Analysis**: `docs/functions/0x000056f0_FUN_000056f0_COMPREHENSIVE.md` (18 sections)
- **Annotated Assembly**: `disassembly/annotated/000056f0_FUN_000056f0_CALLBACK.asm`
- **Quick Reference**: This file

---

## Key Insights

1. This is NOT a simple utility function - it's a specialized callback with 548-byte allocation
2. Purpose is composition: format message via library 1, send via library 2
3. Only documented error: size > 512 bytes
4. Likely part of message-passing or event-handling subsystem
5. Pattern suggests this may be one of multiple similar handlers

---

*Last Updated: November 8, 2025*
*Analysis Tool: Ghidra 11.2.1 + Manual m68k Reverse Engineering*

