# Function Analysis: ND_URLFileDescriptorOpen

**Address**: `0x00006474`
**Size**: 164 bytes (82 words, ~41 instructions)
**Complexity**: Low-Medium
**Purpose**: Open file descriptor from URL/path string with port parsing
**Status**: ✅ Analyzed (2025-11-08)

---

## Executive Summary

`ND_URLFileDescriptorOpen` is a **URL/file path parser and file descriptor opener** that extracts a port number from a URL/path string, converts it to a file descriptor, and opens it for I/O operations. The function appears to handle network socket or device file operations, possibly for communicating with the NeXTdimension board via a pseudo-device or network interface.

**Key Characteristics**:
- Parses URL/path with port number extraction
- Converts port string to integer
- Opens file descriptor via library calls
- Error handling with printf logging
- Returns file descriptor on success, 0 on error
- Small stack frame (4 bytes for local variable)

**Likely Role**: This function implements **device file or socket opening** for NeXTdimension communication, possibly opening `/dev/nd0` or similar device with a port parameter, or establishing a network connection to the graphics board.

---

## Function Signature

### Reverse-Engineered C Prototype

```c
int ND_URLFileDescriptorOpen(
    const char*  url_or_path,     // D3: URL or file path string
    const char*  mode_or_flags    // D2: Mode string or flags
);
```

### Parameters

| Register | Name          | Type         | Description                              |
|----------|---------------|--------------|------------------------------------------|
| D3       | url_or_path   | const char*  | URL or file path (e.g., "device:port")   |
| D2       | mode_or_flags | const char*  | Mode string or flags                     |

### Return Value

- **D0 > 0**: File descriptor (success)
- **D0 = 0**: Error (failure)

### Calling Convention

- **m68k System V ABI**: Link frame, parameters in data registers
- **Preserved registers**: D2, D3
- **Small stack allocation**: 4 bytes for local variable (port number)

---

## Data Structures

### Local Variables

```c
// Stack frame layout
struct stack_frame {
    int32_t  port_number;        // A6-0x4: Extracted port from URL
};
```

### String Addresses Referenced

| Address    | Purpose                                      |
|------------|----------------------------------------------|
| `0x79f6`   | Format string for FUN_00004a52 (URL parsing) |
| `0x79fb`   | Error format string #1 (atoi/strtol error)   |
| `0x7a1b`   | Error format string #2 (open error)          |

---

## Complete Annotated Disassembly

```m68k
; ====================================================================================
; ANNOTATED DISASSEMBLY: ND_URLFileDescriptorOpen
; ====================================================================================
; Address: 0x00006474
; Size: 164 bytes
; Purpose: Parse URL/path and open file descriptor with port parameter
; ====================================================================================

; FUNCTION: int ND_URLFileDescriptorOpen(const char* url_or_path, const char* mode_or_flags)
;
; Parses a URL or file path containing a port specification, extracts the port
; number, and opens a file descriptor using that port. Handles errors with
; logging and cleanup.
;
; PARAMETERS:
;   url_or_path (D3):   URL or file path string (e.g., "/dev/nd0:1234")
;   mode_or_flags (D2): Mode string or flags for opening
;
; RETURNS:
;   D0: File descriptor (>0) on success, 0 on error
;
; STACK FRAME: 4 bytes
;   -0x4: port_number (extracted from URL)
;
; CALLS:
;   FUN_00004a52 - URL/path parser (extracts port)
;   0x0500315e - atoi/strtol (string to integer conversion)
;   0x05002c54 - fdopen or similar (file descriptor opener)
;   FUN_00005256 - File open operation
;   0x050028c4 - printf (error logging)
;   0x05002c5a - fclose or cleanup
;
; ====================================================================================

FUN_00006474:
    ; --- PROLOGUE ---
    link.w      A6, #-0x4                 ; Create 4-byte stack frame
    move.l      D3, -(SP)                 ; Save D3 (callee-save)
    move.l      D2, -(SP)                 ; Save D2 (callee-save)

    ; --- LOAD PARAMETERS INTO D REGISTERS ---
    move.l      (0x8,A6), D3              ; D3 = url_or_path (from stack)
    move.l      (0xc,A6), D2              ; D2 = mode_or_flags (from stack)

    ; --- PARSE URL/PATH TO EXTRACT PORT ---
    pea         (-0x4,A6)                 ; Push &port_number (output)
    pea         (0x79f6).l                ; Push format_string (URL parse pattern)
    move.l      D2, -(SP)                 ; Push mode_or_flags
    move.l      D3, -(SP)                 ; Push url_or_path
    bsr.l       0x00004a52                ; result = FUN_00004a52(url, mode, fmt, &port)
                                           ; Likely: sscanf(url, fmt, &port)
    addq.w      #0x8, SP                  ; Clean up 2 args (8 bytes)
    addq.w      #0x8, SP                  ; Clean up 2 more args (8 bytes)

    ; --- CHECK PARSE RESULT ---
    tst.l       D0                        ; if (parse_result == 0)
    beq.b       .error_return_zero        ;   goto error (parse failed)

    ; --- CONVERT PORT STRING TO INTEGER ---
    pea         (-0x4,A6)                 ; Push &port_number
    bsr.l       0x0500315e                ; D0 = atoi(&port_number)
                                           ; Or possibly: D0 = strtol(&port_number, NULL, 10)
    move.l      D0, -(SP)                 ; Push converted_port
    bsr.l       0x05002c54                ; result = fdopen_or_socket(converted_port)
                                           ; Opens FD using port number
    addq.w      #0x8, SP                  ; Clean up 2 args

    ; --- CHECK FD OPEN RESULT ---
    tst.l       D0                        ; if (fd_result == 0)
    beq.b       .retry_with_file_open     ;   goto retry (fdopen failed, try file open)

    ; Fast path failed - log error and bail
    move.l      D0, -(SP)                 ; Push error_code
    pea         (0x79fb).l                ; Push error_format_1
    bsr.l       0x050028c4                ; printf(error_format_1, error_code)
    bra.b       .error_return_zero        ; goto error_exit

    ; --- RETRY WITH FILE OPEN OPERATION ---
.retry_with_file_open:
    move.l      (-0x4,A6), -(SP)          ; Push port_number (from local var)
    pea         (0x79f6).l                ; Push format_string
    move.l      D2, -(SP)                 ; Push mode_or_flags
    move.l      D3, -(SP)                 ; Push url_or_path
    bsr.l       0x00005256                ; result = FUN_00005256(url, mode, fmt, port)
                                           ; Alternative file open method
    addq.w      #0x8, SP                  ; Clean up 2 args
    addq.w      #0x8, SP                  ; Clean up 2 more args

    ; --- CHECK FILE OPEN RESULT ---
    tst.l       D0                        ; if (open_result != 0)
    bne.b       .file_open_failed         ;   goto error (open failed)

    ; Success path - return port number as FD
    move.l      (-0x4,A6), D0             ; D0 = port_number (return value)
    bra.b       .epilogue                 ; goto epilogue

    ; --- FILE OPEN FAILED - LOG AND CLEANUP ---
.file_open_failed:
    move.l      D0, -(SP)                 ; Push error_code
    pea         (0x7a1b).l                ; Push error_format_2
    bsr.l       0x050028c4                ; printf(error_format_2, error_code)

    ; Cleanup: close the FD we attempted to open
    move.l      (-0x4,A6), -(SP)          ; Push port_number
    bsr.l       0x0500315e                ; D0 = atoi(&port_number) [again?]
    move.l      D0, -(SP)                 ; Push fd
    bsr.l       0x05002c5a                ; fclose_or_cleanup(fd)

    ; Fall through to error return

    ; --- ERROR RETURN PATH ---
.error_return_zero:
    clr.l       D0                        ; D0 = 0 (FAILURE)

    ; --- EPILOGUE ---
.epilogue:
    move.l      (-0xc,A6), D2             ; Restore D2
    move.l      (-0x8,A6), D3             ; Restore D3
    unlk        A6                        ; Destroy stack frame
    rts                                   ; Return to caller

; ====================================================================================
; END OF FUNCTION: ND_URLFileDescriptorOpen
; ====================================================================================
```

---

## Stack Frame Layout

```
High Address
┌─────────────────────────────────────┐
│  Return Address (from caller)       │  A6+0x4
├─────────────────────────────────────┤
│  Old Frame Pointer (saved A6)       │  A6+0x0  ← Current A6
├─────────────────────────────────────┤
│  Saved D2                            │  A6-0x8
│  Saved D3                            │  A6-0xC
├─────────────────────────────────────┤
│  port_number (int32_t)               │  A6-0x4  (local variable)
└─────────────────────────────────────┘
Low Address

Parameters (above frame):
  A6+0x8:  const char* url_or_path
  A6+0xC:  const char* mode_or_flags

Note: Parameters are loaded into D3 and D2 at function entry
```

---

## Hardware Access

**None**: This function does not directly access hardware registers. All I/O is via library calls.

---

## OS Functions and Library Calls

### Identified Library Functions

| Address      | Likely Identity          | Evidence                                    |
|--------------|--------------------------|---------------------------------------------|
| `0x0500315e` | `atoi()` or `strtol()`   | String to integer conversion (port number)  |
| `0x05002c54` | `fdopen()` / `socket()`  | Opens FD from integer descriptor            |
| `0x05002c5a` | `fclose()` / `close()`   | Closes file descriptor on error             |
| `0x050028c4` | `printf()`               | Error message logging                       |

### Internal Function Calls

| Function         | Address    | Purpose                                    |
|------------------|------------|--------------------------------------------|
| `FUN_00004a52`   | `0x4a52`   | URL/path parser (sscanf-like)              |
| `FUN_00005256`   | `0x5256`   | Alternative file open method               |

**Notes on FUN_00004a52**:
```c
// Appears to parse URL with pattern matching
int FUN_00004a52(const char* url, const char* mode,
                 const char* format, int* output);
// Example: FUN_00004a52("/dev/nd0:1234", "rw", "%*[^:]:%d", &port)
// Extracts "1234" into port variable
```

**Notes on FUN_00005256**:
```c
// Alternative open method when fdopen fails
int FUN_00005256(const char* url, const char* mode,
                 const char* format, int port);
// Likely: Constructs device path and calls open()
```

---

## Reverse-Engineered C Pseudocode

```c
/**
 * ND_URLFileDescriptorOpen - Open file descriptor from URL/path with port
 *
 * @param url_or_path  URL or file path string (e.g., "/dev/nd0:1234")
 * @param mode_or_flags Mode string or flags
 * @return File descriptor on success, 0 on error
 */
int ND_URLFileDescriptorOpen(const char* url_or_path, const char* mode_or_flags)
{
    int port_number;
    int result;
    int fd;

    // Parse URL to extract port number
    result = FUN_00004a52(url_or_path, mode_or_flags,
                          format_string_0x79f6, &port_number);
    if (result == 0) {
        // Parse failed
        return 0;
    }

    // Convert port string to integer and open FD
    fd = fdopen_or_socket(atoi(&port_number));
    if (fd != 0) {
        // fdopen succeeded but returned error?
        printf(error_format_0x79fb, fd);
        return 0;
    }

    // Try alternative file open method
    result = FUN_00005256(url_or_path, mode_or_flags,
                          format_string_0x79f6, port_number);
    if (result != 0) {
        // File open failed - cleanup and error
        printf(error_format_0x7a1b, result);

        // Close any partially opened resources
        fclose_or_cleanup(atoi(&port_number));
        return 0;
    }

    // Success - return port number as FD
    return port_number;
}
```

---

## Call Graph

### Called By

```
(Unknown callers - Layer 0 function with 1 incoming call)
    └─> FUN_00006474 (THIS FUNCTION)
```

### Calls To

```
FUN_00006474 (THIS FUNCTION)
    ├─> FUN_00004a52  (URL/path parser)
    ├─> 0x0500315e    (atoi/strtol - library)
    ├─> 0x05002c54    (fdopen/socket - library)
    ├─> FUN_00005256  (alternative file open)
    ├─> 0x050028c4    (printf - library)
    └─> 0x05002c5a    (fclose/close - library)
```

---

## Purpose Classification

### Primary Function
**URL/Path Parsing and File Descriptor Opening** - Device or socket initialization

### Secondary Functions
1. **Port number extraction** from URL string
2. **String to integer conversion** (port parsing)
3. **Error handling and logging** via printf
4. **Resource cleanup** on failure

### Likely Use Case

This function appears to handle **device file or network socket opening** for NeXTdimension communication. Possible scenarios:

**Scenario 1: Device File with Port Parameter**
```
URL: "/dev/nd0:2"
Extracts port=2, opens /dev/nd0 with port parameter
Used for: Selecting NeXTdimension board in multi-board systems
```

**Scenario 2: Network Socket**
```
URL: "localhost:5000"
Extracts port=5000, opens TCP socket
Used for: Remote NeXTdimension emulation or debugging
```

**Scenario 3: Mach Port**
```
URL: "mach_port:1234"
Extracts port=1234, opens Mach IPC port
Used for: Inter-process communication with NeXTdimension server
```

The dual open strategy (fdopen → FUN_00005256 fallback) suggests handling both character devices and network sockets.

---

## Error Handling

### Error Codes

| Code    | Source                 | Meaning                                      |
|---------|------------------------|----------------------------------------------|
| `0`     | Return value           | Generic failure                              |
| Non-zero| printf arguments       | Specific error codes from fdopen/file open   |

### Error Paths

1. **Parse failure** (FUN_00004a52 returns 0)
   - Returns 0 immediately
   - No cleanup needed

2. **fdopen failure** (returns non-zero)
   - Logs error via printf
   - Returns 0

3. **File open failure** (FUN_00005256 returns non-zero)
   - Logs error via printf
   - Cleans up with fclose
   - Returns 0

---

## Protocol Integration

### URL Format

Based on the parsing pattern, the URL likely follows one of these formats:

```
Format 1 (Device with port):
  /dev/nd0:2
  /dev/nd0:1234

Format 2 (Network socket):
  hostname:port
  localhost:5000

Format 3 (Mach port):
  mach:port_number
```

The format string at `0x79f6` would specify the parsing pattern (e.g., `"%*[^:]:%d"` to extract port after colon).

### Integration with NeXTdimension Protocol

This function likely serves as the **initialization step** for establishing communication with the NeXTdimension board:

1. **Driver opens device**: `fd = ND_URLFileDescriptorOpen("/dev/nd0:2", "rw")`
2. **Port 2 selected**: Targets specific NeXTdimension board (slot 2)
3. **FD returned**: Used for subsequent read/write operations
4. **Communication established**: Ready for DMA, mailbox, or command operations

---

## m68k Architecture Details

### Register Usage

| Register | Purpose                            | Preserved? |
|----------|------------------------------------|------------|
| D3       | url_or_path parameter              | Yes        |
| D2       | mode_or_flags parameter            | Yes        |
| D0       | Return value / scratch             | No         |
| A6       | Frame pointer                      | Yes        |

### Optimization Notes

1. **Parameters in data registers** - Efficient for small pointer values
2. **Small stack frame** - Only 4 bytes, minimal overhead
3. **Inline error handling** - No separate error function, reduces call depth
4. **Dual open strategy** - Fallback increases reliability

---

## Analysis Insights

### Key Discoveries

1. **URL Parsing Pattern**
   - Format string at `0x79f6` defines parsing rule
   - Extracts port number into local variable
   - Suggests colon-separated format (device:port)

2. **Dual Open Strategy**
   - First try: fdopen/socket (fast path for existing FD or socket)
   - Second try: FUN_00005256 (file system open for device files)
   - Provides flexibility for different communication methods

3. **Port Number as FD**
   - Success case returns `port_number` directly
   - Suggests port is converted to FD by FUN_00005256
   - Indicates Mach port or custom device multiplexing

4. **Error Logging**
   - Two different error format strings (0x79fb, 0x7a1b)
   - Distinguishes between fdopen and file open failures
   - Helps debugging communication issues

### Architectural Patterns

- **Parse-Transform-Open** - Classic file handling pattern
- **Fallback strategy** - Resilience against different system configurations
- **Resource cleanup** - Proper error handling with fclose on failure

---

## Unanswered Questions

1. **Format String Content**
   - What is the exact format at `0x79f6`?
   - Does it parse hostname:port or device:slot?
   - Are there other fields beyond port?

2. **FUN_00004a52 Details**
   - Is this sscanf, or custom URL parser?
   - What other patterns can it parse?
   - Does it support URL schemes (nd://, mach://, etc.)?

3. **FUN_00005256 Implementation**
   - How does it construct the final device path?
   - Does it call open(), or Mach IPC?
   - What flags does it use?

4. **Return Value Semantics**
   - Why return port_number instead of actual FD?
   - Is port_number == FD in this context?
   - Or is this a handle for later FD lookup?

5. **Mode/Flags Parameter**
   - What values does mode_or_flags accept?
   - "r", "w", "rw" string? Or numeric flags?
   - Used by both parsing and opening?

6. **Multi-Board Support**
   - Does port selection support multiple NeXTdimension boards?
   - Can you open port=2 and port=4 simultaneously?
   - How are FDs multiplexed?

---

## Related Functions

### Directly Called

- **FUN_00004a52** (`0x4a52`) - URL/path parser ← **HIGH PRIORITY**
- **FUN_00005256** (`0x5256`) - Alternative file open ← **HIGH PRIORITY**

### Library Functions

- `atoi/strtol` (`0x0500315e`)
- `fdopen/socket` (`0x05002c54`)
- `fclose/close` (`0x05002c5a`)
- `printf` (`0x050028c4`)

### Related By Pattern

- Other functions using format strings at 0x7xxx
- Other functions calling FUN_00004a52 (URL parsing)
- Functions that use returned FD for I/O

---

## Testing Notes

### Test Cases for Validation

1. **Valid device path**: `/dev/nd0:2` → Should return FD
2. **Valid network**: `localhost:5000` → Should return socket FD
3. **Invalid format**: `no_colon` → Should return 0
4. **Invalid port**: `/dev/nd0:abc` → Should return 0 (atoi fails)
5. **Missing device**: `/dev/nonexistent:1` → Should return 0, log error
6. **Null parameters**: NULL url or mode → Should crash or return 0

### Expected Behavior

- **Valid URL**: Extract port, open FD, return port_number
- **Invalid URL**: Return 0, no error logging (parse fails early)
- **Open failure**: Return 0, log error via printf
- **Resource leak**: Should close FD on failure (cleanup path)

### Debugging Tips

1. **Set breakpoint at 0x6474** - Entry point
2. **Watch D3** - Capture URL strings used
3. **Watch A6-0x4** - See extracted port numbers
4. **Trace FUN_00004a52** - Understand parsing logic
5. **Check return value** - Verify FD vs 0
6. **Read error logs** - Check printf output for failures

---

## Function Size and Complexity Metrics

| Metric                  | Value   |
|-------------------------|---------|
| Total size              | 164 bytes |
| Number of instructions  | ~41     |
| Cyclomatic complexity   | ~5      |
| Number of branches      | 4       |
| Call depth              | 2       |
| Stack usage             | 4 bytes |
| Library calls           | 4       |
| Internal calls          | 2       |
| Error paths             | 3       |

**Complexity Rating**: **Low-Medium**
Small function with straightforward control flow, but has multiple call paths and error handling.

---

**Analysis Date**: 2025-11-08
**Analyst**: Claude Code
**Confidence**: High (control flow), Medium (semantic interpretation)
**Review Status**: Initial analysis complete, awaiting format string analysis

---

**Next Steps**:
1. Analyze **FUN_00004a52** to understand URL parsing format
2. Analyze **FUN_00005256** to understand file opening mechanism
3. Examine format strings at 0x79f6, 0x79fb, 0x7a1b
4. Find callers to understand URL sources
5. Test with actual NeXTdimension hardware/emulator
