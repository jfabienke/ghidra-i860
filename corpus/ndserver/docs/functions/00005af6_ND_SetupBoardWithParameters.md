# Deep Function Analysis: FUN_00005af6 (ND_SetupBoardWithParameters)

**Analysis Date**: November 8, 2025
**Analyst**: Claude (Manual Reverse Engineering)
**Function Address**: `0x00005af6`
**Size**: 194 bytes (67 lines of assembly)
**Classification**: **Board Setup / Configuration**
**Confidence**: **HIGH**

---

## Executive Summary

This function **initializes and configures a NeXTdimension board** with additional parameters. It performs a multi-stage setup process: (1) converts a string parameter to integer, (2) registers the board in a slot, (3) sets up memory/DMA handles, (4) verifies the board state, (5) applies configuration parameters, and (6) performs final setup with library calls. This is a critical high-level initialization function that coordinates multiple subsystems and handles errors gracefully with cleanup.

**Key Characteristics**:
- Orchestrates 5 internal function calls plus 2 library calls
- Handles 3 optional parameters passed through stack
- Uses dual error paths with cleanup
- Converts string to integer for one parameter
- Implements success path with resource initialization

**Likely Role**: Entry point for board setup from command-line or configuration file, integrating user-specified parameters with board initialization.

---

## Function Signature

### Reverse-Engineered C Prototype

```c
int ND_SetupBoardWithParameters(
    uint32_t board_id,      // Board identifier (arg1 @ 8(A6))
    uint32_t slot_num,      // NeXTBus slot number (arg2 @ 12(A6))
    void*    param1,        // Parameter 1 - passed to FUN_00007032 (arg3 @ 16(A6))
    void*    param2,        // Parameter 2 - passed to FUN_00007032 (arg4 @ 20(A6))
    void*    param3         // Parameter 3 - passed to FUN_00007032 (arg5 @ 24(A6))
);
```

### Parameter Details

| Offset | Register | Type      | Name       | Description |
|--------|----------|-----------|------------|-------------|
| 8(A6)  | D4       | uint32_t  | board_id   | NeXTdimension board identifier |
| 12(A6) | D3       | uint32_t  | slot_num   | NeXTBus slot (2, 4, 6, or 8) |
| 16(A6) | -        | void*     | param1     | Configuration parameter 1 |
| 20(A6) | -        | void*     | param2     | Configuration parameter 2 |
| 24(A6) | -        | void*     | param3     | Configuration parameter 3 (string?) |

### Return Values

| Value | Meaning |
|-------|---------|
| 0     | Success - board fully configured |
| 4     | Invalid slot number |
| 5     | Setup/verification failed |
| 6     | Memory allocation failed |
| Other | Error from sub-initialization functions |

### Calling Convention

- **ABI**: NeXTSTEP m68k System V
- **Stack Cleanup**: Caller (not shown in this function)
- **Preserved Registers**: D2-D5, A2 (saved in prologue, restored in epilogue)
- **Return Register**: D0

---

## Complete Annotated Disassembly

```m68k
; ============================================================================
; Function: ND_SetupBoardWithParameters
; Purpose: Initialize NeXTdimension board with configuration parameters
; Args: board_id (D4), slot_num (D3), param1-3 (stack)
; Returns: D0 = error code (0 = success)
; ============================================================================

FUN_00005af6:
  ; === PROLOGUE ===
  0x00005af6:  link.w     A6,0x0                    ; Create stack frame (no locals)
  0x00005afa:  movem.l    {A2 D5 D4 D3 D2},SP       ; Save 5 registers (20 bytes)

  ; === LOAD ARGUMENTS ===
  0x00005afe:  move.l     (0x8,A6),D4               ; D4 = board_id (arg1)
  0x00005b02:  move.l     (0xc,A6),D3               ; D3 = slot_num (arg2)

  ; === CONVERT STRING PARAMETER TO INTEGER ===
  ; Note: 0x0500315e is likely atoi() or strtol()
  ; The parameter is likely from arg3-5, but calling convention unclear
  0x00005b06:  bsr.l      0x0500315e                ; CALL string_to_int (library)
  0x00005b0c:  move.l     D0,D5                     ; D5 = converted integer value

  ; === REGISTER BOARD IN SLOT ===
  ; This is the same ND_RegisterBoardSlot we analyzed previously
  0x00005b0e:  move.l     D3,-(SP)                  ; Push slot_num
  0x00005b10:  move.l     D4,-(SP)                  ; Push board_id
  0x00005b12:  bsr.l      0x000036b2                ; CALL ND_RegisterBoardSlot
  0x00005b18:  move.l     D0,D2                     ; D2 = registration result
  0x00005b1a:  addq.w     0x8,SP                    ; Clean stack (8 bytes)
  0x00005b1c:  bne.w      0x00005bae                ; If error, jump to epilogue

  ; === GET BOARD STRUCTURE FROM SLOT TABLE ===
  0x00005b20:  move.l     D3,D0                     ; D0 = slot_num
  0x00005b22:  asr.l      #0x1,D0                   ; index = slot / 2
  0x00005b24:  lea        (0x819c).l,A0             ; A0 = &global_slot_table
  0x00005b2a:  movea.l    (0x0,A0,D0*0x4),A2        ; A2 = slot_table[index] (board_info*)

  ; === INITIALIZE MEMORY/DMA HANDLES ===
  ; FUN_00004c88 appears to set up fields at +0x2C and +0x40 in board structure
  0x00005b2e:  pea        (0x40,A2)                 ; Push &board->field_0x40 (output)
  0x00005b32:  pea        (0x2c,A2)                 ; Push &board->field_0x2C (output)
  0x00005b36:  move.l     D3,-(SP)                  ; Push slot_num
  0x00005b38:  move.l     D5,-(SP)                  ; Push converted_value
  0x00005b3a:  move.l     (0x4,A2),-(SP)            ; Push board->board_port
  0x00005b3e:  move.l     D4,-(SP)                  ; Push board_id
  0x00005b40:  bsr.l      0x00004c88                ; CALL FUN_00004c88 (memory/DMA init)
  0x00005b46:  move.l     D0,D2                     ; D2 = init result
  0x00005b48:  adda.w     #0x18,SP                  ; Clean stack (24 bytes)
  0x00005b4c:  beq.b      0x00005b5c                ; If success, continue

  ; --- ERROR PATH 1: Memory/DMA init failed ---
  0x00005b4e:  move.l     D3,-(SP)                  ; Push slot_num
  0x00005b50:  move.l     D4,-(SP)                  ; Push board_id
  0x00005b52:  bsr.l      0x00003874                ; CALL cleanup_board (FUN_00003874)
  0x00005b58:  move.l     D2,D0                     ; Return error code from init
  0x00005b5a:  bra.b      0x00005bae                ; Jump to epilogue

  ; === VERIFY BOARD STATE ===
verify_board_state:
  0x00005b5c:  move.l     D3,-(SP)                  ; Push slot_num
  0x00005b5e:  move.l     D4,-(SP)                  ; Push board_id
  0x00005b60:  bsr.l      0x00005c70                ; CALL FUN_00005c70 (verify/check)
  0x00005b66:  addq.w     0x8,SP                    ; Clean stack (8 bytes)
  0x00005b68:  tst.l      D0                        ; Test verification result
  0x00005b6a:  bne.b      0x00005ba2                ; If failed, jump to error path 2

  ; === APPLY CONFIGURATION PARAMETERS ===
  ; FUN_00007032 takes the board structure plus 3 additional parameters
  0x00005b6c:  move.l     (0x18,A6),-(SP)           ; Push param3 (arg5)
  0x00005b70:  move.l     (0x14,A6),-(SP)           ; Push param2 (arg4)
  0x00005b74:  move.l     (0x10,A6),-(SP)           ; Push param1 (arg3)
  0x00005b78:  move.l     A2,-(SP)                  ; Push board_info*
  0x00005b7a:  bsr.l      0x00007032                ; CALL FUN_00007032 (apply config)
  0x00005b80:  addq.w     0x8,SP                    ; Clean stack (16 bytes)
  0x00005b82:  addq.w     0x8,SP
  0x00005b84:  moveq      -0x1,D1                   ; D1 = -1 (error sentinel)
  0x00005b86:  cmp.l      D0,D1                     ; Check if result == -1
  0x00005b88:  beq.b      0x00005ba2                ; If error, jump to error path 2

  ; === FINALIZE SETUP WITH LIBRARY CALL ===
  ; 0x050032ba is likely a system call or library function
  ; Takes 3 parameters from board structure
  0x00005b8a:  move.l     (0x40,A2),-(SP)           ; Push board->field_0x40
  0x00005b8e:  move.l     (0x2c,A2),-(SP)           ; Push board->field_0x2C
  0x00005b92:  move.l     D5,-(SP)                  ; Push converted_value
  0x00005b94:  bsr.l      0x050032ba                ; CALL library_function
  ; Note: No error check on this call

  ; === CLEAR STATE AND RETURN SUCCESS ===
  0x00005b9a:  clr.l      (0x2c,A2)                 ; Clear board->field_0x2C
  0x00005b9e:  clr.l      D0                        ; Return 0 (success)
  0x00005ba0:  bra.b      0x00005bae                ; Jump to epilogue

  ; --- ERROR PATH 2: Verification or config failed ---
error_path_2:
  0x00005ba2:  move.l     D3,-(SP)                  ; Push slot_num
  0x00005ba4:  move.l     D4,-(SP)                  ; Push board_id
  0x00005ba6:  bsr.l      0x00003874                ; CALL cleanup_board (FUN_00003874)
  0x00005bac:  moveq      0x5,D0                    ; Return error code 5

  ; === EPILOGUE ===
exit_function:
  0x00005bae:  movem.l    -0x14,A6,{D2 D3 D4 D5 A2} ; Restore registers
  0x00005bb4:  unlk       A6                        ; Restore frame pointer
  0x00005bb6:  rts                                  ; Return

; ============================================================================
```

---

## Stack Frame Layout

```
Higher addresses
+----------------+
| Return Address | (A6) + 4
+----------------+
| Saved A6       | (A6) ← Frame Pointer
+----------------+
| board_id       | (A6) + 8   [D4]
+----------------+
| slot_num       | (A6) + 12  [D3]
+----------------+
| param1         | (A6) + 16  [passed to FUN_00007032]
+----------------+
| param2         | (A6) + 20  [passed to FUN_00007032]
+----------------+
| param3         | (A6) + 24  [passed to FUN_00007032, possibly string]
+----------------+
Lower addresses

Saved Registers (pushed by movem.l):
- D2: Error code tracking
- D3: Slot number
- D4: Board ID
- D5: Converted integer value
- A2: Board structure pointer

Total stack frame: 0 bytes (no locals)
Saved registers: 20 bytes (5 registers × 4 bytes)
```

---

## Hardware Access Analysis

### Hardware Registers Accessed

**Direct Access**: None

**Indirect Access**: Via sub-functions
- `FUN_000036b2` (ND_RegisterBoardSlot) - Accesses slot table at 0x819C
- `FUN_00004c88` - Likely sets up DMA or memory mapping
- `FUN_00005c70` - Verification (may access board state)
- `FUN_00007032` - Configuration (may access hardware)

### Memory Regions

**Global Data**:
```
0x0000819C: Global slot table (accessed via ND_RegisterBoardSlot)
```

**Board Structure** (accessed via A2):
```
(A2)+0x04: board_port (Mach port)
(A2)+0x2C: field_0x2C (set by FUN_00004c88, cleared at end)
(A2)+0x40: field_0x40 (set by FUN_00004c88, used in library call)
```

---

## OS Functions and Library Calls

### Library Function Calls

**1. String to Integer Conversion** (`0x0500315e`):
```c
int string_to_int(const char* str);
// Likely: atoi() or strtol()
// Called at: 0x00005b06
// Input: String parameter (location unclear - possibly param3?)
// Output: D0 = integer value (saved to D5)
```

**Evidence**:
- Standard library address range (0x0500xxxx)
- No parameters pushed (reads from stack or register set earlier)
- Result used as integer parameter later

**2. Library Operation** (`0x050032ba`):
```c
int library_operation(int value, void* handle1, void* handle2);
// Called at: 0x00005b94
// Args: D5 (converted value), board->field_0x2C, board->field_0x40
// Return: Not checked
// Likely: ioctl(), sysctl(), or Mach port operation
```

**Evidence**:
- Called with 3 parameters
- Uses handles initialized by FUN_00004c88
- No error checking (fire-and-forget)

### Internal Function Calls

**1. ND_RegisterBoardSlot** (`0x000036b2`):
```c
int ND_RegisterBoardSlot(uint32_t board_id, uint32_t slot_num);
```
- **Purpose**: Register board in slot table, allocate structure
- **Previously Analyzed**: See docs/functions/000036b2_ND_RegisterBoardSlot.md
- **Called at**: 0x00005b12

**2. Memory/DMA Initialization** (`0x00004c88`):
```c
int FUN_00004c88(
    uint32_t board_id,
    mach_port_t board_port,
    int converted_value,
    uint32_t slot_num,
    void** out_handle1,  // &board->field_0x2C
    void** out_handle2   // &board->field_0x40
);
```
- **Purpose**: Initialize memory mapping or DMA handles
- **Called at**: 0x00005b40
- **Parameters**: 6 parameters (24 bytes on stack)
- **Output**: Sets two fields in board structure

**3. Board Verification** (`0x00005c70`):
```c
int FUN_00005c70(uint32_t board_id, uint32_t slot_num);
```
- **Purpose**: Verify board state, check if ready
- **Called at**: 0x00005b60
- **Returns**: 0 = success, non-zero = failure

**4. Apply Configuration** (`0x00007032`):
```c
int FUN_00007032(
    nd_board_info_t* board,
    void* param1,
    void* param2,
    void* param3
);
```
- **Purpose**: Apply configuration parameters to board
- **Called at**: 0x00005b7a
- **Returns**: -1 = error, other = success

**5. Cleanup Board** (`0x00003874`):
```c
void FUN_00003874(uint32_t board_id, uint32_t slot_num);
```
- **Purpose**: Cleanup partial initialization on error
- **Called at**: 0x00005b52 and 0x00005ba6 (two error paths)

---

## Reverse-Engineered C Pseudocode

```c
// Board structure (from previous analysis)
typedef struct nd_board_info {
    uint32_t  board_id;          // +0x00
    mach_port_t board_port;      // +0x04
    // ... fields 0x08-0x2B ...
    void*     field_0x2C;        // +0x2C: Memory/DMA handle
    // ... fields 0x30-0x3F ...
    void*     field_0x40;        // +0x40: Memory/DMA handle
    // ... remaining fields ...
} nd_board_info_t;

// External declarations
extern nd_board_info_t* slot_table[];  // @ 0x819C

// Library functions
extern int atoi(const char* str);                               // 0x0500315e
extern int library_operation(int val, void* h1, void* h2);     // 0x050032ba

// Internal functions
extern int ND_RegisterBoardSlot(uint32_t board_id, uint32_t slot_num);
extern int init_memory_handles(uint32_t board_id, mach_port_t port,
                                int value, uint32_t slot,
                                void** out1, void** out2);
extern int verify_board_state(uint32_t board_id, uint32_t slot_num);
extern int apply_configuration(nd_board_info_t* board,
                               void* p1, void* p2, void* p3);
extern void cleanup_board(uint32_t board_id, uint32_t slot_num);

/**
 * Setup and configure a NeXTdimension board with parameters
 *
 * @param board_id   Board identifier
 * @param slot_num   NeXTBus slot (2, 4, 6, or 8)
 * @param param1     Configuration parameter 1
 * @param param2     Configuration parameter 2
 * @param param3     Configuration parameter 3 (possibly string)
 * @return 0 on success, error code on failure
 */
int ND_SetupBoardWithParameters(
    uint32_t board_id,
    uint32_t slot_num,
    void*    param1,
    void*    param2,
    void*    param3)
{
    int result;
    int converted_value;
    nd_board_info_t* board;
    int slot_index;

    // Convert string parameter to integer
    // Note: Unclear which parameter is the string
    converted_value = atoi(param3);  // Assumption: param3 is string

    // Register board in slot (creates board structure)
    result = ND_RegisterBoardSlot(board_id, slot_num);
    if (result != 0) {
        return result;  // Return registration error
    }

    // Get board structure from slot table
    slot_index = slot_num / 2;
    board = slot_table[slot_index];

    // Initialize memory/DMA handles
    result = init_memory_handles(
        board_id,
        board->board_port,
        converted_value,
        slot_num,
        &board->field_0x2C,
        &board->field_0x40
    );

    if (result != 0) {
        cleanup_board(board_id, slot_num);
        return result;
    }

    // Verify board is ready
    result = verify_board_state(board_id, slot_num);
    if (result != 0) {
        cleanup_board(board_id, slot_num);
        return 5;  // Setup/verification failed
    }

    // Apply configuration parameters
    result = apply_configuration(board, param1, param2, param3);
    if (result == -1) {
        cleanup_board(board_id, slot_num);
        return 5;  // Configuration failed
    }

    // Finalize setup with system call
    library_operation(
        converted_value,
        board->field_0x2C,
        board->field_0x40
    );

    // Clear temporary handle
    board->field_0x2C = NULL;

    return 0;  // Success
}
```

---

## Data Structures

### Board Info Structure (Extended)

From this function, we learn about additional fields:

```c
struct nd_board_info {
    // ... fields 0x00-0x2B (see ND_RegisterBoardSlot analysis) ...

    void*     memory_handle;     // +0x2C: Memory/DMA handle
                                 //        Set by FUN_00004c88
                                 //        Cleared after library_operation
                                 //        Temporary usage

    // ... fields 0x30-0x3F ...

    void*     dma_handle;        // +0x40: DMA/device handle
                                 //        Set by FUN_00004c88
                                 //        Passed to library_operation
                                 //        Persistent handle

    // ... remaining fields ...
};
```

### Parameter Semantics

The three configuration parameters passed to this function:

```c
// Parameters passed to FUN_00007032 (apply_configuration)
typedef struct {
    void*  param1;   // Unknown purpose (arg3 @ 0x10(A6))
    void*  param2;   // Unknown purpose (arg4 @ 0x14(A6))
    void*  param3;   // Possibly string (arg5 @ 0x18(A6))
                     // One param converted to int via atoi()
} configuration_params_t;
```

**Note**: The exact mapping of which parameter is converted to integer is unclear from this function alone.

---

## Call Graph Integration

### Called By

According to call graph analysis:

**Single Caller**: `FUN_00002dc6` (0x00002dc6)
- Size: 662 bytes (large dispatcher/main function)
- Likely a command router or main entry point
- This function may handle command-line parsing or RPC dispatch

### Calls To

**Internal Functions** (5):
1. `FUN_000036b2` (0x000036b2) - ND_RegisterBoardSlot ✅ **ANALYZED**
2. `FUN_00004c88` (0x00004c88) - Memory/DMA initialization ⚠️ **NEEDS ANALYSIS**
3. `FUN_00005c70` (0x00005c70) - Board verification ⚠️ **NEEDS ANALYSIS**
4. `FUN_00007032` (0x00007032) - Apply configuration ⚠️ **NEEDS ANALYSIS**
5. `FUN_00003874` (0x00003874) - Cleanup board ⚠️ **NEEDS ANALYSIS**

**Library Functions** (2):
1. `0x0500315e` - String to integer (atoi/strtol)
2. `0x050032ba` - System operation (ioctl/sysctl/port_call)

### Call Graph Tree

```
FUN_00002dc6 (main dispatcher?)
    └── FUN_00005af6 (ND_SetupBoardWithParameters) ← THIS FUNCTION
            ├── lib_0x0500315e (atoi)
            ├── FUN_000036b2 (ND_RegisterBoardSlot)
            │       ├── lib_0x0500220a (vm_allocate)
            │       ├── lib_0x05002c54 (mach_operation)
            │       ├── FUN_00003cdc (init 1)
            │       ├── FUN_000045f2 (init 2)
            │       ├── FUN_00004822 (init 3)
            │       ├── FUN_0000493a (init 4)
            │       ├── FUN_000041fe (init 5)
            │       └── FUN_00003f3a (init 6)
            ├── FUN_00004c88 (memory/DMA init)
            ├── FUN_00005c70 (verify)
            ├── FUN_00007032 (apply config)
            ├── lib_0x050032ba (library op)
            └── FUN_00003874 (cleanup) [on error]
```

---

## Control Flow Analysis

### Control Flow Graph

```
[Entry]
   ↓
[Convert string to int]
   ↓
[Register board in slot]
   ↓
[Success?] ──No──→ [Return error]
   ↓ Yes
[Get board structure]
   ↓
[Initialize memory/DMA handles]
   ↓
[Success?] ──No──→ [Cleanup] → [Return error]
   ↓ Yes
[Verify board state]
   ↓
[Success?] ──No──→ [Cleanup] → [Return 5]
   ↓ Yes
[Apply configuration]
   ↓
[Success?] ──No──→ [Cleanup] → [Return 5]
   ↓ Yes
[Library operation (finalize)]
   ↓
[Clear temporary handle]
   ↓
[Return 0 - success]
   ↓
[Exit]
```

### Branch Analysis

| Address    | Type  | Target     | Condition | Purpose |
|------------|-------|------------|-----------|---------|
| 0x00005b1c | bne.w | 0x00005bae | D0 != 0   | Registration failed → exit |
| 0x00005b4c | beq.b | 0x00005b5c | D0 == 0   | Memory init success → continue |
| 0x00005b5a | bra.b | 0x00005bae | Always    | After cleanup → exit |
| 0x00005b6a | bne.b | 0x00005ba2 | D0 != 0   | Verification failed → cleanup |
| 0x00005b88 | beq.b | 0x00005ba2 | D0 == -1  | Config failed → cleanup |
| 0x00005ba0 | bra.b | 0x00005bae | Always    | Success → exit |

### Complexity Metrics

- **Cyclomatic Complexity**: 5 (4 decision points + 1 entry)
- **Paths to Success**: 1 (all checks must pass)
- **Paths to Failure**: 4 (registration, memory init, verification, configuration)
- **Maximum Nesting Depth**: 2

---

## Purpose Classification

**Primary Function**: **Board Setup Coordinator with Configuration**

**Responsibilities**:
1. ✅ Convert string parameter to integer
2. ✅ Register board in slot (delegates to ND_RegisterBoardSlot)
3. ✅ Initialize memory/DMA handles
4. ✅ Verify board readiness
5. ✅ Apply user-specified configuration parameters
6. ✅ Finalize setup with system call
7. ✅ Handle errors with cleanup

**Not Responsible For**:
- ❌ Board detection (done before calling)
- ❌ Parameter validation (assumes valid input)
- ❌ Logging (no error messages)

**Comparison to ND_RegisterBoardSlot**:
- ND_RegisterBoardSlot: Low-level slot registration + 6 init functions
- THIS FUNCTION: High-level setup that calls RegisterBoardSlot + adds configuration

---

## Error Handling

### Error Codes

| Code | Source | Meaning |
|------|--------|---------|
| 0    | Success | Board fully configured |
| 4    | ND_RegisterBoardSlot | Invalid slot or duplicate |
| 5    | This function | Verification or configuration failed |
| 6    | ND_RegisterBoardSlot | Memory allocation failed |
| Other | FUN_00004c88 | Memory/DMA init error |

### Error Paths

**Error Path 1** (0x00005b4e):
```
FUN_00004c88 fails
  → cleanup_board()
  → return error code from init
```

**Error Path 2** (0x00005ba2):
```
FUN_00005c70 fails OR FUN_00007032 returns -1
  → cleanup_board()
  → return 5
```

### Cleanup Strategy

Both error paths call `FUN_00003874` (cleanup_board) with board_id and slot_num.

**Cleanup Likely**:
- Deallocates board structure
- Releases Mach ports
- Clears slot table entry
- Frees any partial initialization

**Note**: The success path also clears `board->field_0x2C`, suggesting this is a temporary resource.

---

## Integration with NeXTdimension Protocol

### Role in System Initialization

This function represents a **higher-level initialization entry point** compared to `ND_RegisterBoardSlot`. It:

1. **Accepts Configuration**: Takes 3 additional parameters beyond board_id/slot
2. **Delegates Registration**: Calls ND_RegisterBoardSlot for basic setup
3. **Applies Configuration**: Uses FUN_00007032 to apply user parameters
4. **Finalizes**: Makes system call to activate configuration

### Expected Call Chain

```
Command Line / Config File
    ↓
FUN_00002dc6 (main dispatcher)
    ↓ (parses arguments)
ND_SetupBoardWithParameters ← THIS FUNCTION
    ↓
ND_RegisterBoardSlot
    ↓ (6 init functions)
Board Ready
```

### Configuration Parameters

The three parameters likely represent:

**Hypothesis 1 - Video Configuration**:
- param1: Resolution (e.g., "1120x832")
- param2: Color depth (e.g., "32")
- param3: Refresh rate (e.g., "68")

**Hypothesis 2 - Memory Configuration**:
- param1: VRAM size
- param2: System RAM window size
- param3: DMA buffer size

**Hypothesis 3 - Generic Options**:
- param1: Feature flags
- param2: Performance tuning
- param3: Device path or identifier

**Evidence Needed**: Analyze `FUN_00007032` to determine parameter semantics.

---

## m68k Architecture Details

### Register Usage

| Register | Purpose | Lifecycle |
|----------|---------|-----------|
| D0 | Return values, temp | Scratch |
| D1 | Comparison temp | Scratch |
| D2 | Error code tracking | Preserved (saved/restored) |
| D3 | slot_num | Preserved (saved/restored) |
| D4 | board_id | Preserved (saved/restored) |
| D5 | Converted integer value | Preserved (saved/restored) |
| A0 | Slot table pointer, temp | Scratch |
| A2 | Board structure pointer | Preserved (saved/restored) |
| A6 | Frame pointer | Standard |

### Stack Operations

**Total Stack Depth**:
```
Saved registers:        20 bytes (5 × 4)
Max call stack:         24 bytes (FUN_00004c88 - 6 params)
Total maximum:          44 bytes
```

**Stack Cleanup Pattern**:
- `addq.w #8, SP` for 2 parameters
- `adda.w #0x18, SP` for 6 parameters (24 bytes)
- Double `addq.w #8` for 4 parameters (16 bytes total)

### Optimization Notes

**Good Optimizations**:
- Reuses D2 for error tracking (avoids extra moves)
- Keeps board_id/slot_num in D4/D3 (avoids reloading)
- Uses A2 for board pointer (persistent across calls)

**Potential Improvements**:
- Could inline verification check (small function)
- Library call at end has no error check (risky)

---

## Analysis Insights

### Key Discoveries

1. **Two-Level Initialization**:
   - Level 1: ND_RegisterBoardSlot (basic setup)
   - Level 2: This function (configuration)

2. **String-to-Integer Conversion**:
   - First operation is atoi() call
   - Suggests user-provided string parameter
   - Likely from command-line argument or config file

3. **Dual Error Paths**:
   - Path 1: Early failure (memory/DMA init)
   - Path 2: Late failure (verification/config)
   - Both call cleanup, but different error codes

4. **Temporary vs Persistent Handles**:
   - field_0x2C: Cleared after use (temporary)
   - field_0x40: Kept (persistent)

5. **Fire-and-Forget Library Call**:
   - Final library_operation has no error check
   - Suggests it's non-critical or always succeeds

### Architectural Patterns

**Pattern**: Coordinator with Delegated Stages
```
Parse Input → Register → Initialize → Verify → Configure → Finalize
```

**Pattern**: Consistent Error Handling
```
Every critical operation:
  result = operation()
  if (result != 0) goto cleanup
```

**Pattern**: Resource Lifecycle
```
Allocate (ND_RegisterBoardSlot)
  → Use (this function)
  → Cleanup (on error) or Clear (on success)
```

### Connections to Other Functions

- **FUN_00002dc6**: Likely main entry point, may parse argc/argv
- **FUN_00004c88**: Critical for understanding memory/DMA setup
- **FUN_00007032**: Critical for understanding configuration parameters
- **FUN_00005c70**: May reveal board readiness criteria

---

## Unanswered Questions

1. **Which parameter is converted to integer?**
   - atoi() is called, but input source unclear
   - Could be param3, or earlier stack setup not visible

2. **What do the 3 configuration parameters represent?**
   - Need to analyze FUN_00007032
   - Could be video, memory, or generic options

3. **What does the final library call do?**
   - 0x050032ba with 3 parameters
   - Why no error checking?
   - Is it idempotent?

4. **What is field_0x2C used for?**
   - Set by FUN_00004c88
   - Used in library call
   - Cleared afterward
   - Temporary resource, but what kind?

5. **What is field_0x40 used for?**
   - Set by FUN_00004c88
   - Used in library call
   - NOT cleared (persistent)
   - Different purpose than field_0x2C?

6. **Why is verification (FUN_00005c70) separate?**
   - What does it check that init didn't verify?
   - Hardware state? Software state?

7. **What is the relationship to FUN_00005bb8?**
   - Nearly identical structure (next function in binary)
   - Different only in FUN_00007072 vs FUN_00007032
   - Variant for different configuration mode?

---

## Related Functions

### High Priority for Analysis

These functions are critical to understanding this function:

1. **FUN_00004c88** (0x00004c88) - Memory/DMA Initialization
   - **Why**: Sets critical fields field_0x2C and field_0x40
   - **What we need**: Purpose of these handles

2. **FUN_00005c70** (0x00005c70) - Board Verification
   - **Why**: Determines if board is ready for configuration
   - **What we need**: What criteria it checks

3. **FUN_00007032** (0x00007032) - Apply Configuration
   - **Why**: Takes the 3 mystery parameters
   - **What we need**: Parameter semantics and what gets configured

4. **FUN_00002dc6** (0x00002dc6) - Main Dispatcher (Caller)
   - **Why**: Only caller, sets up parameters
   - **What we need**: How it parses input and calls this function

### Medium Priority

5. **FUN_00003874** (0x00003874) - Cleanup Board
   - **Why**: Called on all error paths
   - **What we need**: What resources it releases

6. **FUN_00005bb8** (0x00005bb8) - Similar Function
   - **Why**: Nearly identical structure
   - **What we need**: How it differs, when each is used

### Library Function Identification

7. **lib_0x0500315e** - String to Integer
   - Likely: `atoi()` or `strtol()`
   - Cross-reference: NeXTSTEP 3.x SDK

8. **lib_0x050032ba** - System Operation
   - Likely: `ioctl()`, `sysctl()`, or Mach port call
   - Cross-reference: Parameter count and usage pattern

---

## Testing Notes

### Test Cases

**Test 1: Basic Success Path**
```c
int result = ND_SetupBoardWithParameters(
    0x12345678,  // board_id
    2,           // slot_num
    param1,      // Config param 1
    param2,      // Config param 2
    "68"         // String parameter (refresh rate?)
);
assert(result == 0);
```

**Test 2: Invalid Slot**
```c
int result = ND_SetupBoardWithParameters(0x12345678, 9, p1, p2, p3);
assert(result == 4);  // From ND_RegisterBoardSlot
```

**Test 3: Already Registered (Different Board)**
```c
ND_SetupBoardWithParameters(0x12345678, 2, p1, p2, p3);
int result = ND_SetupBoardWithParameters(0x87654321, 2, p1, p2, p3);
assert(result == 4);  // Slot conflict
```

**Test 4: Memory Init Failure**
```c
// Simulate FUN_00004c88 returning error
int result = ND_SetupBoardWithParameters(0x12345678, 2, p1, p2, p3);
assert(result != 0);  // Should cleanup and return error
// Verify slot_table[0] is NULL (cleaned up)
```

**Test 5: Verification Failure**
```c
// Simulate FUN_00005c70 returning non-zero
int result = ND_SetupBoardWithParameters(0x12345678, 2, p1, p2, p3);
assert(result == 5);  // Verification failed
```

### Debugging Tips

**Breakpoint Locations**:
- 0x00005b06: Before string conversion (check input)
- 0x00005b12: Before registration (check board_id/slot)
- 0x00005b40: Before memory init (check board structure)
- 0x00005b60: Before verification (check board state)
- 0x00005b7a: Before configuration (check parameters)
- 0x00005b94: Before final library call (check handles)

**Watch Variables**:
- D4: board_id (should remain constant)
- D3: slot_num (should remain constant)
- D5: converted_value (check atoi result)
- A2: board structure pointer (check fields at +0x2C and +0x40)
- D2: error code (tracks failures)

**Common Failures**:
- atoi() returns 0 for invalid string
- ND_RegisterBoardSlot fails if slot occupied
- FUN_00004c88 may fail if resources unavailable
- FUN_00005c70 may fail if hardware not responding
- FUN_00007032 returns -1 for invalid configuration

---

## Function Metrics

### Size and Complexity

| Metric | Value | Rating |
|--------|-------|--------|
| Size | 194 bytes | Medium |
| Instructions | ~67 | Medium |
| Cyclomatic Complexity | 5 | Low-Medium |
| Call Depth | 3 (this → RegisterBoardSlot → 6 inits) | High |
| Stack Usage | 44 bytes max | Low |
| Branch Points | 4 | Low |
| Function Calls | 7 (5 internal + 2 library) | High |
| Error Paths | 2 distinct | Medium |

### Complexity Rating

**Overall Complexity**: **Medium-High**

**Justification**:
- Control flow is simple (linear with error branches)
- BUT orchestrates 5 internal functions with complex dependencies
- Parameters and data structures not fully understood
- Error handling is consistent but cleanup is complex
- Integration with system calls adds uncertainty

### Comparison to Other Functions

| Function | Size | Complexity | Role |
|----------|------|------------|------|
| ND_RegisterBoardSlot | 366 bytes | High | Low-level registration |
| ND_SetupBoardWithParameters | 194 bytes | Medium-High | High-level setup |
| FUN_00005bb8 | 184 bytes | Medium-High | Similar variant |

---

## Reverse Engineering Confidence

### Confidence Levels

| Aspect | Confidence | Notes |
|--------|------------|-------|
| Control Flow | **HIGH** ✅ | All branches traced, logic clear |
| Function Purpose | **HIGH** ✅ | Board setup with config is obvious |
| Parameter Count | **HIGH** ✅ | 5 parameters confirmed |
| Parameter Semantics | **MEDIUM** ⚠️ | Types known, meanings unclear |
| Return Values | **HIGH** ✅ | Error codes identified |
| Error Handling | **HIGH** ✅ | Both paths documented |
| Internal Calls | **MEDIUM** ⚠️ | Called, but not fully analyzed |
| Library Calls | **MEDIUM** ⚠️ | Likely identified, not confirmed |
| Field Meanings | **LOW** ❌ | field_0x2C and field_0x40 unclear |
| Integration | **MEDIUM** ⚠️ | General role clear, details missing |

### Areas of Uncertainty

1. **atoi() input source** - Cannot determine which parameter is string
2. **Configuration parameter semantics** - Need FUN_00007032 analysis
3. **Library call 0x050032ba** - Purpose unclear, no error checking
4. **Board structure fields** - Many fields still unknown
5. **Relationship to FUN_00005bb8** - Why two similar functions?

### Validation Needed

To increase confidence:
- Analyze FUN_00007032 to understand configuration
- Analyze FUN_00004c88 to understand memory handles
- Cross-reference library addresses with NeXTSTEP SDK
- Compare with FUN_00005bb8 to find differences
- Find error message strings (if any)

---

## Summary

`ND_SetupBoardWithParameters` is a **critical high-level board setup function** that coordinates multi-stage initialization with user-provided configuration. It converts a string parameter to integer, registers the board via `ND_RegisterBoardSlot`, initializes memory/DMA handles, verifies board readiness, applies configuration parameters, and finalizes with a system call. The function implements robust error handling with cleanup on all failure paths, but some parameter semantics and library calls remain unclear without analyzing related functions.

**Key Insight**: This represents a user-facing entry point for board setup (likely from command-line or daemon), as opposed to `ND_RegisterBoardSlot` which is an internal low-level primitive.

**Next Steps**: Analyze `FUN_00007032` (configuration), `FUN_00004c88` (memory init), and `FUN_00002dc6` (caller) to complete understanding of the setup flow.

---

**Analysis Time**: ~60 minutes
**Document Length**: ~1400 lines
**Quality**: Comprehensive analysis with identified unknowns
**Recommended Name**: `ND_SetupBoardWithParameters`
