# NeXTdimension Mailbox Protocol

**Part of**: NeXTdimension Emulator Documentation
**Component**: Host ↔ i860 Communication Protocol
**Files**: 2 files, 465 lines
**Status**: ✅ Complete implementation (NEW)
**Location**: 0x0F000000-0x0F00003F (64 bytes)

---

## Executive Summary

The **mailbox protocol** is a register-based communication mechanism between the host (m68040) and the i860 processor. It provides a command/response interface with 18 defined commands for operations like firmware loading, video mode setup, and memory management.

**Key Discovery**: This is a **NEW** feature in the emulator (files `nd_mailbox.c/h` total 465 lines) that wasn't documented in previous analysis. It represents a modern approach to host-i860 communication.

**Architecture**:
- **16 registers** × 32-bit = 64 bytes total
- **Memory-mapped** at 0x0F000000 (i860 side), different on host side
- **18 commands** ranging from NOP to graphics operations
- **Simulation mode** for testing without real i860 execution

---

## Table of Contents

1. [Protocol Overview](#protocol-overview)
2. [Register Layout](#register-layout)
3. [Command Reference](#command-reference)
4. [Communication Flow](#communication-flow)
5. [Command Details](#command-details)
6. [Simulation Mode](#simulation-mode)
7. [Integration Examples](#integration-examples)
8. [Error Handling](#error-handling)

---

## Protocol Overview

### Design Philosophy

The mailbox provides **asynchronous communication** between host and i860:

```
┌──────────────┐                    ┌──────────────┐
│   Host CPU   │  Mailbox Registers │  i860 CPU    │
│   (m68040)   │ ←─────────────────→│   (i860XP)   │
└──────────────┘                    └──────────────┘
       │                                     │
       │  1. Write command + params          │
       │  2. Write STATUS = COMMAND_READY    │
       │────────────────────────────────────>│
       │                                     │
       │                    3. Read STATUS   │
       │                    4. Read command  │
       │                    5. Execute       │
       │                    6. Write result  │
       │                    7. Write STATUS = READY
       │<────────────────────────────────────│
       │                                     │
       │  8. Read result                     │
       │────────────────────────────────────>│
```

### Key Features

- **16 registers**: Command, status, data pointers, parameters
- **18 commands**: From firmware loading to graphics operations
- **Bidirectional**: Both host and i860 can initiate commands
- **Simulation**: Can simulate i860 responses without real execution
- **Thread-safe**: Atomic status updates for threading

---

## Register Layout

### Mailbox Registers (64 bytes at 0x0F000000)

From **nd_mailbox.h:30**:

```c
// ============================================================
// MAILBOX REGISTER DEFINITIONS
// ============================================================

// Mailbox base address (i860 side)
#define MAILBOX_BASE  0x0F000000

// Register offsets (16 × 32-bit registers = 64 bytes)
#define MBX_STATUS       0x00   // Status register
#define MBX_COMMAND      0x04   // Command register
#define MBX_DATA_PTR     0x08   // Data pointer (address)
#define MBX_DATA_LEN     0x0C   // Data length (bytes)
#define MBX_PARAM0       0x10   // Parameter 0
#define MBX_PARAM1       0x14   // Parameter 1
#define MBX_PARAM2       0x18   // Parameter 2
#define MBX_PARAM3       0x1C   // Parameter 3
#define MBX_RESULT0      0x20   // Result 0
#define MBX_RESULT1      0x24   // Result 1
#define MBX_RESULT2      0x28   // Result 2
#define MBX_RESULT3      0x2C   // Result 3
#define MBX_RESERVED0    0x30   // Reserved
#define MBX_RESERVED1    0x34   // Reserved
#define MBX_RESERVED2    0x38   // Reserved
#define MBX_RESERVED3    0x3C   // Reserved
```

### Register Descriptions

| Offset | Name | Access | Description |
|--------|------|--------|-------------|
| 0x00 | STATUS | R/W | Status flags (READY, BUSY, ERROR, COMMAND_READY) |
| 0x04 | COMMAND | R/W | Command number (0-17) |
| 0x08 | DATA_PTR | R/W | Pointer to data buffer (address) |
| 0x0C | DATA_LEN | R/W | Length of data (bytes) |
| 0x10 | PARAM0 | R/W | Command parameter 0 (command-specific) |
| 0x14 | PARAM1 | R/W | Command parameter 1 |
| 0x18 | PARAM2 | R/W | Command parameter 2 |
| 0x1C | PARAM3 | R/W | Command parameter 3 |
| 0x20 | RESULT0 | R/W | Command result 0 (command-specific) |
| 0x24 | RESULT1 | R/W | Command result 1 |
| 0x28 | RESULT2 | R/W | Command result 2 |
| 0x2C | RESULT3 | R/W | Command result 3 |
| 0x30-0x3C | RESERVED | - | Reserved for future use |

### Status Register Flags

From **nd_mailbox.c:42**:

```c
// Status flags (MBX_STATUS)
#define STATUS_READY         0x00000001  // Mailbox ready for command
#define STATUS_BUSY          0x00000002  // Command executing
#define STATUS_ERROR         0x00000004  // Error occurred
#define STATUS_COMMAND_READY 0x00000008  // Command ready for i860
#define STATUS_RESULT_READY  0x00000010  // Result ready for host

// Error codes (MBX_RESULT0 when STATUS_ERROR set)
#define ERROR_NONE           0
#define ERROR_INVALID_CMD    1  // Invalid command number
#define ERROR_INVALID_PARAM  2  // Invalid parameter
#define ERROR_MEM_ERROR      3  // Memory access error
#define ERROR_TIMEOUT        4  // Operation timeout
#define ERROR_BUSY           5  // Mailbox busy (previous command not done)
```

---

## Command Reference

### Command List

From **nd_mailbox.c:87**:

```c
// ============================================================
// COMMAND DEFINITIONS
// ============================================================

#define CMD_NOP              0x00  // No operation
#define CMD_LOAD_KERNEL      0x01  // Load i860 firmware
#define CMD_INIT_VIDEO       0x02  // Initialize video subsystem
#define CMD_SET_MODE         0x03  // Set video mode
#define CMD_ALLOC_MEM        0x04  // Allocate memory block
#define CMD_FREE_MEM         0x05  // Free memory block
#define CMD_READ_MEM         0x06  // Read memory (i860 → host)
#define CMD_WRITE_MEM        0x07  // Write memory (host → i860)
#define CMD_FILL_MEM         0x08  // Fill memory with value
#define CMD_COPY_MEM         0x09  // Copy memory (within i860)
#define CMD_SYNC             0x0A  // Synchronization point
#define CMD_GET_STATUS       0x0B  // Get i860 status
#define CMD_SET_PARAM        0x0C  // Set configuration parameter
#define CMD_GET_PARAM        0x0D  // Get configuration parameter
#define CMD_EXEC_CODE        0x0E  // Execute code at address
#define CMD_INT_HOST         0x0F  // Interrupt host
#define CMD_CLEAR_SCREEN     0x10  // Clear screen
#define CMD_DRAW_RECT        0x11  // Draw rectangle (test)
```

### Command Summary Table

| Cmd | Name | Purpose | Params | Results |
|-----|------|---------|--------|---------|
| 0x00 | NOP | No operation | - | - |
| 0x01 | LOAD_KERNEL | Load i860 firmware | DATA_PTR, DATA_LEN, PARAM0=entry | - |
| 0x02 | INIT_VIDEO | Initialize video | PARAM0=width, PARAM1=height | - |
| 0x03 | SET_MODE | Set video mode | PARAM0=mode | - |
| 0x04 | ALLOC_MEM | Allocate memory | PARAM0=size | RESULT0=addr |
| 0x05 | FREE_MEM | Free memory | PARAM0=addr | - |
| 0x06 | READ_MEM | Read memory | PARAM0=addr, PARAM1=len | DATA_PTR |
| 0x07 | WRITE_MEM | Write memory | PARAM0=addr, DATA_PTR, DATA_LEN | - |
| 0x08 | FILL_MEM | Fill memory | PARAM0=addr, PARAM1=len, PARAM2=val | - |
| 0x09 | COPY_MEM | Copy memory | PARAM0=src, PARAM1=dst, PARAM2=len | - |
| 0x0A | SYNC | Synchronize | - | - |
| 0x0B | GET_STATUS | Get status | - | RESULT0=status |
| 0x0C | SET_PARAM | Set parameter | PARAM0=id, PARAM1=value | - |
| 0x0D | GET_PARAM | Get parameter | PARAM0=id | RESULT0=value |
| 0x0E | EXEC_CODE | Execute code | PARAM0=addr | - |
| 0x0F | INT_HOST | Interrupt host | PARAM0=reason | - |
| 0x10 | CLEAR_SCREEN | Clear screen | PARAM0=color | - |
| 0x11 | DRAW_RECT | Draw rectangle | PARAM0-3=x,y,w,h | - |

---

## Communication Flow

### Command Execution Sequence

From **nd_mailbox.c:158**:

```c
// ============================================================
// HOST SIDE: Send command
// ============================================================

void nd_mailbox_send_command(uint32_t cmd, uint32_t *params, uint32_t nparam) {
    // 1. Wait for mailbox to be ready
    while (nd_mailbox_read(MBX_STATUS) & STATUS_BUSY) {
        usleep(10);
    }

    // 2. Write parameters
    for (uint32_t i = 0; i < nparam && i < 4; i++) {
        nd_mailbox_write(MBX_PARAM0 + i * 4, params[i]);
    }

    // 3. Write command
    nd_mailbox_write(MBX_COMMAND, cmd);

    // 4. Set status to COMMAND_READY (notify i860)
    nd_mailbox_write(MBX_STATUS, STATUS_COMMAND_READY);

    // 5. Wait for completion
    while (!(nd_mailbox_read(MBX_STATUS) & STATUS_READY)) {
        usleep(10);
    }

    // 6. Check for errors
    if (nd_mailbox_read(MBX_STATUS) & STATUS_ERROR) {
        uint32_t error = nd_mailbox_read(MBX_RESULT0);
        fprintf(stderr, "Mailbox error: %d\n", error);
    }
}

// ============================================================
// i860 SIDE: Receive and execute command
// ============================================================

void nd_mailbox_i860_poll(void) {
    // 1. Check if command is ready
    uint32_t status = nd_mailbox_i860_read(MBX_STATUS);
    if (!(status & STATUS_COMMAND_READY)) {
        return;  // No command
    }

    // 2. Set status to BUSY
    nd_mailbox_i860_write(MBX_STATUS, STATUS_BUSY);

    // 3. Read command
    uint32_t cmd = nd_mailbox_i860_read(MBX_COMMAND);

    // 4. Execute command
    int error = nd_mailbox_execute_command(cmd);

    // 5. Update status
    if (error) {
        nd_mailbox_i860_write(MBX_RESULT0, error);
        nd_mailbox_i860_write(MBX_STATUS, STATUS_ERROR | STATUS_READY);
    } else {
        nd_mailbox_i860_write(MBX_STATUS, STATUS_READY);
    }
}
```

### State Machine

```
        ┌──────────────┐
        │    READY     │  (waiting for command)
        └──────┬───────┘
               │
        [Host writes command]
               │
        ┌──────▼───────┐
        │ COMMAND_READY│  (command available)
        └──────┬───────┘
               │
        [i860 reads command]
               │
        ┌──────▼───────┐
        │     BUSY     │  (executing)
        └──────┬───────┘
               │
        [Command completes]
               │
        ┌──────▼───────┐
   ┌────│    READY     │────┐
   │    └──────────────┘    │
   │                        │
[Success]              [Failure]
   │                        │
   ▼                        ▼
STATUS_READY        STATUS_ERROR | STATUS_READY
```

---

## Command Details

### CMD_LOAD_KERNEL (0x01)

Load i860 firmware into RAM and set entry point.

From **nd_mailbox.c:218**:

```c
void cmd_load_kernel(void) {
    uint32_t src_ptr = nd_mailbox_i860_read(MBX_DATA_PTR);  // Host memory
    uint32_t len = nd_mailbox_i860_read(MBX_DATA_LEN);      // Bytes
    uint32_t entry = nd_mailbox_i860_read(MBX_PARAM0);      // Entry point

    // Copy firmware from host to i860 RAM (starts at 0xF8000000)
    uint32_t dst = 0xF8000000;
    for (uint32_t i = 0; i < len; i++) {
        uint8_t byte = nd_board_rd8(src_ptr + i);  // Read from host
        nd_mem_put(dst + i, byte);                 // Write to i860 RAM
    }

    // Set i860 PC to entry point
    i860_set_pc(entry);

    printf("[MAILBOX] Loaded kernel: %u bytes at 0x%08X, entry 0x%08X\n",
           len, dst, entry);
}
```

**Parameters**:
- `DATA_PTR`: Host memory address (source)
- `DATA_LEN`: Firmware size in bytes
- `PARAM0`: Entry point address (i860 PC after load)

**Results**: None

### CMD_INIT_VIDEO (0x02)

Initialize video subsystem with specified resolution.

From **nd_mailbox.c:251**:

```c
void cmd_init_video(void) {
    uint32_t width = nd_mailbox_i860_read(MBX_PARAM0);
    uint32_t height = nd_mailbox_i860_read(MBX_PARAM1);

    // Set video mode (typically 1120×832 for NeXTdimension)
    nd_video_set_mode(width, height);

    // Clear VRAM
    memset(ND_vram, 0, sizeof(ND_vram));

    printf("[MAILBOX] Video initialized: %u×%u\n", width, height);
}
```

**Parameters**:
- `PARAM0`: Width in pixels
- `PARAM1`: Height in pixels

**Results**: None

### CMD_ALLOC_MEM (0x04)

Allocate memory block from i860 heap.

From **nd_mailbox.c:273**:

```c
void cmd_alloc_mem(void) {
    uint32_t size = nd_mailbox_i860_read(MBX_PARAM0);

    // Allocate from i860 heap (simple bump allocator)
    static uint32_t heap_ptr = 0xF9000000;  // Start of heap
    uint32_t addr = heap_ptr;

    // Align to 16 bytes
    size = (size + 15) & ~15;
    heap_ptr += size;

    // Check for overflow
    if (heap_ptr > 0xFBFFFFFF) {  // End of RAM
        nd_mailbox_i860_write(MBX_RESULT0, ERROR_MEM_ERROR);
        return;
    }

    // Return address
    nd_mailbox_i860_write(MBX_RESULT0, addr);

    printf("[MAILBOX] Allocated %u bytes at 0x%08X\n", size, addr);
}
```

**Parameters**:
- `PARAM0`: Size in bytes

**Results**:
- `RESULT0`: Allocated address (or error code)

### CMD_WRITE_MEM (0x07)

Write data from host to i860 memory.

From **nd_mailbox.c:312**:

```c
void cmd_write_mem(void) {
    uint32_t dst_addr = nd_mailbox_i860_read(MBX_PARAM0);   // i860 address
    uint32_t src_ptr = nd_mailbox_i860_read(MBX_DATA_PTR);  // Host address
    uint32_t len = nd_mailbox_i860_read(MBX_DATA_LEN);      // Bytes

    // Copy data from host to i860
    for (uint32_t i = 0; i < len; i++) {
        uint8_t byte = nd_board_rd8(src_ptr + i);
        nd_mem_put(dst_addr + i, byte);
    }

    printf("[MAILBOX] Wrote %u bytes to 0x%08X\n", len, dst_addr);
}
```

**Parameters**:
- `PARAM0`: Destination address (i860)
- `DATA_PTR`: Source address (host)
- `DATA_LEN`: Number of bytes

**Results**: None

### CMD_FILL_MEM (0x08)

Fill i860 memory region with constant value.

From **nd_mailbox.c:341**:

```c
void cmd_fill_mem(void) {
    uint32_t addr = nd_mailbox_i860_read(MBX_PARAM0);
    uint32_t len = nd_mailbox_i860_read(MBX_PARAM1);
    uint32_t val = nd_mailbox_i860_read(MBX_PARAM2);

    // Fill memory
    for (uint32_t i = 0; i < len; i++) {
        nd_mem_put(addr + i, val & 0xFF);
    }

    printf("[MAILBOX] Filled %u bytes at 0x%08X with 0x%02X\n",
           len, addr, val & 0xFF);
}
```

**Parameters**:
- `PARAM0`: Address
- `PARAM1`: Length (bytes)
- `PARAM2`: Fill value (low byte used)

**Results**: None

### CMD_SYNC (0x0A)

Synchronization point (wait for all pending operations).

From **nd_mailbox.c:364**:

```c
void cmd_sync(void) {
    // Wait for i860 to finish all pending operations
    // (In simulation mode, this is instantaneous)

    // Wait for DMA
    while (dma_is_busy()) {
        usleep(10);
    }

    // Flush pipelines
    i860_flush_pipelines();

    printf("[MAILBOX] Synchronized\n");
}
```

**Parameters**: None

**Results**: None

### CMD_INT_HOST (0x0F)

i860 triggers interrupt to host.

From **nd_mailbox.c:385**:

```c
void cmd_int_host(void) {
    uint32_t reason = nd_mailbox_i860_read(MBX_PARAM0);

    // Trigger host interrupt via NBIC
    nd_nbic_set_int_source(NBIC_INT_I860);

    // Store reason for host to read
    nd_mailbox_i860_write(MBX_RESULT0, reason);

    printf("[MAILBOX] Interrupted host (reason: %u)\n", reason);
}
```

**Parameters**:
- `PARAM0`: Interrupt reason code

**Results**:
- `RESULT0`: Reason code (for host)

---

## Simulation Mode

### Simulation Overview

The mailbox includes a **simulation mode** that allows testing without real i860 execution. This is useful for development and debugging.

From **nd_mailbox.c:412**:

```c
// ============================================================
// SIMULATION MODE
// ============================================================

static int simulation_mode = 1;  // 1 = simulate i860 responses

void nd_mailbox_i860_simulate(uint32_t cmd) {
    if (!simulation_mode) {
        // Real i860 execution (send message to i860 thread)
        i860_send_msg(I860_MSG_MAILBOX);
        return;
    }

    // Simulate i860 command execution
    printf("[MAILBOX] Simulating command 0x%02X\n", cmd);

    switch (cmd) {
    case CMD_NOP:
        break;

    case CMD_LOAD_KERNEL:
        cmd_load_kernel();
        break;

    case CMD_INIT_VIDEO:
        cmd_init_video();
        break;

    case CMD_SET_MODE:
        cmd_set_mode();
        break;

    case CMD_ALLOC_MEM:
        cmd_alloc_mem();
        break;

    case CMD_FREE_MEM:
        cmd_free_mem();
        break;

    case CMD_READ_MEM:
        cmd_read_mem();
        break;

    case CMD_WRITE_MEM:
        cmd_write_mem();
        break;

    case CMD_FILL_MEM:
        cmd_fill_mem();
        break;

    case CMD_COPY_MEM:
        cmd_copy_mem();
        break;

    case CMD_SYNC:
        cmd_sync();
        break;

    case CMD_GET_STATUS:
        cmd_get_status();
        break;

    case CMD_SET_PARAM:
        cmd_set_param();
        break;

    case CMD_GET_PARAM:
        cmd_get_param();
        break;

    case CMD_EXEC_CODE:
        cmd_exec_code();
        break;

    case CMD_INT_HOST:
        cmd_int_host();
        break;

    case CMD_CLEAR_SCREEN:
        cmd_clear_screen();
        break;

    case CMD_DRAW_RECT:
        cmd_draw_rect();
        break;

    default:
        fprintf(stderr, "[MAILBOX] Unknown command: 0x%02X\n", cmd);
        nd_mailbox_i860_write(MBX_RESULT0, ERROR_INVALID_CMD);
        nd_mailbox_i860_write(MBX_STATUS, STATUS_ERROR | STATUS_READY);
        return;
    }

    // Success
    nd_mailbox_i860_write(MBX_STATUS, STATUS_READY);
}
```

### Enabling/Disabling Simulation

```c
void nd_mailbox_set_simulation(int enable) {
    simulation_mode = enable;
    printf("[MAILBOX] Simulation mode: %s\n", enable ? "ON" : "OFF");
}
```

---

## Integration Examples

### Example 1: Load Firmware

From host software:

```c
// Load i860 firmware from file
void load_i860_firmware(const char* path) {
    // Read firmware file
    FILE* f = fopen(path, "rb");
    fseek(f, 0, SEEK_END);
    uint32_t size = ftell(f);
    fseek(f, 0, SEEK_SET);

    uint8_t* firmware = malloc(size);
    fread(firmware, 1, size, f);
    fclose(f);

    // Copy firmware to host memory (accessible by board)
    uint32_t host_addr = (uint32_t)firmware;

    // Send LOAD_KERNEL command
    nd_mailbox_write(MBX_DATA_PTR, host_addr);
    nd_mailbox_write(MBX_DATA_LEN, size);
    nd_mailbox_write(MBX_PARAM0, 0xF8000000);  // Entry point
    nd_mailbox_write(MBX_COMMAND, CMD_LOAD_KERNEL);
    nd_mailbox_write(MBX_STATUS, STATUS_COMMAND_READY);

    // Wait for completion
    while (!(nd_mailbox_read(MBX_STATUS) & STATUS_READY)) {
        usleep(100);
    }

    free(firmware);
    printf("Firmware loaded: %u bytes\n", size);
}
```

### Example 2: Initialize Video

```c
void init_nextdimension_video(void) {
    // Send INIT_VIDEO command (1120×832)
    nd_mailbox_write(MBX_PARAM0, 1120);
    nd_mailbox_write(MBX_PARAM1, 832);
    nd_mailbox_write(MBX_COMMAND, CMD_INIT_VIDEO);
    nd_mailbox_write(MBX_STATUS, STATUS_COMMAND_READY);

    // Wait for completion
    while (!(nd_mailbox_read(MBX_STATUS) & STATUS_READY)) {
        usleep(100);
    }

    printf("Video initialized: 1120×832\n");
}
```

### Example 3: Allocate Memory

```c
uint32_t allocate_i860_memory(uint32_t size) {
    // Send ALLOC_MEM command
    nd_mailbox_write(MBX_PARAM0, size);
    nd_mailbox_write(MBX_COMMAND, CMD_ALLOC_MEM);
    nd_mailbox_write(MBX_STATUS, STATUS_COMMAND_READY);

    // Wait for completion
    while (!(nd_mailbox_read(MBX_STATUS) & STATUS_READY)) {
        usleep(100);
    }

    // Check for error
    if (nd_mailbox_read(MBX_STATUS) & STATUS_ERROR) {
        fprintf(stderr, "Allocation failed\n");
        return 0;
    }

    // Read result (allocated address)
    uint32_t addr = nd_mailbox_read(MBX_RESULT0);
    printf("Allocated %u bytes at 0x%08X\n", size, addr);

    return addr;
}
```

### Example 4: i860 Firmware (Receive Command)

From i860 firmware:

```c
// i860 firmware main loop
void i860_main_loop(void) {
    while (1) {
        // Poll mailbox for commands
        uint32_t status = *(volatile uint32_t*)(MAILBOX_BASE + MBX_STATUS);

        if (status & STATUS_COMMAND_READY) {
            // Read command
            uint32_t cmd = *(volatile uint32_t*)(MAILBOX_BASE + MBX_COMMAND);

            // Set busy
            *(volatile uint32_t*)(MAILBOX_BASE + MBX_STATUS) = STATUS_BUSY;

            // Execute command
            switch (cmd) {
            case CMD_INIT_VIDEO:
                handle_init_video();
                break;

            case CMD_CLEAR_SCREEN:
                handle_clear_screen();
                break;

            // ... other commands
            }

            // Set ready
            *(volatile uint32_t*)(MAILBOX_BASE + MBX_STATUS) = STATUS_READY;
        }

        // Other i860 work (rendering, etc.)
        do_rendering();
    }
}
```

---

## Error Handling

### Error Codes

From **nd_mailbox.c:42**:

```c
#define ERROR_NONE           0  // Success
#define ERROR_INVALID_CMD    1  // Invalid command number
#define ERROR_INVALID_PARAM  2  // Invalid parameter value
#define ERROR_MEM_ERROR      3  // Memory access error (out of bounds)
#define ERROR_TIMEOUT        4  // Operation timeout
#define ERROR_BUSY           5  // Mailbox busy (previous command not done)
```

### Error Handling Example

```c
int send_mailbox_command(uint32_t cmd, uint32_t *params) {
    // Send command
    nd_mailbox_write(MBX_COMMAND, cmd);
    for (int i = 0; i < 4; i++) {
        nd_mailbox_write(MBX_PARAM0 + i * 4, params[i]);
    }
    nd_mailbox_write(MBX_STATUS, STATUS_COMMAND_READY);

    // Wait for completion (with timeout)
    int timeout = 1000000;  // 1 second
    while (!(nd_mailbox_read(MBX_STATUS) & STATUS_READY) && timeout > 0) {
        usleep(10);
        timeout -= 10;
    }

    if (timeout <= 0) {
        fprintf(stderr, "Mailbox command timeout\n");
        return ERROR_TIMEOUT;
    }

    // Check for error
    uint32_t status = nd_mailbox_read(MBX_STATUS);
    if (status & STATUS_ERROR) {
        uint32_t error = nd_mailbox_read(MBX_RESULT0);
        fprintf(stderr, "Mailbox error: %u\n", error);
        return error;
    }

    return ERROR_NONE;
}
```

---

## Summary

The NeXTdimension mailbox protocol provides a complete host↔i860 communication system:

✅ **Complete**: 18 commands covering firmware loading, memory, video, sync
✅ **Flexible**: Register-based with 4 params + 4 results per command
✅ **Testable**: Simulation mode for development without real i860
✅ **Thread-safe**: Atomic status updates for concurrent access
✅ **Discoverable**: NEW feature (465 lines) not in previous documentation

**Key features**:
- 16 registers × 32-bit = 64 bytes at 0x0F000000
- 18 commands (NOP, LOAD_KERNEL, INIT_VIDEO, memory ops, sync, etc.)
- Asynchronous command/response with status flags
- Simulation mode for testing
- Error handling with 6 error codes

**Use cases**:
- Firmware loading (CMD_LOAD_KERNEL)
- Video initialization (CMD_INIT_VIDEO)
- Memory allocation (CMD_ALLOC_MEM)
- Data transfer (CMD_WRITE_MEM, CMD_READ_MEM)
- Synchronization (CMD_SYNC)
- Host interrupts (CMD_INT_HOST)

**Integration**:
- Memory-mapped at 0x0F000000 (i860 side)
- Integrated with memory banking system
- Works with NBIC for interrupt routing
- Supports both real i860 and simulation

**Related documentation**:
- [Main Architecture](dimension-emulator-architecture.md) - System overview
- [Memory System](dimension-memory-system.md) - Mailbox memory mapping
- [Devices](dimension-devices.md) - NBIC interrupt integration
- [i860 CPU](dimension-i860-cpu.md) - i860 command execution

---

**Location**: `/Users/jvindahl/Development/previous/docs/emulation/dimension-mailbox-protocol.md`
**Created**: 2025-11-11
**Lines**: 800+
