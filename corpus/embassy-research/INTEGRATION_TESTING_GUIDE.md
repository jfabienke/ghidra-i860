# NeXTdimension Firmware Integration Testing Guide

**Purpose**: Test the mailbox protocol implementation with the Previous emulator and NeXTSTEP

---

## Overview

The NeXTdimension mailbox protocol is now complete and ready for integration testing. This guide walks through testing the firmware with the Previous emulator, which will:

1. Validate protocol implementation
2. Discover unknown commands (0x13+)
3. Test real-world command sequences
4. Identify any timing or synchronization issues

---

## Prerequisites

### Firmware Side (Complete ✅)

- ✅ Mailbox protocol implementation
- ✅ All 19 documented command handlers
- ✅ Register interface at 0x02000000
- ✅ Embassy async integration
- ✅ Example application

### Emulator Side (Needs Implementation ⏳)

The Previous emulator needs mailbox register handlers added to:
- **File**: `/Users/jvindahl/Development/previous/src/dimension/nd_mailbox.c` (create new)
- **Integration**: `/Users/jvindahl/Development/previous/src/dimension/dimension.c` (update)

---

## Step 1: Add Mailbox Registers to Previous Emulator

### Create `src/dimension/nd_mailbox.c`

```c
/*
  Previous - nd_mailbox.c

  NeXTdimension mailbox protocol emulation.
  Maps host (68040) register accesses to i860 firmware registers.
*/

#include "main.h"
#include "dimension.h"
#include "nd_mem.h"

// Mailbox registers (64 bytes at 0x02000000 in i860 space)
// These are at offset 0x0F000000 in host 68040 address space
#define ND_MAILBOX_BASE     0x0F000000

static struct {
    uint32_t status;        // 0x00
    uint32_t command;       // 0x04
    uint32_t data_ptr;      // 0x08
    uint32_t data_len;      // 0x0C
    uint32_t result;        // 0x10
    uint32_t error_code;    // 0x14
    uint32_t host_signal;   // 0x18
    uint32_t i860_signal;   // 0x1C
    uint32_t arg1;          // 0x20
    uint32_t arg2;          // 0x24
    uint32_t arg3;          // 0x28
    uint32_t arg4;          // 0x2C
    uint32_t reserved[4];   // 0x30-0x3F
} nd_mailbox;

// Status bit definitions
#define ND_MBOX_STATUS_READY    0x00000001
#define ND_MBOX_STATUS_BUSY     0x00000002
#define ND_MBOX_STATUS_COMPLETE 0x00000004
#define ND_MBOX_STATUS_ERROR    0x00000008
#define ND_MBOX_STATUS_IRQ_HOST 0x00000010
#define ND_MBOX_STATUS_IRQ_I860 0x00000020

void nd_mailbox_init(void) {
    // Initialize mailbox to reset state
    memset(&nd_mailbox, 0, sizeof(nd_mailbox));

    // Set READY bit (firmware initialized)
    nd_mailbox.status = ND_MBOX_STATUS_READY;

    Log_Printf(LOG_ND_LEVEL, "[ND Mailbox] Initialized at 0x%08X\n", ND_MAILBOX_BASE);
}

// Host reads from mailbox registers
uint32_t nd_mailbox_read(uint32_t addr) {
    uint32_t offset = addr - ND_MAILBOX_BASE;
    uint32_t val = 0;

    switch (offset) {
        case 0x00: val = nd_mailbox.status; break;
        case 0x04: val = nd_mailbox.command; break;
        case 0x08: val = nd_mailbox.data_ptr; break;
        case 0x0C: val = nd_mailbox.data_len; break;
        case 0x10: val = nd_mailbox.result; break;
        case 0x14: val = nd_mailbox.error_code; break;
        case 0x18: val = nd_mailbox.host_signal; break;
        case 0x1C: val = nd_mailbox.i860_signal; break;
        case 0x20: val = nd_mailbox.arg1; break;
        case 0x24: val = nd_mailbox.arg2; break;
        case 0x28: val = nd_mailbox.arg3; break;
        case 0x2C: val = nd_mailbox.arg4; break;
        default:
            if (offset >= 0x30 && offset < 0x40) {
                val = nd_mailbox.reserved[(offset - 0x30) / 4];
            } else {
                Log_Printf(LOG_WARN, "[ND Mailbox] Read from unknown offset 0x%02X\n", offset);
            }
            break;
    }

    Log_Printf(LOG_ND_LEVEL, "[ND Mailbox] Read  0x%08X = 0x%08X\n", addr, val);
    return val;
}

// Host writes to mailbox registers
void nd_mailbox_write(uint32_t addr, uint32_t val) {
    uint32_t offset = addr - ND_MAILBOX_BASE;

    Log_Printf(LOG_ND_LEVEL, "[ND Mailbox] Write 0x%08X = 0x%08X\n", addr, val);

    switch (offset) {
        case 0x00: // Status
            // Host can set READY bit to send command
            if (val & ND_MBOX_STATUS_READY) {
                nd_mailbox.status |= ND_MBOX_STATUS_READY;
                Log_Printf(LOG_ND_LEVEL, "[ND Mailbox] HOST: Command sent (code 0x%02X)\n",
                          nd_mailbox.command);
            }
            // Host can clear COMPLETE bit after reading result
            if (!(val & ND_MBOX_STATUS_COMPLETE)) {
                nd_mailbox.status &= ~ND_MBOX_STATUS_COMPLETE;
            }
            break;

        case 0x04: nd_mailbox.command = val; break;
        case 0x08: nd_mailbox.data_ptr = val; break;
        case 0x0C: nd_mailbox.data_len = val; break;
        case 0x10: nd_mailbox.result = val; break;
        case 0x14: nd_mailbox.error_code = val; break;
        case 0x18: nd_mailbox.host_signal = val; break;
        case 0x1C: nd_mailbox.i860_signal = val; break;
        case 0x20: nd_mailbox.arg1 = val; break;
        case 0x24: nd_mailbox.arg2 = val; break;
        case 0x28: nd_mailbox.arg3 = val; break;
        case 0x2C: nd_mailbox.arg4 = val; break;
        default:
            if (offset >= 0x30 && offset < 0x40) {
                nd_mailbox.reserved[(offset - 0x30) / 4] = val;
            } else {
                Log_Printf(LOG_WARN, "[ND Mailbox] Write to unknown offset 0x%02X\n", offset);
            }
            break;
    }
}

// i860 firmware reads from mailbox (for testing)
uint32_t nd_mailbox_i860_read(uint32_t addr) {
    // i860 sees mailbox at 0x02000000
    uint32_t host_addr = ND_MAILBOX_BASE + (addr - 0x02000000);
    return nd_mailbox_read(host_addr);
}

// i860 firmware writes to mailbox (for testing)
void nd_mailbox_i860_write(uint32_t addr, uint32_t val) {
    // i860 sees mailbox at 0x02000000
    uint32_t host_addr = ND_MAILBOX_BASE + (addr - 0x02000000);
    nd_mailbox_write(host_addr, val);
}

// Simulate i860 firmware processing (for testing before real firmware)
void nd_mailbox_i860_simulate(void) {
    // Check if command is ready
    if (nd_mailbox.status & ND_MBOX_STATUS_READY) {
        uint32_t cmd = nd_mailbox.command;

        // Clear READY, set BUSY
        nd_mailbox.status &= ~ND_MBOX_STATUS_READY;
        nd_mailbox.status |= ND_MBOX_STATUS_BUSY;

        Log_Printf(LOG_ND_LEVEL, "[ND Mailbox] i860: Processing command 0x%02X\n", cmd);

        // Simulate command processing
        switch (cmd) {
            case 0x00: // NOP
                nd_mailbox.result = 0;
                nd_mailbox.error_code = 0; // SUCCESS
                break;
            case 0x10: // GET_INFO
                // Return board info: clock=33, RAM=32, VRAM=4, FW=0x01
                nd_mailbox.result = (0x01 << 24) | (4 << 16) | (32 << 8) | 33;
                nd_mailbox.error_code = 0;
                break;
            default:
                // Unknown command
                nd_mailbox.result = 0;
                nd_mailbox.error_code = 1; // INVALID_COMMAND
                Log_Printf(LOG_WARN, "[ND Mailbox] i860: Unknown command 0x%02X\n", cmd);
                break;
        }

        // Clear BUSY, set COMPLETE
        nd_mailbox.status &= ~ND_MBOX_STATUS_BUSY;
        nd_mailbox.status |= ND_MBOX_STATUS_COMPLETE;

        Log_Printf(LOG_ND_LEVEL, "[ND Mailbox] i860: Command complete (result=0x%08X, error=%d)\n",
                  nd_mailbox.result, nd_mailbox.error_code);
    }
}
```

### Update `src/dimension/dimension.c`

Add mailbox initialization and register mapping:

```c
#include "nd_mailbox.h"

void dimension_init(void) {
    // ... existing initialization ...

    // Initialize mailbox
    nd_mailbox_init();
}

// In memory access handlers, add mailbox register range:

uint32_t dimension_mem_read(uint32_t addr) {
    // Check if access is to mailbox registers
    if (addr >= 0x0F000000 && addr < 0x0F000040) {
        return nd_mailbox_read(addr);
    }

    // ... existing memory handlers ...
}

void dimension_mem_write(uint32_t addr, uint32_t val) {
    // Check if access is to mailbox registers
    if (addr >= 0x0F000000 && addr < 0x0F000040) {
        nd_mailbox_write(addr, val);
        return;
    }

    // ... existing memory handlers ...
}
```

---

## Step 2: Build and Run Previous Emulator

```bash
cd /Users/jvindahl/Development/previous

# Add new file to CMakeLists.txt
# Edit src/dimension/CMakeLists.txt:
# add_library(Dimension ... nd_mailbox.c ...)

# Rebuild
mkdir -p build
cd build
cmake ..
make -j$(sysctl -n hw.ncpu)

# Run with NeXTdimension enabled
./Previous --nextdimension on
```

---

## Step 3: Boot NeXTSTEP and Monitor Mailbox

### Enable Verbose Logging

In Previous, enable detailed logging:

```c
// In nd_mailbox.c, set log level:
#define LOG_ND_LEVEL LOG_DEBUG
```

### Expected Boot Sequence

When NeXTSTEP boots with NeXTdimension:

1. **NDserver daemon starts**
2. **Probes mailbox** - Reads status register
3. **Sends GET_INFO command** (0x10) - Queries board capabilities
4. **Initializes video** - INIT_VIDEO (0x02), SET_MODE (0x03)
5. **Clears screen** - FILL_RECT (0x05) with black
6. **Loads NeXT logo** - UPDATE_FRAMEBUFFER (0x04)
7. **Ongoing commands** - Drawing operations as needed

### Log Output Example

```
[ND Mailbox] Initialized at 0x0F000000
[ND Mailbox] Read  0x0F000000 = 0x00000001  (status: READY)
[ND Mailbox] Write 0x0F000004 = 0x00000010  (command: GET_INFO)
[ND Mailbox] Write 0x0F000000 = 0x00000001  (set READY bit)
[ND Mailbox] HOST: Command sent (code 0x10)
[ND Mailbox] i860: Processing command 0x10
[ND Mailbox] i860: Command complete (result=0x01042021, error=0)
[ND Mailbox] Read  0x0F000000 = 0x00000004  (status: COMPLETE)
[ND Mailbox] Read  0x0F000010 = 0x01042021  (result)
[ND Mailbox] Read  0x0F000014 = 0x00000000  (error_code: SUCCESS)
[ND Mailbox] Write 0x0F000000 = 0x00000000  (clear COMPLETE bit)
```

---

## Step 4: Capture Unknown Commands

### Enable Unknown Command Logging

Commands 0x13+ are unknown. When encountered:

```c
default:
    // Unknown command
    nd_mailbox.result = 0;
    nd_mailbox.error_code = 1; // INVALID_COMMAND
    Log_Printf(LOG_WARN, "[ND Mailbox] *** UNKNOWN COMMAND: 0x%02X ***\n", cmd);
    Log_Printf(LOG_WARN, "[ND Mailbox]     arg1=0x%08X, arg2=0x%08X\n",
              nd_mailbox.arg1, nd_mailbox.arg2);
    Log_Printf(LOG_WARN, "[ND Mailbox]     arg3=0x%08X, arg4=0x%08X\n",
              nd_mailbox.arg3, nd_mailbox.arg4);
    Log_Printf(LOG_WARN, "[ND Mailbox]     data_ptr=0x%08X, data_len=0x%08X\n",
              nd_mailbox.data_ptr, nd_mailbox.data_len);
    break;
```

### Collect Unknown Commands

Create a log file:

```bash
./Previous --nextdimension on 2>&1 | tee nd_mailbox_test.log
grep "UNKNOWN COMMAND" nd_mailbox_test.log > unknown_commands.txt
```

### Analyze Results

```bash
# Count unique unknown commands
awk '/UNKNOWN COMMAND/ {print $NF}' unknown_commands.txt | sort | uniq -c

# Example output:
#   15 0x13
#    8 0x14
#    3 0x1A
```

Update firmware with discovered commands!

---

## Step 5: Validate Known Commands

### Test Matrix

| Command | Code | Test Method | Expected Result |
|---------|------|-------------|-----------------|
| NOP | 0x00 | Send via NDserver | result=0, error=0 |
| LOAD_KERNEL | 0x01 | Boot sequence | Kernel loaded to DRAM |
| INIT_VIDEO | 0x02 | Boot sequence | Screen initializes |
| SET_MODE | 0x03 | Boot sequence | 1120x832 mode set |
| UPDATE_FB | 0x04 | Display NeXT logo | Logo appears |
| FILL_RECT | 0x05 | Clear screen | Screen fills with color |
| BLIT | 0x06 | Copy region | Pixels copied |
| SET_PALETTE | 0x07 | Indexed color mode | Palette loaded |
| SET_CURSOR | 0x08 | Move mouse | Cursor bitmap changes |
| MOVE_CURSOR | 0x09 | Move mouse | Cursor position updates |
| SHOW_CURSOR | 0x0A | Hide/show | Cursor visibility changes |
| GET_INFO | 0x10 | NDserver probe | Board info returned |
| MEMORY_TEST | 0x11 | Diagnostics | Test passes/fails |
| RESET | 0x12 | Diagnostics | Video resets |

### Validation Script

```bash
#!/bin/bash
# nd_test_commands.sh

echo "Testing NeXTdimension Mailbox Commands..."

# Parse log for command results
for cmd in 00 01 02 03 04 05 06 07 08 09 0A 10 11 12; do
    echo -n "Command 0x$cmd: "

    count=$(grep "Processing command 0x$cmd" nd_mailbox_test.log | wc -l)
    errors=$(grep "command 0x$cmd" nd_mailbox_test.log | grep "error=[1-9]" | wc -l)

    if [ $count -eq 0 ]; then
        echo "NOT USED"
    elif [ $errors -gt 0 ]; then
        echo "ERRORS ($errors/$count)"
    else
        echo "OK ($count calls)"
    fi
done
```

---

## Step 6: Performance Testing

### Measure Command Latencies

Add timing to emulator:

```c
#include <time.h>

void nd_mailbox_i860_simulate(void) {
    if (nd_mailbox.status & ND_MBOX_STATUS_READY) {
        struct timespec start, end;
        clock_gettime(CLOCK_MONOTONIC, &start);

        // ... process command ...

        clock_gettime(CLOCK_MONOTONIC, &end);

        uint64_t ns = (end.tv_sec - start.tv_sec) * 1000000000 +
                      (end.tv_nsec - start.tv_nsec);

        Log_Printf(LOG_DEBUG, "[ND Mailbox] Command 0x%02X took %llu ns\n",
                  cmd, ns);
    }
}
```

### Analyze Performance

```bash
# Extract latencies
grep "took.*ns" nd_mailbox_test.log | \
    awk '{print $4, $6}' | \
    sort | uniq -c

# Expected ranges:
# NOP: <1000 ns
# GET_INFO: <2000 ns
# FILL_RECT: 10000-100000 ns
# UPDATE_FB: 100000-10000000 ns
```

---

## Step 7: Integration with Real Firmware

### Replace Simulation with Real i860 Code

Once validated with simulation:

1. **Load actual firmware** - Use `LOAD_KERNEL` command
2. **Jump to entry point** - i860 executes at 0x00000000
3. **Firmware runs mailbox loop** - Embassy task handles commands
4. **Remove simulation code** - Real firmware responds

### Firmware Loading Sequence

```
1. Previous starts with i860 in reset
2. Host loads firmware via LOAD_KERNEL (0x01)
3. Host releases i860 from reset
4. i860 firmware runs mailbox_task()
5. Firmware sets READY bit
6. Host sends commands normally
```

---

## Troubleshooting

### Issue: No commands received

**Check**:
- Mailbox register mapping (0x0F000000 on host)
- NDserver daemon running
- NeXTdimension enabled in config

**Debug**:
```c
Log_Printf(LOG_DEBUG, "[ND Mailbox] Status reads: %d\n", read_count);
```

### Issue: Commands timeout

**Check**:
- READY bit set after init
- COMPLETE bit set after processing
- Status transitions (READY → BUSY → COMPLETE)

**Debug**:
```c
Log_Printf(LOG_DEBUG, "[ND Mailbox] Status: 0x%02X\n", nd_mailbox.status);
```

### Issue: Wrong results

**Check**:
- Result register (0x10) written correctly
- Error code register (0x14) set to SUCCESS (0)
- Argument parsing (packed u16 values)

**Debug**:
```c
Log_Printf(LOG_DEBUG, "[ND Mailbox] Result: 0x%08X, Error: %d\n",
          nd_mailbox.result, nd_mailbox.error_code);
```

---

## Success Criteria

✅ **Mailbox protocol working**:
- Commands sent and received
- Results returned correctly
- Status bits transition properly

✅ **Known commands validated**:
- All 19 commands tested
- Expected results confirmed
- No protocol errors

✅ **Unknown commands discovered**:
- Commands 0x13+ identified
- Parameters logged
- Ready to implement

✅ **Performance acceptable**:
- Command latencies reasonable
- No timeouts or hangs
- Smooth operation

---

## Next Steps After Validation

1. **Add newly discovered commands** (0x13+)
2. **Implement RAMDAC programming**
3. **Add cursor hardware control**
4. **Optimize with interrupts**
5. **Profile and optimize hot paths**

---

## Resources

- **Firmware**: `/Users/jvindahl/Development/nextdimension/firmware/rust/nextdim-embassy/`
- **Emulator**: `/Users/jvindahl/Development/previous/`
- **Documentation**: `MAILBOX_IMPLEMENTATION_COMPLETE.md`
- **Previous Docs**: `/Users/jvindahl/Development/previous/src/CLAUDE.md`

---

**Status**: Ready for integration testing
**Last Updated**: November 7, 2025
**Next Milestone**: Discover unknown commands, validate known commands
