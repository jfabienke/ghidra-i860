# NeXTcube ROM Strings - Complete Decoded Messages

**ROM Version**: v2.5 (v66)
**Binary File**: Rev_2.5_v66.bin (128KB)
**Extraction Date**: 2025-11-11
**Method**: Direct binary extraction at all identified PEA.L addresses

---

## Overview

This document contains **ALL 154 strings** extracted from the NeXTcube boot ROM binary, mapped to their exact addresses and usage contexts. These are the actual messages displayed on the graphical boot console.

---

## Complete String Database

### Boot Messages & System Information

#### 0x0100F260: Boot Banner
```
"Testing\nsystem ..."
```
**Context**: Initial boot message displayed immediately after power-on
**Function**: Welcome message during hardware initialization

#### 0x0100FCC1: ROM Version
```
"NeXT ROM Monitor %d.%d (v%d)"
```
**Format Args**: Major version, minor version, ROM version number
**Context**: Displays ROM version (e.g., "NeXT ROM Monitor 2.5 (v66)")
**Usage**: System identification

#### 0x0100F2E0: System Configuration
```
"%d MHz, memory %d nS\nBackplane slot #%d\nEthernet address: %x:%x:%x:%x:%x:%x\n"
```
**Format Args**:
- CPU frequency in MHz (e.g., 25 or 33)
- Memory speed in nanoseconds
- Backplane slot number
- 6 bytes of MAC address (hex values)

**Context**: Comprehensive system information display
**Example Output**:
```
33 MHz, memory 80 nS
Backplane slot #1
Ethernet address: 0:0:0f:ca:b5:3e
```

---

### Memory Configuration & Testing

#### 0x0100F273: Memory Config Failure
```
"Main Memory Configuration Test Failed\n\n"
```
**Context**: Memory controller configuration error (early boot)
**Severity**: CRITICAL - Cannot continue boot

#### 0x0100F29B: Memory Test Failure
```
"Main Memory Test Failed\n\n"
```
**Context**: RAM test failure during POST
**Severity**: CRITICAL

#### 0x0100F2B5: VRAM Label
```
"VRAM"
```
**Context**: Label for video RAM testing

#### 0x0100F2BA: VRAM Test Failure
```
"VRAM Memory Test Failed\n"
```
**Context**: Video memory test failure
**Impact**: Cannot display graphics

#### 0x0100F3F7: Memory Size
```
"Memory size %dMB"
```
**Format Args**: Total RAM in megabytes
**Context**: Reports detected memory size
**Example**: "Memory size 32MB"

#### 0x0100F408: Parity Status
```
", parity enabled"
```
**Context**: Appended to memory size if parity SIMMs detected

#### 0x0100F35D: Memory Socket Mismatch (Range)
```
"Memory sockets %d-%d configured for %s SIMMs but have %s SIMMs installed.\n"
```
**Format Args**:
- First socket number
- Last socket number
- Expected SIMM type (string)
- Actual SIMM type (string)

**Context**: SIMM configuration error
**Example**: "Memory sockets 0-3 configured for 1MB SIMMs but have 4MB SIMMs installed."

#### 0x0100F3A8: Memory Socket Mismatch (Individual)
```
"Memory sockets %d and %d configured for %s SIMMs but have %s SIMMs installed.\n"
```
**Context**: Similar to above, but for non-contiguous sockets

#### 0x0100F531: Memory Bank Info (Range)
```
"Memory sockets %d-%d have %s SIMMs installed (0x%x-0x%x)\n"
```
**Format Args**: Socket range, SIMM type, start address, end address
**Context**: Informational - shows memory map

#### 0x0100F56B: Memory Bank Info (Individual)
```
"Memory sockets %d and %d have %s SIMMs installed (0x%x-0x%x)\n"
```
**Context**: Similar to above, non-contiguous sockets

#### 0x0100F41B: Memory Failure Fatal
```
"can't continue without some working memory\n"
```
**Context**: No usable RAM detected - HALT condition

#### 0x0100F81A: Mixed Mode SIMMs
```
"Bank %d has mixed mode SIMM's\n"
```
**Context**: Parity and non-parity SIMMs mixed in same bank

#### 0x0100F839: Parity Requirement
```
"All of the SIMMs must be parity SIMMs if you want parity to work.\n"
```
**Context**: Warning about parity configuration

#### 0x0100F95D: Bad SIMM Detection
```
"One or both SIMMs in memory bank %d are bad\n"
```
**Context**: Hardware failure detected in specific bank

#### 0x0100F789: Bad SIMM (Alternate)
```
"One or more SIMM at memory bank %d is bad\n"
```
**Context**: Similar failure message

#### 0x0100F98A: Mixed SIMM Sizes
```
"Bank %d has mixed size SIMMs.\n"
```
**Context**: Different capacity SIMMs in same bank (not supported)

---

### Memory Diagnostic Details

#### 0x0100F6EA: DRAM Error Type
```
"\nDRAM error type %d\n"
```
**Format Args**: Error type code
**Context**: Detailed memory diagnostic

#### 0x0100F6FF: Socket Prompt
```
"Check socket (0 is the first socket): "
```
**Context**: User prompt for manual diagnostic

#### 0x0100F726: Numeric Display
```
"%d "
```
**Context**: Generic number formatting

#### 0x0100F72A: Memory Error Location
```
"\nMemory error at location: %x\n"
```
**Format Args**: Address where error occurred
**Example**: "Memory error at location: 4000000"

#### 0x0100F749: Error Value
```
"Value at time of failure: %x\n"
```
**Format Args**: Data value that failed
**Context**: Diagnostic detail

#### 0x0100F767: Coupling Fault
```
"Coupling dependent memory fault!\n"
```
**Context**: Advanced memory diagnostic - coupling error between bits

#### 0x0100F7B4: Bank Note
```
"Note: bank 0 is the first bank\n"
```
**Context**: Informational for diagnostics

#### 0x0100F932: Socket Check Result
```
"Check socket (0 is the first socket): %d\n\n"
```
**Format Args**: Socket number
**Context**: Diagnostic output

---

### VRAM Diagnostics

#### 0x0100F9A9: VRAM Failure (Detailed with newline)
```
"\nVRAM failure at 0x%x:  read 0x%08x, expected 0x%08x, bad bits %08x, IC U%d\n"
```
**Format Args**:
- Address of failure
- Value read
- Expected value
- XOR of bad bits
- Chip number (IC designator)

**Context**: Detailed VRAM diagnostic with chip location

#### 0x0100F9F6: VRAM Failure (Detailed)
```
"VRAM failure at 0x%x:  read 0x%08x, expected 0x%08x, bad bits %08x, IC U%d\n"
```
**Context**: Same as above without leading newline

---

### CPU & System Tests

#### 0x0100F2D3: CPU Identification
```
"CPU MC68040 "
```
**Context**: CPU model string (prepended to system info)

#### 0x0100F447: Double Newline
```
"\n\n"
```
**Context**: Spacing/formatting

#### 0x0100F419: Single Newline
```
"\n"
```
**Context**: Most frequently used string (5+ uses) - simple line terminator

#### 0x0100F44A: System Test Error
```
"System test failed.  Error code %x.\n\n"
```
**Format Args**: Error code (hex)
**Context**: POST failure with diagnostic code

#### 0x0100F470: System Test Pass
```
"\nSystem test passed.\n"
```
**Context**: Successful POST completion

#### 0x0100F87C: FPU Test
```
"Testing the FPU"
```
**Context**: Floating-point unit diagnostic

#### 0x0100F88C: SCC Test
```
", SCC"
```
**Context**: Serial Communications Controller test (appended to list)

#### 0x0100F892: SCSI Test
```
", SCSI"
```
**Context**: SCSI controller test

#### 0x0100F899: Ethernet Test
```
", Enet"
```
**Context**: Ethernet controller test

#### 0x0100F8A0: ECC Test
```
", ECC"
```
**Context**: Error-Correcting Code hardware test

#### 0x0100F8A6: RTC Test
```
", RTC"
```
**Context**: Real-Time Clock test

#### 0x0100F8AC: Timer Test
```
", Timer"
```
**Context**: System timer test

#### 0x0100F8B4: Event Counter Test
```
", Event Counter"
```
**Context**: Event counter hardware test

#### 0x0100F8C4: Sound Test
```
", Sound Out"
```
**Context**: Sound output hardware test

#### 0x0100F8D0: Extended Test Banner
```
"\n\nStarting Extended Self Test...\n"
```
**Context**: Entering comprehensive diagnostic mode

#### 0x0100F8F2: Extended SCSI
```
"Extended SCSI Test"
```
**Context**: Detailed SCSI subsystem test

#### 0x0100F905: Self Test Exit
```
"\n\nPress and hold any key to exit self test"
```
**Context**: User prompt during extended diagnostics

---

### Boot Device & Boot Process

#### 0x0100F495: No Boot Command
```
"No default boot command.\n"
```
**Context**: NVRAM boot command not set or invalid

#### 0x0100F4AF: Space Character
```
" "
```
**Context**: Formatting

#### 0x0100FB4C: Boot Command Display
```
"Boot command: %s\n"
```
**Format Args**: Boot command string
**Example**: "Boot command: sd(0,0,0)mach"

#### 0x0100FB5E: Boot Device Not Found
```
"Default boot device not found.\n"
```
**Context**: Device specified in NVRAM doesn't exist

#### 0x0100FB7E: Device Specification
```
"(%d,%d,%d)"
```
**Format Args**: Controller, unit, partition
**Context**: Boot device specification format

#### 0x0100FB89: Boot Command Format
```
"boot %s%s%s\n"
```
**Format Args**: Device, filename, flags
**Context**: Displays full boot command

#### 0x0100FB96: Boot Usage
```
"Usage: b [device[(ctrl,unit,part)] [filename] [flags]]\n"
```
**Context**: Help text for boot command

#### 0x0100FBCE: Boot Devices Header
```
"boot devices:\n"
```
**Context**: List of available boot devices

#### 0x0100FBDD: Device List Entry
```
"\t%s: %s.\n"
```
**Format Args**: Device name, description
**Example**: "\tsd: SCSI disk."

#### 0x0100FBFE: Booting Message
```
"Booting %s from %s\n"
```
**Format Args**: Filename, device
**Example**: "Booting mach from sd(0,0,0)"

#### 0x0100FC23: Device Spec with File
```
"%s(%d,%d,%d)%s"
```
**Context**: Device specification with filename

#### 0x0100FC32: Simple Device Spec
```
"%s()%s"
```
**Context**: Device with no controller/unit/part

#### 0x0100FBE7: Binary Format Error
```
"unknown binary format\n"
```
**Context**: Boot file is not Mach-O or recognized format

#### 0x0100FFE6: Bad Label
```
"Bad label\n"
```
**Context**: Disk label corrupted or unreadable

#### 0x0100FFF1: No Bootfile
```
"No bootfile in label\n"
```
**Context**: Disk label doesn't specify boot image

---

### SCSI Subsystem Messages

#### 0x0100F7D4: SCSI DMA Interrupt
```
"SCSI DMA intr?\n"
```
**Context**: Unexpected SCSI DMA interrupt

#### 0x0100FCF3: Boot Error
```
"Error during boot"
```
**Context**: Generic boot failure

#### 0x0100FD05: Incomplete Boot
```
"Didn't complete"
```
**Context**: Boot process interrupted or stalled

#### 0x0100FD15: SCSI State Error
```
"scstart: bad state"
```
**Context**: SCSI state machine error

#### 0x0100FD28: Software Error
```
"software error"
```
**Context**: Generic software fault

#### 0x0100FD37: Parity Error
```
"parity error"
```
**Context**: SCSI bus parity error

#### 0x0100FD44: Selection Failed
```
"selection failed"
```
**Context**: SCSI device selection failed

#### 0x0100FD55: Bus Error
```
"bus error"
```
**Context**: SCSI bus error condition

#### 0x0100FD5F: Target Aborted
```
"target aborted"
```
**Context**: SCSI target aborted command

#### 0x0100FD6E: FIFO Level
```
"fifo level"
```
**Context**: SCSI FIFO level error

#### 0x0100FD79: Target Aborted 2
```
"target aborted2"
```
**Context**: Alternative target abort message

#### 0x0100FD89: Message In FIFO
```
"msgin fifo level"
```
**Context**: SCSI message-in FIFO error

#### 0x0100FD9A: Interrupt Error
```
"scintr program error"
```
**Context**: SCSI interrupt handler error

#### 0x0100FDAF: Command Phase Error
```
"SCSI command phase"
```
**Context**: Unexpected SCSI phase

#### 0x0100FDC2: I/O Direction Error
```
"SCSI bad i/o direction"
```
**Context**: DMA direction mismatch

#### 0x0100FDD9: Unaligned DMA Segment
```
"SCSI unaligned DMA segment"
```
**Context**: DMA buffer alignment error

#### 0x0100FDF4: Unaligned DMA
```
"SCSI unaligned DMA"
```
**Context**: Generic DMA alignment error

#### 0x0100FE07: Message Out Phase
```
"SCSI msgout phase"
```
**Context**: Unexpected message-out phase

#### 0x0100FE19: No Current Device
```
"scmsgin: no current sd"
```
**Context**: SCSI message-in with no active device

#### 0x0100FE30: Unexpected Message
```
"SCSI unexpected msg:%d\n"
```
**Format Args**: Message byte value
**Context**: Unknown SCSI message received

#### 0x0100FE48: Unexpected Message (Short)
```
"Unexpected msg"
```
**Context**: Shorter version

#### 0x0100FE57: No Function Complete
```
"scmsgin: no FUNCCMPLT"
```
**Context**: SCSI command didn't complete

#### 0x0100FE6D: SCSI Error Format
```
"sc: %s\n"
```
**Format Args**: Error string
**Context**: Generic SCSI error wrapper

#### 0x0100FE75: Bus Hung
```
"SCSI Bus Hung\n"
```
**Context**: SCSI bus timeout/hung condition

#### 0x0100FE84: No Disk
```
"no SCSI disk\n"
```
**Context**: No bootable SCSI disk found

#### 0x0100FE92: Booting SCSI Target
```
"booting SCSI target %d, lun %d\n"
```
**Format Args**: Target ID, LUN
**Example**: "booting SCSI target 0, lun 0"

#### 0x0100FEB2: Block Length Query
```
"dev blk len?\n"
```
**Context**: Cannot read device block length

#### 0x0100FEC0: Read Capacity Command
```
"READ CAPACITY"
```
**Context**: SCSI command name

#### 0x0100FECE: Request Sense Command
```
"REQ SENSE"
```
**Context**: SCSI command name

#### 0x0100FED8: **Waiting for Drive**
```
"waiting for drive to come ready"
```
**Context**: CRITICAL - Drive spin-up wait (matches earlier analysis)

#### 0x0100FEF8: Bad Block Size
```
"bad dev blk size %d\n"
```
**Format Args**: Block size in bytes
**Context**: Unsupported sector size

#### 0x0100FF0D: Read Command
```
"READ"
```
**Context**: SCSI READ command name

#### 0x0100FF12: Bad SCSI State
```
"sdcmd bad state: %d\n"
```
**Format Args**: State number
**Context**: SCSI driver state machine error

#### 0x0100FF27: Generic Label Format
```
"%s: "
```
**Context**: Generic prefix for error messages

#### 0x0100FF2C: Selection Timeout
```
"Selection timeout on target\n"
```
**Context**: SCSI device didn't respond

#### 0x0100FF49: Sense Key Error
```
"Failed, sense key: 0x%x\n"
```
**Format Args**: SCSI sense key (hex)
**Context**: SCSI error with sense data

#### 0x0100FF62: Target Busy
```
"Target busy\n"
```
**Context**: SCSI device returned BUSY status

#### 0x0100FF6F: Target Disconnected
```
"Target disconnected\n"
```
**Context**: SCSI device disconnected unexpectedly

#### 0x0100FF84: Driver Refused
```
"Driver refused command\n"
```
**Context**: SCSI driver rejected command

#### 0x0100FF9C: State Machine Error
```
"sdfail bad state: %d\n"
```
**Format Args**: State number
**Context**: SCSI failure handler state error

#### 0x0100FFB2: DMA Alignment
```
"dma_list: bad alignment"
```
**Context**: DMA scatter-gather list alignment error

#### 0x0100FFCA: DMA Residual Error
```
"dma_cleanup: negative resid"
```
**Context**: DMA transfer accounting error

---

### Network Boot (TFTP/BOOTP)

#### 0x0100FC12: TFTP Protocol
```
"octet"
```
**Context**: TFTP transfer mode (binary)

#### 0x0100FC18: TFTP Error
```
"\ntftp: %s\n"
```
**Format Args**: Error message
**Context**: TFTP failure

#### 0x0100FC39: TFTP Timeout
```
"tftp: timeout\n"
```
**Context**: TFTP server didn't respond

#### 0x0100FC48: BOOTP Request
```
"Requesting BOOTP information"
```
**Context**: Network boot initialization

#### 0x0100FC65: BOOTP From
```
"from %s"
```
**Format Args**: Server name/address
**Context**: BOOTP server identification

#### 0x0100FC6D: Boot Protocol Name
```
"boot"
```
**Context**: Protocol identifier

#### 0x0100FC72: NeXT Identifier
```
"NeXT"
```
**Context**: Vendor identifier in BOOTP

#### 0x0100FC77: Network OK
```
" [OK]\n"
```
**Context**: Network operation succeeded

#### 0x0100FC7E: Network Timeout
```
" [timeout]\n"
```
**Context**: Network operation timed out

#### 0x0100FCA9: Ethernet Write Error
```
"en_write: tx not ready\n"
```
**Context**: Ethernet transmitter not ready

---

### ROM Monitor Commands & Interface

#### 0x0100F4E2: Command Prompt
```
"NeXT>"
```
**Context**: ROM monitor command prompt

#### 0x0100F4E8: New Password Prompt
```
"New password: "
```
**Context**: Setting ROM password

#### 0x0100F4F7: Retype Password
```
"Retype new password: "
```
**Context**: Password confirmation

#### 0x0100F50D: Password Mismatch
```
"Mismatch - password unchanged\n"
```
**Context**: Password confirmation failed

#### 0x0100F619: Password Prompt
```
"Password: "
```
**Context**: ROM monitor authentication

#### 0x0100F624: Password Failed
```
"Sorry\n"
```
**Context**: Incorrect password

#### 0x0100F600: Unknown Command
```
"Huh?\n"
```
**Context**: Invalid command entered

#### 0x0100F62B: Usage Error
```
"usage error, type \"?\" for help\n"
```
**Context**: Invalid command syntax

#### 0x0100F606: Test Failed Banner
```
"System\ntest\nfailed"
```
**Context**: Multi-line failure message (diagnostic mode)

#### 0x0100F930: **Period**
```
"."
```
**Context**: Progress indicator (matches earlier analysis - "Trying alternate boot device")

---

### User Input & Formatting

#### 0x0100F52C: Character 'a'
```
"a"
```
**Context**: Single character (possibly choice option)

#### 0x0100F52E: Character 'd'
```
"d"
```
**Context**: Single character (possibly choice option)

#### 0x0100F64B: Format Prefix
```
"%s%s: "
```
**Context**: Composite string formatting

#### 0x0100F652: Hex Input Prompt
```
"%08x? "
```
**Context**: Prompting for hex value

#### 0x0100F659: Binary Input Prompt
```
"%b? "
```
**Context**: Prompting for binary value

#### 0x0100F65E: String Input Prompt
```
"%s? "
```
**Context**: Prompting for string value

#### 0x0100F663: Length Limit
```
"must be < %d chars long\n"
```
**Format Args**: Maximum length
**Context**: Input validation

#### 0x0100F680: **Generic Prompt**
```
" %s? "
```
**Context**: Used 3 times - generic value prompt (matches earlier analysis)

#### 0x0100F6DF: Address Display
```
"%x: "
```
**Context**: Memory dump address prefix

#### 0x0100F6E4: Question Mark
```
"? "
```
**Context**: Generic prompt

#### 0x0100F6E7: **Format String**
```
"%s"
```
**Context**: Used multiple times - generic string formatting

#### 0x0100FC9B: Backspace Sequence
```
"\x08 \x08"
```
**Context**: Erase character on screen (backspace-space-backspace)

#### 0x0100FC9F: Radix Prefix "0t"
```
"0t"
```
**Context**: Decimal (base-10) prefix

#### 0x0100FCA2: Radix Prefix "0x"
```
"0x"
```
**Context**: Hexadecimal prefix

#### 0x0100FCA5: Character 'X'
```
"X"
```
**Context**: Format specifier

#### 0x0100FCA7: Character 'L'
```
"L"
```
**Context**: Long modifier

#### 0x0100F5E8: Input Radix
```
"default input radix %d\n"
```
**Format Args**: Radix (8, 10, 16)
**Context**: Number input base setting

---

### Diagnostic & Miscellaneous

#### 0x0100F25D: Language Code
```
"en"
```
**Context**: English language identifier

#### 0x0100F32D: NVRAM Warning
```
"Warning: non-volatile memory is uninitialized.\n"
```
**Context**: NVRAM/RTC data corrupt or first boot

#### 0x0100F486: Diagnostics Label
```
"diagnostics"
```
**Context**: Diagnostic mode identifier

#### 0x0100F492: Help Flag
```
"-h"
```
**Context**: Command line help flag

#### 0x0100F4B1: Stack Frame Error
```
"bogus stack frame\n"
```
**Context**: Exception handler detected corrupt stack

#### 0x0100F4C4: Exception Report
```
"Exception #%d (0x%x) at 0x%x\n"
```
**Format Args**: Exception number (decimal), exception number (hex), address
**Context**: CPU exception handler output
**Example**: "Exception #2 (0x2) at 0x1000234"

#### 0x0100F5A9: Error Code History
```
"Old error code: %x\nLast error code: %x\n"
```
**Format Args**: Previous error, current error
**Context**: Diagnostic error code display

#### 0x0100F5D1: Function Code
```
"Function code %d (%s)\n"
```
**Format Args**: Code number, description
**Context**: Diagnostic function identification

#### 0x0100F686: Floppy Required
```
"There must be a disk inserted in drive #0 before you can set this option\n"
```
**Context**: Configuration requirement

#### 0x0100F7E4: Sound Interrupt
```
"Sound Out Over Run Interrupt.\n"
```
**Context**: Audio hardware error

#### 0x0100F803: Sound DMA Error
```
"\nSound Out DMA error!\n"
```
**Context**: Audio DMA failure

#### 0x0100FAF1: TP String
```
"tp"
```
**Context**: Unknown (possibly device/protocol abbreviation)

#### 0x0100FCDE: Power Down Confirm
```
"\nreally power down? "
```
**Context**: Shutdown confirmation prompt

---

## Format String Analysis

### Printf Format Specifiers Used

| Specifier | Count | Purpose | Example |
|-----------|-------|---------|---------|
| `%d` | 35+ | Decimal integer | "Memory size %dMB" |
| `%x` | 30+ | Hexadecimal | "Error code %x" |
| `%s` | 25+ | String | "Booting %s" |
| `%08x` | 5 | 8-digit hex (padded) | "read 0x%08x" |
| `%b` | 1 | Binary (custom?) | "%b? " |

### Common Argument Patterns

**System Info (0x0100F2E0)**:
```asm
; Stack setup before call
MOVE.L ethernet_addr+5,-(A7)  ; MAC byte 6
MOVE.L ethernet_addr+4,-(A7)  ; MAC byte 5
MOVE.L ethernet_addr+3,-(A7)  ; MAC byte 4
MOVE.L ethernet_addr+2,-(A7)  ; MAC byte 3
MOVE.L ethernet_addr+1,-(A7)  ; MAC byte 2
MOVE.L ethernet_addr+0,-(A7)  ; MAC byte 1
MOVE.L slot_number,-(A7)      ; Backplane slot
MOVE.L memory_speed,-(A7)     ; nS
MOVE.L cpu_freq,-(A7)         ; MHz
PEA.L $0100F2E0               ; Format string
BSR.L $0100685A               ; printf
ADDA.W #$0028,A7              ; Clean up (10 args = 40 bytes)
```

**Memory Error (0x0100F9A9)**:
```asm
; VRAM diagnostic
MOVE.L chip_number,-(A7)      ; IC Uxx
MOVE.L bad_bits,-(A7)         ; XOR
MOVE.L expected_value,-(A7)   ; Expected
MOVE.L read_value,-(A7)       ; Actual
MOVE.L address,-(A7)          ; Location
PEA.L $0100F9A9               ; Format string
BSR.L $0100685A               ; printf
ADDA.W #$0018,A7              ; Clean up (6 args = 24 bytes)
```

---

## Key Discoveries

### Confirmed Messages from Earlier Analysis

| Address | Predicted Message | Actual Message | Match? |
|---------|-------------------|----------------|--------|
| 0x0100FED8 | "Boot device failed" | "waiting for drive to come ready" | ❌ Different |
| 0x0100F930 | "Trying alternate boot device" | "." | ❌ Just a dot! |
| 0x0100F419 | "OK" or success | "\n" | ❌ Just newline |

**Insight**: The "boot device failed" and "trying alternate boot device" messages were **incorrect guesses**. The actual messages are:
- 0x0100FED8: Drive spin-up wait message
- 0x0100F930: Single period (progress dot)
- 0x0100F419: Simple newline (explains 5+ uses)

### Actual Boot Failure Messages

| Address | Message | Context |
|---------|---------|---------|
| 0x0100FB5E | "Default boot device not found." | NVRAM device invalid |
| 0x0100FE84 | "no SCSI disk\n" | No bootable SCSI disk |
| 0x0100FCF3 | "Error during boot" | Generic boot error |
| 0x0100FD05 | "Didn't complete" | Boot incomplete |

### Most Common Strings (by reuse)

1. **0x0100F419** ("\n") - 5+ uses - Line terminator
2. **0x0100F680** (" %s? ") - 3 uses - Generic prompt
3. **0x0100F273** (memory config fail) - 2 uses
4. **0x0100F29B** (memory test fail) - 2 uses

---

## String Categories Summary

| Category | Count | Address Range |
|----------|-------|---------------|
| Memory messages | 28 | 0x0100F273-0x0100F98A |
| SCSI messages | 42 | 0x0100F7D4-0x0100FFCA |
| System info | 15 | 0x0100F2D3-0x0100F8D0 |
| Boot messages | 18 | 0x0100FB4C-0x0100FFF1 |
| Network messages | 12 | 0x0100FC12-0x0100FCA9 |
| ROM Monitor UI | 20 | 0x0100F4E2-0x0100F6E7 |
| Diagnostics | 18 | 0x0100F5A9-0x0100F905 |

---

## Usage Examples (Reconstructed)

### Normal Boot Sequence Output
```
Testing
system ...
CPU MC68040 33 MHz, memory 80 nS
Backplane slot #1
Ethernet address: 0:0:f:ca:b5:3e
Memory size 32MB, parity enabled

Testing the FPU, SCC, SCSI, Enet, RTC, Timer


Boot command: sd(0,0,0)mach
Booting mach from sd(0,0,0)
```

### Memory Error Example
```
Testing
system ...
Main Memory Configuration Test Failed

Memory error at location: 4000000
Value at time of failure: deadbeef

One or more SIMM at memory bank 0 is bad
Check socket (0 is the first socket): 0

can't continue without some working memory
```

### SCSI Boot Failure Example
```
booting SCSI target 0, lun 0
waiting for drive to come ready....
Selection timeout on target
no SCSI disk

Default boot device not found.
```

---

## Next Steps Completed ✓

1. ✅ **Extract ROM binary strings** - ALL 154 strings extracted
2. ✅ **Map string content to addresses** - Complete address→message database
3. ⏭️ **Analyze printf arguments** - Patterns documented, detailed call-site analysis next
4. ⏭️ **Decode format specifiers** - Common patterns identified, full analysis pending
5. ⏭️ **Build complete boot message trace** - Example sequences reconstructed

---

## Cross-References

- **[Console Messages Catalog](nextcube-rom-console-messages.md)** - All call sites and calling patterns
- **[ROM Monitor Commands](nextcube-rom-monitor-commands.md)** - Boot modes and implicit commands
- **[ROM Analysis](nextcube-rom-analysis.md)** - Complete ROM structure

---

**Extraction Method**: Binary string extraction from Rev_2.5_v66.bin at all identified PEA.L addresses
**Verification**: All 154 addresses successfully extracted, 153 non-empty strings
**Character Encoding**: ASCII (all strings successfully decoded)
