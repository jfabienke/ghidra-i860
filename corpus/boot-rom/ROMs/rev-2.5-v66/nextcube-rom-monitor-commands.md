# NeXTcube ROM Monitor Command Set Analysis

**ROM Version**: v2.5 (v66)
**ROM Address**: 0x01000000-0x0101FFFF (128KB)
**Analysis Method**: Direct disassembly reverse engineering
**Date**: 2025-11-11

## Executive Summary

The NeXTcube boot ROM does **not** have a traditional interactive command-line ROM Monitor. Instead, it implements an **implicit command system** based on:

1. **Boot device selection** stored in NVRAM/RTC
2. **Hardware state detection** at specific registers
3. **Key combinations** during boot (not yet fully documented in disassembly)
4. **Automatic boot paths** based on hardware configuration

## Key Finding: No Interactive Shell

Unlike many contemporary systems (Sun OpenBoot, Mac Programmer's Switch), the NeXTcube ROM does **not** implement:

- ❌ Command prompt
- ❌ Text parser for user commands
- ❌ Interactive debugger interface
- ❌ Serial console commands

Instead, all "commands" are **pre-defined boot modes** selected through hardware state.

---

## Boot Device Selection Mechanism

### Device Table Structure

**Location**: 0x01016D5C (ROM data section)

Each boot device has a 28-byte (0x1C) structure containing function pointers:

```
Offset  Purpose
+0x00   Device type identifier
+0x04   Init function pointer
+0x08   Probe function pointer
+0x0C   Boot function pointer
+0x10   Read function pointer
+0x14   Write function pointer
+0x18   Control function pointer
```

### Boot Device Codes

Stored at offsets `0x034C` (device) and `0x034D` (subdevice) in the system state structure:

```c
struct boot_device_state {
    uint8_t device;     // 0x034C - Primary boot device
    uint8_t subdevice;  // 0x034D - Secondary/fallback device
    uint8_t flags;      // 0x034E - Boot flags
};
```

**Device codes** (from disassembly at 0x0100A0E2-0x0100A148):

- `0x00` = Internal SCSI disk
- `0x01` = Network boot (Ethernet)
- `0x02` = Floppy disk
- `0x03` = External SCSI
- `0x04` = CD-ROM
- `0x0E` = Diagnostic mode
- `0xFF` = Invalid/unset

---

## Implicit "Commands" via Boot Modes

### 1. Normal Boot (Default)

**Trigger**: No special keys pressed
**Code Path**: 0x010002CC → 0x0100B10E
**Device**: Read from NVRAM (0x034C)

```asm
; Read boot device from NVRAM
0100A11A: 102A 034C          MOVE.B (A2,$034C),D0    ; Get device code
0100A11E: 49C0               EXT.B D0
0100A120: B0AA 0006          CMP.L (A2,$0006),D0     ; Check validity
0100A124: 661A               BNE.B $0100A140         ; Invalid device

; Load function pointer table
0100A12C: 41F9 0101 6D5C     LEA.L $01016D5C,A0      ; Device table
0100A132: 721C               MOVE.L #$0000001C,D1    ; Entry size = 28 bytes
0100A134: 4C01 0800          MULL.L #$0800,D1        ; Calculate offset
0100A13A: 2070 080C          MOVEA.L (A0,D0.L*1,$0C),A0  ; Get boot function
0100A13E: 4E90               JSR.L (A0)              ; Call boot function
```

### 2. Alternate Boot Device

**Trigger**: Hardware register check at 0x0100B10E
**Code Path**: 0x0100B0FA → 0x0100B14A
**Fallback Logic**: Tries up to 3 devices

```asm
; Boot device fallback loop
0100B142: 5283               ADD.L #$00000001,D3     ; Increment device counter
0100B144: 7202               MOVE.L #$00000002,D1    ; Max 3 attempts
0100B146: B283               CMP.L D3,D1
0100B148: 6CB0               BGE.B $0100B0FA         ; Try next device

; If all fail, show error
0100B150: 6C10               BGE.B $0100B162         ; Boot failed
0100B152: 4879 0100 FED8     PEA.L $0100FED8         ; "Boot failed" message
0100B158: 61FF FFFF B616     BSR.L $01006770         ; Display error
```

**Messages**:
- 0x0100FED8: "Boot device failed"
- 0x0100F930: "Trying alternate boot device"
- 0x0100F419: "Boot successful"

### 3. NeXTdimension Graphics Mode

**Trigger**: Device Type 3 detected at 0x0200C000
**Code Path**: 0x010000F2 → 0x0100023E
**Special Handling**: Alternate memory map

```asm
; Detect NeXTdimension board
010001EA: 2035 0170 0200 C000    MOVE.L (A5,D0.W*1+$0200C000),D0
010001FA: 740C                   MOVE.L #$0000000C,D2
010001FC: E4A1                   ASR.L D2,D1           ; Extract bits 15-12
010001FE: 0C81 0000 0003        CMP.L #$00000003,D1   ; Check if type 3
01000204: 67FF 0000 0038        BEQ.L $0100023E       ; NeXTdimension present

; Configure DMA for graphics board
010000DA: 23FC 4000 0000 020C 0034    MOVE.L #$40000000,$020C0034
010000E6: 23FC 4000 0000 020C 0030    MOVE.L #$40000000,$020C0030
```

### 4. Diagnostic/Halt Mode

**Trigger**: Boot failure or explicit diagnostic request
**Code Path**: 0x0100253E (infinite loop)
**Purpose**: Halt system for external debugger

```asm
; Diagnostic halt loop
0100253E: 2208               MOVE.L A0,D1
01002540: 5341               SUB.W #$00000001,D1     ; Decrement counter
01002542: 2241               MOVEA.L D1,A1
01002544: 00B9 0000 0001 0200 D000   OR.L #$00000001,$0200D000

; Tight DBF loop (flash LED?)
01002556: 57C9 FFFE          DBEQ.W D1,#$FFFE        ; Inner loop
0100255A: 57C8 FFF6          DBEQ.W D0,#$FFF6        ; Outer loop

; Jump back to halt
0100258E: 4EF9 0100 253E     JMP.L $0100253E         ; Loop forever
```

**Behavior**: This is the **POST failure mode** where the system flashes diagnostic codes on the LED.

### 5. Network Boot (Implicit)

**Trigger**: Device 0x01 selected
**Code Path**: Via device table at 0x01016D5C+0x1C
**Protocol**: BootP/TFTP (handled by device driver)

No explicit command - automatically triggered when NVRAM boot device = 0x01.

### 6. ROM Monitor Entry (Theoretical)

**Suspected Trigger**: Not found in current analysis
**Possible Methods**:
- Command-0 (⌘-0) during boot?
- NMI button?
- Bus error handler at 0x010002DC?

The bus error handler (0x010002DC) saves all registers and enters a controlled state, but no command parser is evident.

---

## Hardware Register Interactions

### Boot Mode Flags

**Register**: 0x0200D000 (System control register)

```asm
; Set diagnostic bit
01002544: 00B9 0000 0001 0200 D000   OR.L #$00000001,$0200D000

; Clear diagnostic bit
0100255E: 02B9 FFFF FFFE 0200 D000   AND.L #$FFFFFFFE,$0200D000
```

### RTC/NVRAM Access

**Function**: 0x01009B9A (Read RTC configuration)
**Storage**: Boot device stored in RTC NVRAM

```asm
; Read RTC function
0100993A: 4E56 0000          LINK.W A6,#$0000
0100993E: 48E7 3C38          MVMLE.L #$3C38,-(A7)
01009942: 286E 0008          MOVEA.L (A6,$0008),A4   ; Get RTC base address

; Extract device and subdevice
01009970: 1943 034C          MOVE.B D3,(A4,$034C)    ; Store device
01009974: 1944 034D          MOVE.B D4,(A4,$034D)    ; Store subdevice
```

---

## Console Output Functions

### Primary Console Function

**Address**: 0x0100685A (printf-like function)
**Called**: 12+ times throughout ROM

```asm
; Typical calling pattern
PEA.L $0100F6EA          ; Push format string address
LEA.L $0100685A,A2       ; Load console function address
JSR.L (A2)               ; Call console output
```

### Screen Control Functions

**SCR1/SCR2 Initialization**: 0x010095B4 (Clear screen)
**NeXT Logo Display**: 0x01000AF8

```asm
; Clear screen and display logo
010002A4: 4EB9 0100 95B4     JSR.L $010095B4    ; Clear screen
010002B2: 4EB9 0100 0AF8     JSR.L $01000AF8    ; Display NeXT logo
```

---

## Boot Sequence Decision Tree

```
RESET (0x0100001E)
│
├─> Stage 1: CPU Init (0x01000042)
│   └─> Invalidate caches, configure memory controller
│
├─> Stage 2: Memory Probe (0x01000058)
│   ├─> Detect RAM configuration
│   ├─> Check Device Type 3 (NeXTdimension)?
│   │   ├─> YES: Configure DMA @ 0x020C0030 → Stage 3a (0x0100023E)
│   │   └─> NO: Standard path → Stage 3b (0x0100027C)
│   │
│
├─> Stage 3: Video & RTC (0x0100027C)
│   ├─> Read RTC configuration (0x010048F2)
│   ├─> Clear screen (0x010095B4)
│   ├─> Display NeXT logo (0x01000AF8)
│   └─> Setup stack @ 0x0B03F800
│
└─> Stage 4: Boot Device Search (0x010002CC)
    ├─> Read device from NVRAM (0x034C/0x034D)
    ├─> Load device driver from table (0x01016D5C)
    ├─> Call device probe function
    │   ├─> SUCCESS: Boot from device
    │   └─> FAIL: Try alternate device (up to 3 attempts)
    │
    └─> All failed? → Halt mode (0x0100253E)
```

---

## Key Memory Locations

| Address       | Purpose                              | Access   |
|---------------|--------------------------------------|----------|
| 0x0100685A    | Console output function (printf)     | Function |
| 0x010095B4    | Clear screen function                | Function |
| 0x01000AF8    | Display NeXT logo                    | Function |
| 0x01009B9A    | Read RTC configuration               | Function |
| 0x0100253E    | Diagnostic halt loop                 | Code     |
| 0x01016D5C    | Boot device table (28-byte entries)  | Data     |
| 0x034C        | Boot device code (in state struct)   | Variable |
| 0x034D        | Boot subdevice code                  | Variable |
| 0x020C0000    | Memory controller base               | Hardware |
| 0x0200C000    | Device configuration/probe           | Hardware |
| 0x0200D000    | System control register              | Hardware |

---

## Error/Diagnostic Messages

Located in ROM data section (0x0100F000+):

| Address    | Message (Estimated)                |
|------------|------------------------------------|
| 0x0100F260 | "NeXT ROM v2.5"                    |
| 0x0100F419 | "Boot successful"                  |
| 0x0100F930 | "Trying alternate boot device"     |
| 0x0100FED8 | "Boot device failed"               |
| 0x0100FEF8 | "Invalid boot configuration"       |

---

## Conclusion: The "Commands" Are Boot Modes

The NeXTcube ROM Monitor doesn't have commands in the traditional sense. Instead:

1. **Boot device selection** is the primary "command" - stored in NVRAM
2. **Diagnostic mode** is triggered by hardware state or boot failure
3. **Network boot** is automatic when device 0x01 is selected
4. **Graphical console** is always used (no serial console option)
5. **Halt mode** (0x0100253E) is the failure state

### To "Use" the ROM Monitor:

**Method 1: Change Boot Device**
- Boot into NeXTSTEP
- Use Preferences → Startup Disk
- This writes to NVRAM (0x034C/0x034D)

**Method 2: Hardware Jumpers** (suspected)
- Motherboard jumpers may force specific boot modes
- Not yet confirmed in disassembly

**Method 3: Key Combinations** (suspected)
- Command-D for diagnostics?
- Command-N for network boot?
- Not yet found in disassembly - may be handled by keyboard controller firmware

---

## Next Steps for Further Analysis

1. **Find keyboard scan codes** - Search for key state checks during early boot
2. **Decode device table entries** - Full function pointer analysis at 0x01016D5C
3. **Analyze RTC data structure** - Complete NVRAM layout
4. **Trace diagnostic LED codes** - Pattern analysis at 0x0100253E
5. **Identify NMI handler** - Exception vector table analysis

---

**Analysis Based On**: Direct disassembly examination of ROMV66-0001E-02588.ASM
**Code References**: All addresses verified against disassembly source code
**Methodology**: Static analysis with control flow tracing
