# NeXTcube ROM v3.3 - Data Sections and Strings

**Date**: 2025-11-12
**ROM**: Rev_3.3_v74.bin (128KB)
**Extracted by**: Automated Python analysis

---

## Summary

- **Total strings found**: 472 (8+ characters)
- **ROM Monitor commands**: 24
- **Device names**: 47
- **Error messages**: 25
- **Boot messages**: 0
- **Hardware config strings**: 37
- **Interrupt names**: 6
- **Test messages**: 12
- **Potential jump tables**: 1120

---

## ROM Monitor Commands and Help Strings

| Offset (Ghidra) | Offset (NeXT) | String |
|----------------|---------------|--------|
| 0x00012F79 | 0x01012F79 | `boot command` |
| 0x00013016 | 0x01013016 | `allow any ROM command even if password protected` |
| 0x00013047 | 0x01013047 | `allow boot from any device even if password protected` |
| 0x0001356B | 0x0101356B | `No default boot command.` |
| 0x0001361D | 0x0101361D | `Retype new password: ` |
| 0x00013794 | 0x01013794 | `usage error, type "?" for help` |
| 0x00013854 | 0x01013854 | `DRAM error type %d` |
| 0x00013D50 | 0x01013D50 | `Boot command: %s` |
| 0x00013D62 | 0x01013D62 | `Default boot device not found.` |
| 0x00013D8D | 0x01013D8D | `boot %s%s%s` |
| 0x00013DA6 | 0x01013DA6 | `Usage: b [device[(ctrl,unit,part)] [filename] [flags]]` |
| 0x00013DDE | 0x01013DDE | `boot devices:` |
| 0x00013E0E | 0x01013E0E | `Booting %s from %s` |
| 0x00013E58 | 0x01013E58 | `Requesting BOOTP information` |
| 0x00013F3D | 0x01013F3D | `Error during boot` |
| 0x00013FF9 | 0x01013FF9 | `SCSI command phase` |
| 0x000140AE | 0x010140AE | `booting SCSI target %d, lun %d` |
| 0x000141A0 | 0x010141A0 | `Driver refused command` |
| 0x00014219 | 0x01014219 | `No bootfile in label` |
| 0x0001424B | 0x0101424B | `Can't load blk0 boot` |
| 0x0001452D | 0x0101452D | `fc_send_cmd: Error sending command bytes  (%d)` |
| 0x00014CD8 | 0x01014CD8 | `NeXT ROM monitor commands:` |
| 0x00014EC1 | 0x01014EC1 | `b [device[(ctrl,unit,part)] [filename] [flags]]  boot from device` |
| 0x00014FD5 | 0x01014FD5 | `Examine command, with no arguments, uses last [alist].` |

---

## Device and Peripheral Names

| Offset (Ghidra) | Offset (NeXT) | Device Name |
|----------------|---------------|-------------|
| 0x00012C7B | 0x01012C7B | `enetTXDMA` |
| 0x00012C85 | 0x01012C85 | `enetRXDMA` |
| 0x00012C97 | 0x01012C97 | `opticalDMA` |
| 0x00012CA2 | 0x01012CA2 | `printerDMA` |
| 0x00012CAD | 0x01012CAD | `soundoutDMA` |
| 0x00012CB9 | 0x01012CB9 | `soundinDMA` |
| 0x00012D13 | 0x01012D13 | `soundrun` |
| 0x00012E2F | 0x01012E2F | `enetTXDMA` |
| 0x00012E39 | 0x01012E39 | `enetRXDMA` |
| 0x00012E4B | 0x01012E4B | `printerDMA` |
| 0x00012E56 | 0x01012E56 | `soundoutDMA` |
| 0x00012E62 | 0x01012E62 | `soundinDMA` |
| 0x00012EA5 | 0x01012EA5 | `soundrun` |
| 0x00012FAF | 0x01012FAF | `sound out tests` |
| 0x00012FC0 | 0x01012FC0 | `SCSI tests` |
| 0x0001307D | 0x0101307D | `allow optical drive #0 eject even if password protected` |
| 0x00013385 | 0x01013385 | `Ethernet address: %x:%x:%x:%x:%x:%x` |
| 0x000137EF | 0x010137EF | `There must be a disk inserted in drive #0 before you can set this option` |
| 0x00013AAF | 0x01013AAF | `SCSI DMA intr?` |
| 0x00013ABF | 0x01013ABF | `Sound Out Over Run Interrupt.` |
| 0x00013ADF | 0x01013ADF | `Sound Out DMA error!` |
| 0x00013B3D | 0x01013B3D | `, Sound Out` |
| 0x00013B6B | 0x01013B6B | `Extended SCSI Test` |
| 0x00013C56 | 0x01013C56 | `disk ...` |
| 0x00013CD4 | 0x01013CD4 | `Ethernet (try thin interface first)` |
| 0x00013CFB | 0x01013CFB | `Ethernet (try twisted pair interface first)` |
| 0x00013D2A | 0x01013D2A | `SCSI disk` |
| 0x00013D37 | 0x01013D37 | `Optical disk` |
| 0x00013D44 | 0x01013D44 | `Floppy disk` |
| 0x0001400C | 0x0101400C | `SCSI bad i/o direction` |
| 0x00014023 | 0x01014023 | `SCSI msgout phase` |
| 0x0001404C | 0x0101404C | `SCSI unexpected msg:%d` |
| 0x00014091 | 0x01014091 | `SCSI Bus Hung` |
| 0x000140A0 | 0x010140A0 | `no SCSI disk` |
| 0x000141CE | 0x010141CE | `dma_cleanup: negative resid` |
| 0x000141EA | 0x010141EA | `dma_start: bad DMA buffer alignment` |
| 0x000142CE | 0x010142CE | `no disk inserted` |
| 0x00014307 | 0x01014307 | `no optical disk` |
| 0x00014318 | 0x01014318 | `no valid disk label found` |
| 0x000143D5 | 0x010143D5 | `No Floppy Disk Drive` |
| 0x000143EB | 0x010143EB | `No Floppy Disk Present` |
| 0x00014403 | 0x01014403 | `Floppy Disk not Formatted` |
| 0x0001441E | 0x0101441E | `Unknown Floppy Disk error (%d)` |
| 0x0001443E | 0x0101443E | `Floppy Disk not Initialized` |
| 0x00014586 | 0x01014586 | `dma_bytes_moved: DMA buf overflow` |
| 0x00014E22 | 0x01014E22 | `ej [drive #]  eject optical disk (default = 0)` |
| 0x00014E67 | 0x01014E67 | `ef [drive #]  eject floppy disk (default = 0)` |

---

## Interrupt and Timer Names

| Offset (Ghidra) | Offset (NeXT) | Interrupt Name |
|----------------|---------------|----------------|
| 0x00012C5B | 0x01012C5B | `intrstat` |
| 0x00012C72 | 0x01012C72 | `systimer` |
| 0x00012D57 | 0x01012D57 | `intrmask` |
| 0x00012DE5 | 0x01012DE5 | `timeripl7` |
| 0x00012E26 | 0x01012E26 | `systimer` |
| 0x0001445B | 0x0101445B | `fd_intr: BOGUS fvp->state` |

---

## Error Messages

| Offset (Ghidra) | Offset (NeXT) | Error Message |
|----------------|---------------|---------------|
| 0x000132B0 | 0x010132B0 | `Main Memory Configuration Test Failed` |
| 0x000132D8 | 0x010132D8 | `Main Memory Test Failed` |
| 0x000132F7 | 0x010132F7 | `VRAM Memory Test Failed` |
| 0x00013526 | 0x01013526 | `System test failed.  Error code %x.` |
| 0x00013588 | 0x01013588 | `parity error: status 0x%x, address 0x%x, data 0x%x` |
| 0x00013712 | 0x01013712 | `Old error code: %x` |
| 0x00013725 | 0x01013725 | `Last error code: %x` |
| 0x00013894 | 0x01013894 | `Memory error at location: %x` |
| 0x00013BC8 | 0x01013BC8 | `Memory error at location: 0x%x` |
| 0x00013EBD | 0x01013EBD | `enreg_read failed ` |
| 0x00013ED1 | 0x01013ED1 | `enreg_write failed ` |
| 0x00013F72 | 0x01013F72 | `software error` |
| 0x00013F81 | 0x01013F81 | `parity error` |
| 0x00013F8E | 0x01013F8E | `selection failed` |
| 0x00013F9F | 0x01013F9F | `bus error` |
| 0x00013FE4 | 0x01013FE4 | `scintr program error` |
| 0x00014165 | 0x01014165 | `Failed, sense key: 0x%x` |
| 0x00014295 | 0x01014295 | `uncorrectable ECC error` |
| 0x000142DF | 0x010142DF | `PLL failed` |
| 0x00014379 | 0x01014379 | `(error #%d)` |
| 0x0001438F | 0x0101438F | `fd: RECALIBRATE FAILED` |
| 0x000143A7 | 0x010143A7 | `fd: CONTROLLER I/O ERROR` |
| 0x000143C1 | 0x010143C1 | `RECALIBRATE FAILED` |
| 0x0001455D | 0x0101455D | `fc_send_cmd: Error getting status bytes` |
| 0x00014DFB | 0x01014DFB | `ec  print recorded system error codes` |

---

## Hardware Configuration Strings

| Offset (Ghidra) | Offset (NeXT) | Configuration String |
|----------------|---------------|---------------------|
| 0x00012F86 | 0x01012F86 | `DRAM tests` |
| 0x000130B5 | 0x010130B5 | `enable parity checking if parity memory is present` |
| 0x000130FB | 0x010130FB | `16MB of nibble mode` |
| 0x0001310F | 0x0101310F | `4MB of nibble mode` |
| 0x00013122 | 0x01013122 | `1MB of nibble mode` |
| 0x0001313D | 0x0101313D | `16MB of page mode` |
| 0x0001314F | 0x0101314F | `4MB of page mode` |
| 0x00013160 | 0x01013160 | `1MB of page mode (illegal)` |
| 0x0001317B | 0x0101317B | `16MB of parity nibble mode` |
| 0x00013196 | 0x01013196 | `4MB of parity nibble mode` |
| 0x000131B0 | 0x010131B0 | `1MB of parity nibble mode` |
| 0x000131CA | 0x010131CA | `16MB of parity page mode` |
| 0x000131E3 | 0x010131E3 | `4MB of parity page mode` |
| 0x000131FB | 0x010131FB | `1MB of parity page mode (illegal)` |
| 0x0001321D | 0x0101321D | `32MB of page mode` |
| 0x0001322F | 0x0101322F | `8MB of page mode` |
| 0x00013240 | 0x01013240 | `2MB of page mode` |
| 0x00013251 | 0x01013251 | `32MB of parity page mode` |
| 0x0001326A | 0x0101326A | `8MB of parity page mode` |
| 0x00013282 | 0x01013282 | `2MB of parity page mode` |
| 0x0001335B | 0x0101335B | `%d MHz, memory %d nS` |
| 0x000133AA | 0x010133AA | `Warning: non-volatile memory is uninitialized.` |
| 0x000133DA | 0x010133DA | `Memory sockets %d-%d configured for %s SIMMs but have %s SIMMs installed.` |
| 0x00013425 | 0x01013425 | `Memory sockets %d and %d configured for %s SIMMs but have %s SIMMs installed.` |
| 0x0001347F | 0x0101347F | `Memory sockets %d and %d (%s) configured for %s SIMMs but have %s SIMMs installed.` |
| 0x000134D3 | 0x010134D3 | `Memory size %dMB` |
| 0x000134E4 | 0x010134E4 | `, parity enabled` |
| 0x000134F7 | 0x010134F7 | `can't continue without some working memory` |
| 0x00013657 | 0x01013657 | `Memory sockets %d-%d have %s SIMMs installed (0x%x-0x%x)` |
| 0x00013691 | 0x01013691 | `Memory sockets %d and %d have %s SIMMs installed (0x%x-0x%x)` |
| 0x000136CF | 0x010136CF | `Memory sockets %d and %d (%s) have %s SIMMs installed (0x%x-0x%x)` |
| 0x000138D0 | 0x010138D0 | `Coupling dependent memory fault!` |
| 0x000138F2 | 0x010138F2 | `One or more SIMM at memory bank %d is bad` |
| 0x0001395C | 0x0101395C | `All of the SIMMs must be parity SIMMs if you want parity to work.` |
| 0x000139CA | 0x010139CA | `One or both SIMMs in memory bank %d are bad` |
| 0x00014D3E | 0x01014D3E | `m  print memory configuration` |
| 0x00014DC3 | 0x01014DC3 | `e [lwb] [alist] [format]  examine memory location addr` |

---

## Test and Diagnostic Messages

| Offset (Ghidra) | Offset (NeXT) | Test Message |
|----------------|---------------|--------------|
| 0x00012F91 | 0x01012F91 | `perform power-on system test` |
| 0x00012FE1 | 0x01012FE1 | `verbose test mode` |
| 0x00013310 | 0x01013310 | `Secondary Cache ram Test Fail` |
| 0x00013330 | 0x01013330 | `Secondary Tag ram Test Fail` |
| 0x0001354D | 0x0101354D | `System test passed.` |
| 0x00013868 | 0x01013868 | `Check socket (0 is the first socket): ` |
| 0x0001399F | 0x0101399F | `Check socket (0 is the first socket): %d` |
| 0x00013AF5 | 0x01013AF5 | `Testing the FPU` |
| 0x00013B4B | 0x01013B4B | `Starting Extended Self Test...` |
| 0x00013B80 | 0x01013B80 | `Press and hold any key to exit self test` |
| 0x00013BAC | 0x01013BAC | `Cache RAM selftest failure` |
| 0x00013C2C | 0x01013C2C | `Cache tag selftest failure.` |

---

## Potential Jump Tables and Data Structures

Found 1120 potential jump tables:

### Table 1 @ 0x00002FE8
- **Entries**: 4
- **First addresses**:
  - `0x0101297C`
  - `0x01010101`
  - `0x01010101`
  - `0x01010101`

### Table 2 @ 0x00002FEC
- **Entries**: 4
- **First addresses**:
  - `0x0101297C`
  - `0x01010101`
  - `0x01010101`
  - `0x01010101`

### Table 3 @ 0x00002FF0
- **Entries**: 4
- **First addresses**:
  - `0x0101297C`
  - `0x01010101`
  - `0x01010101`
  - `0x01010101`

### Table 4 @ 0x00010618
- **Entries**: 4
- **First addresses**:
  - `0x010143D5`
  - `0x010143EB`
  - `0x01014403`
  - `0x0101441E`

### Table 5 @ 0x0001061C
- **Entries**: 4
- **First addresses**:
  - `0x010143D5`
  - `0x010143EB`
  - `0x01014403`
  - `0x0101441E`

### Table 6 @ 0x00011BE0
- **Entries**: 4
- **First addresses**:
  - `0x01000D6C`
  - `0x01000D64`
  - `0x01000D6C`
  - `0x01000D7A`

### Table 7 @ 0x00011BE4
- **Entries**: 5
- **First addresses**:
  - `0x01000D6C`
  - `0x01000D64`
  - `0x01000D6C`
  - `0x01000D7A`
  - `0x01000D96`

### Table 8 @ 0x00011BE8
- **Entries**: 6
- **First addresses**:
  - `0x01000D6C`
  - `0x01000D64`
  - `0x01000D6C`
  - `0x01000D7A`
  - `0x01000D96`
  - `0x01000D96`

### Table 9 @ 0x00011BEC
- **Entries**: 7
- **First addresses**:
  - `0x01000D6C`
  - `0x01000D64`
  - `0x01000D6C`
  - `0x01000D7A`
  - `0x01000D96`
  - `0x01000D96`
  - `0x01000D86`

### Table 10 @ 0x00011BF0
- **Entries**: 8
- **First addresses**:
  - `0x01000D6C`
  - `0x01000D64`
  - `0x01000D6C`
  - `0x01000D7A`
  - `0x01000D96`
  - `0x01000D96`
  - `0x01000D86`
  - `0x01000D86`

### Table 11 @ 0x00011BF4
- **Entries**: 8
- **First addresses**:
  - `0x01000D64`
  - `0x01000D6C`
  - `0x01000D7A`
  - `0x01000D96`
  - `0x01000D96`
  - `0x01000D86`
  - `0x01000D86`
  - `0x01000DBC`

### Table 12 @ 0x00011BF8
- **Entries**: 8
- **First addresses**:
  - `0x01000D6C`
  - `0x01000D7A`
  - `0x01000D96`
  - `0x01000D96`
  - `0x01000D86`
  - `0x01000D86`
  - `0x01000DBC`
  - `0x01000DBC`

### Table 13 @ 0x00011BFC
- **Entries**: 8
- **First addresses**:
  - `0x01000D7A`
  - `0x01000D96`
  - `0x01000D96`
  - `0x01000D86`
  - `0x01000D86`
  - `0x01000DBC`
  - `0x01000DBC`
  - `0x01000DAC`

### Table 14 @ 0x00011C00
- **Entries**: 8
- **First addresses**:
  - `0x01000D96`
  - `0x01000D96`
  - `0x01000D86`
  - `0x01000D86`
  - `0x01000DBC`
  - `0x01000DBC`
  - `0x01000DAC`
  - `0x01000DAC`

### Table 15 @ 0x00011C04
- **Entries**: 8
- **First addresses**:
  - `0x01000D96`
  - `0x01000D86`
  - `0x01000D86`
  - `0x01000DBC`
  - `0x01000DBC`
  - `0x01000DAC`
  - `0x01000DAC`
  - `0x01001D72`

### Table 16 @ 0x00011C08
- **Entries**: 8
- **First addresses**:
  - `0x01000D86`
  - `0x01000D86`
  - `0x01000DBC`
  - `0x01000DBC`
  - `0x01000DAC`
  - `0x01000DAC`
  - `0x01001D72`
  - `0x01001D72`

### Table 17 @ 0x00011C0C
- **Entries**: 8
- **First addresses**:
  - `0x01000D86`
  - `0x01000DBC`
  - `0x01000DBC`
  - `0x01000DAC`
  - `0x01000DAC`
  - `0x01001D72`
  - `0x01001D72`
  - `0x01001D50`

### Table 18 @ 0x00011C10
- **Entries**: 8
- **First addresses**:
  - `0x01000DBC`
  - `0x01000DBC`
  - `0x01000DAC`
  - `0x01000DAC`
  - `0x01001D72`
  - `0x01001D72`
  - `0x01001D50`
  - `0x01001D50`

### Table 19 @ 0x00011C14
- **Entries**: 8
- **First addresses**:
  - `0x01000DBC`
  - `0x01000DAC`
  - `0x01000DAC`
  - `0x01001D72`
  - `0x01001D72`
  - `0x01001D50`
  - `0x01001D50`
  - `0x01001D5E`

### Table 20 @ 0x00011C18
- **Entries**: 8
- **First addresses**:
  - `0x01000DAC`
  - `0x01000DAC`
  - `0x01001D72`
  - `0x01001D72`
  - `0x01001D50`
  - `0x01001D50`
  - `0x01001D5E`
  - `0x01001D5E`


---

## All Other Strings (Alphabetical)

| Offset (Ghidra) | Offset (NeXT) | String |
|----------------|---------------|--------|
| 0x0001B050 | 0x0101B050 | `          ` |
| 0x0001B045 | 0x0101B045 | `   @    ` |
| 0x00018400 | 0x01018400 | `  4c0S6d` |
| 0x00012004 | 0x01012004 | ` $'*-0257:<>@BDFGIKMNPQSTVWYZ\]^`abdefgijklmopqrstuvwyz{|}~` |
| 0x00014385 | 0x01014385 | ` %d:0:%d` |
| 0x0001859A | 0x0101859A | ` 0pW4Z`W]du` |
| 0x00003E02 | 0x01003E02 | ` <UUUU"<` |
| 0x00013E96 | 0x01013E96 | ` [timeout]` |
| 0x00007608 | 0x01007608 | ` JTJ"KTK0` |
| 0x00007624 | 0x01007624 | ` JXJ"KXK ` |
| 0x0001844D | 0x0101844D | ` UCpS)60x` |
| 0x0001843B | 0x0101843B | ` ZyBGc'0` |
| 0x0001822A | 0x0101822A | ` Zz Z z "I` |
| 0x00017D3D | 0x01017D3D | `!!L8Z!b!8!` |
| 0x00017BCE | 0x01017BCE | `!#XEPV,:5` |
| 0x00016E5A | 0x01016E5A | `!1rz$TI;LZ` |
| 0x00017C4A | 0x01017C4A | `!:ZV:V'5k"s!@F` |
| 0x00014AEF | 0x01014AEF | `!ddP<<FPd` |
| 0x00016CC0 | 0x01016CC0 | `!rO\l%VOJ'!&%` |
| 0x00018125 | 0x01018125 | `!Uo#wriT7YQX[iCwU!Uo#<` |
| 0x00005600 | 0x01005600 | `"^N^NuNV` |
| 0x00017C5C | 0x01017C5C | `"Fl$5lZ!:V{!AG#` |
| 0x00017C9A | 0x01017C9A | `"Vr$}w5kZY![]5x}V"SI$;` |
| 0x00015688 | 0x01015688 | `$)PFQ8Q:Q` |
| 0x00013E33 | 0x01013E33 | `%s(%d,%d,%d)%s` |
| 0x00016EAC | 0x01016EAC | `&%+o:Mr\z$V` |
| 0x00016E79 | 0x01016E79 | `&;rz$T@&;8` |
| 0x00016E6A | 0x01016E6A | `&Arz$TDEJ&!` |
| 0x00005F0C | 0x01005F0C | `&H$<UUUU`` |
| 0x00016CA5 | 0x01016CA5 | `&rMTg\l%VFNG*` |
| 0x00016F92 | 0x01016F92 | `'1rLz$LT@/1rLz$Mn/5Mz$WL['` |
| 0x00017B23 | 0x01017B23 | `'5lc7hZ)'j` |
| 0x0000F4C6 | 0x0100F4C6 | `'kBTB\.- ` |
| 0x00013D82 | 0x01013D82 | `(%d,%d,%d)` |
| 0x00016F7A | 0x01016F7A | `(?Lz$LV0\Lz$LV0\Lz$LT@'` |
| 0x0000F3BD | 0x0100F3BD | `(B(B{B(Bz/` |
| 0x00015EA9 | 0x01015EA9 | `)8F)8$PNQ` |
| 0x00015CE2 | 0x01015CE2 | `)=9J=F AJN` |
| 0x00016EA2 | 0x01016EA2 | `)l3EM\z$V` |
| 0x000189A8 | 0x010189A8 | `*\T+T;Su*({` |
| 0x00018970 | 0x01018970 | `*ZeBcXSu*({` |
| 0x000183C0 | 0x010183C0 | `+"Sj!Ce%!48}` |
| 0x00018998 | 0x01018998 | `+<I=;/*9{*({` |
| 0x00018059 | 0x01018059 | `+@3 "WDIU+83z"` |
| 0x00016EB9 | 0x01016EB9 | `+mMuV\z$V` |
| 0x00016EC7 | 0x01016EC7 | `+rL^T]z$V` |
| 0x00016ED1 | 0x01016ED1 | `+rwx\z$V` |
| 0x00013B2D | 0x01013B2D | `, Event Counter` |
| 0x0001898D | 0x0101898D | `,IcYSu*({` |
| 0x00017BDD | 0x01017BDD | `-5fV"8]}` |
| 0x00017B42 | 0x01017B42 | `.%UI$Fm($8;f"FlV ` |
| 0x0001B15F | 0x0101B15F | `.076/A8&` |
| 0x00004A24 | 0x01004A24 | `.:N^NuNV` |
| 0x0000F456 | 0x0100F456 | `0+B`7@Bb` |
| 0x0000F49E | 0x0100F49E | `0+Bb7@Bb +BTLE` |
| 0x00013EA2 | 0x01013EA2 | `0123456789abcdef` |
| 0x0001A890 | 0x0101A890 | `0123456789abcdef` |
| 0x0001856C | 0x0101856C | `0S.oQ`.p` |
| 0x00004D62 | 0x01004D62 | `0v(@&LHx` |
| 0x000189DC | 0x010189DC | `2WxWmX+2Su*({` |
| 0x00016E88 | 0x01016E88 | `3CLrz$T@'3B+h1:=Lrz$V` |
| 0x00017CEF | 0x01017CEF | `4vW2w@E2OZ` |
| 0x0001B13F | 0x0101B13F | `5BCDEGHJKLMOP` |
| 0x00016E39 | 0x01016E39 | `5Lz$LrM^a` |
| 0x00016E4A | 0x01016E4A | `5Lz$TCMVt!` |
| 0x000183AC | 0x010183AC | `6hH'#C0Vo)"0` |
| 0x0000F644 | 0x0100F644 | `7BBR7kB~Bt` |
| 0x00015BF4 | 0x01015BF4 | `7OPN)NM:JF` |
| 0x00017C39 | 0x01017C39 | `8At!EV!f)5f` |
| 0x000180F2 | 0x010180F2 | `8EG A"ce!6lhU ` |
| 0x0001B134 | 0x0101B134 | `9:;<@=1234` |
| 0x00018881 | 0x01018881 | `9{*(x]TW*/Bn` |
| 0x000188A1 | 0x010188A1 | `9{*(xtcWT/Bn` |
| 0x00017CDF | 0x01017CDF | `:3f53k53f53k!V2` |
| 0x0000FC61 | 0x0100FC61 | `:Bs`L7DBv ` |
| 0x00015E6D | 0x01015E6D | `:N()8F)8(F(N` |
| 0x00015E34 | 0x01015E34 | `:N4)8F)8)8` |
| 0x00015DFB | 0x01015DFB | `:NF)8F)8)8` |
| 0x00015D55 | 0x01015D55 | `:NF)FN)F5F(N` |
| 0x00015D8F | 0x01015D8F | `:P8)8F)8)8` |
| 0x00015DC4 | 0x01015DC4 | `:PA)8F)8)8` |
| 0x000184C8 | 0x010184C8 | `:WS6S$0c` |
| 0x000189CE | 0x010189CE | `< <E;*3*9{*({` |
| 0x000189B7 | 0x010189B7 | `<E/-9{*({` |
| 0x000159E6 | 0x010159E6 | `=:EP8784` |
| 0x000189EB | 0x010189EB | `=Bq?*9{*({` |
| 0x00018494 | 0x01018494 | `>+Ui1b:06*0` |
| 0x00018047 | 0x01018047 | `? "[zEwU)3{X "869` |
| 0x00016E15 | 0x01016E15 | `?Lz$L^T^d` |
| 0x00003CE9 | 0x01003CE9 | `@"<UUUUI` |
| 0x00014F8C | 0x01014F8C | `[alist] is starting address or list of addresses to cycli...` |
| 0x00014F56 | 0x01014F56 | `[lwb] select long/word/byte length (default = long).` |
| 0x00016FB5 | 0x01016FB5 | `\/VT}z$a` |
| 0x00016CB7 | 0x01016CB7 | `\l%VOG(!` |
| 0x00016DF0 | 0x01016DF0 | `\Lz$LW^d` |
| 0x00016F0E | 0x01016F0E | `\z$V(:8+rVw\z$V&DB+rLT_}z$T<=J+o=Murz$T3CEIB+mCNrz$T;KLJ+...` |
| 0x00017B92 | 0x01017B92 | `]g"#Ag:l` |
| 0x00018BFD | 0x01018BFD | `_{*(xZ[Z` |
| 0x00018559 | 0x01018559 | ``#WD/`8/cC/`8/c6S.` |
| 0x000184BD | 0x010184BD | ``&0`0hx?6x` |
| 0x0000FDFF | 0x0100FDFF | ``BjBjBjBhHx` |
| 0x00014D20 | 0x01014D20 | `a [n]  open address register` |
| 0x00005D5A | 0x01005D5A | `a&"<UUUUa` |
| 0x00018AF0 | 0x01018AF0 | `a<;/2n}{` |
| 0x00013371 | 0x01013371 | `Backplane slot #%d` |
| 0x00014273 | 0x01014273 | `Bad blkno` |
| 0x0001427E | 0x0101427E | `Bad cksum` |
| 0x000144C6 | 0x010144C6 | `Bad Controller Phase` |
| 0x00014333 | 0x01014333 | `bad ctrl or unit number` |
| 0x00014114 | 0x01014114 | `bad dev blk size %d` |
| 0x0001420E | 0x0101420E | `Bad label` |
| 0x00014261 | 0x01014261 | `Bad version 0x%x` |
| 0x0001393D | 0x0101393D | `Bank %d has mixed mode SIMM's` |
| 0x000139F7 | 0x010139F7 | `Bank %d has mixed size SIMMs.` |
| 0x0000FDF0 | 0x0100FDF0 | `BjBjBjBhBjBf`` |
| 0x000135BC | 0x010135BC | `bogus stack frame` |
| 0x0001823A | 0x0101823A | `B~BXz #w` |
| 0x00014E96 | 0x01014E96 | `c  continue execution at last pc location` |
| 0x000180CD | 0x010180CD | `c(3c 9z=` |
| 0x0001B340 | 0x0101B340 | `Canon OMD-1` |
| 0x0001800D | 0x0101800D | `cEi8""7n3U` |
| 0x000144DB | 0x010144DB | `Controller hang` |
| 0x0001500C | 0x0101500C | `Copyright (c) 1988-1990 NeXT Inc.` |
| 0x0001334E | 0x0101334E | `CPU MC68040 ` |
| 0x00018853 | 0x01018853 | `cSu*(t<H+Weu` |
| 0x00018870 | 0x01018870 | `cSu*(tAU+2eu` |
| 0x00014D5D | 0x01014D5D | `d [n]  open data register` |
| 0x00013751 | 0x01013751 | `default input radix %d` |
| 0x0001422F | 0x0101422F | `dev blk len %d, fs sect %d` |
| 0x000140CE | 0x010140CE | `dev blk len?` |
| 0x00013D9A | 0x01013D9A | `diagnostics` |
| 0x00013F4F | 0x01013F4F | `Didn't complete` |
| 0x00010240 | 0x01010240 | `dlV3f(2<` |
| 0x00018525 | 0x01018525 | `dqp OZ!:` |
| 0x00012D9E | 0x01012D9E | `DSPblock` |
| 0x00012F10 | 0x01012F10 | `DSPblock` |
| 0x00012F69 | 0x01012F69 | `DSPmemen` |
| 0x00012D95 | 0x01012D95 | `DSPreset` |
| 0x00012F07 | 0x01012F07 | `DSPreset` |
| 0x00012F41 | 0x01012F41 | `DSPtxdint` |
| 0x00018843 | 0x01018843 | `e9{*({W]*/Be` |
| 0x00018982 | 0x01018982 | `ea>9{*({` |
| 0x000181BF | 0x010181BF | `ejmiz  Og` |
| 0x00013EEA | 0x01013EEA | `en_write: tx not ready` |
| 0x00014E52 | 0x01014E52 | `eo  (same as above)` |
| 0x00018B1B | 0x01018B1B | `epu*(tCsWT4en` |
| 0x000175B3 | 0x010175B3 | `eUT@UUUUUU` |
| 0x000135CF | 0x010135CF | `Exception #%d (0x%x) at pc 0x%x sp 0x%x` |
| 0x00013C08 | 0x01013C08 | `Expected: 0x%x     Received: 0x%x` |
| 0x00017C29 | 0x01017C29 | `f,8Ft9@!` |
| 0x00018822 | 0x01018822 | `f9{*)osW` |
| 0x00017B77 | 0x01017B77 | `f:!E:pxwJ` |
| 0x0000F464 | 0x0100F464 | `f` +BTLE` |
| 0x00018A09 | 0x01018A09 | `fa=9{*({` |
| 0x000189F8 | 0x010189F8 | `faqeYSu*({` |
| 0x000135F8 | 0x010135F8 | `faultaddr 0x%x` |
| 0x000144EB | 0x010144EB | `fc: Controller Reset: %s` |
| 0x00014498 | 0x01014498 | `fd%d: Sector %d(d) cmd = %s; status = %d: %s` |
| 0x00014505 | 0x01014505 | `fd: Bogus density (%d) in fc_specify()` |
| 0x0001758F | 0x0101758F | `ffUDUUUUUU` |
| 0x00013FB8 | 0x01013FB8 | `fifo level` |
| 0x00017FC1 | 0x01017FC1 | `FJ+$3U9L,$DFh-$Uv#Ej'#6` |
| 0x00013CC9 | 0x01013CC9 | `floppy ...` |
| 0x0001825A | 0x0101825A | `ftiz %X_[Fr` |
| 0x0001373A | 0x0101373A | `Function code %d (%s)` |
| 0x00018961 | 0x01018961 | `fZe<9{*({` |
| 0x00009DDF | 0x01009DDF | `H`6 IXI ` |
| 0x00017FEF | 0x01017FEF | `i##[c i 8iUkcD c""3Fc8` |
| 0x00018101 | 0x01018101 | `imU Um"Eih ` |
| 0x00018C99 | 0x01018C99 | `i{*+#iu*+(i{*+0` |
| 0x0001801E | 0x0101801E | `jd!"@qc8c` |
| 0x0001756B | 0x0101756B | `jffTUUUUUU` |
| 0x0000DBCF | 0x0100DBCF | `jXO`6Hx'` |
| 0x00018C85 | 0x01018C85 | `j{**#ju**(j{**)ju*+` |
| 0x000159F6 | 0x010159F6 | `K F 4(IK` |
| 0x00015A33 | 0x01015A33 | `K JANFJQF8%3` |
| 0x00002C4C | 0x01002C4C | `K(N^NuNqNV` |
| 0x0000F739 | 0x0100F739 | `kBb7@B`o.0+BbH` |
| 0x00012D34 | 0x01012D34 | `kybd/mouse` |
| 0x00012EBD | 0x01012EBD | `kybd/mouse` |
| 0x00018BCA | 0x01018BCA | `L _u*(y:` |
| 0x00012FCC | 0x01012FCC | `loop until keypress` |
| 0x00018C07 | 0x01018C07 | `lu{~) tSu*({<yA` |
| 0x00016E28 | 0x01016E28 | `Lz$Lr\Vx` |
| 0x00017B81 | 0x01017B81 | `m5:##785V:k_` |
| 0x00015A70 | 0x01015A70 | `M:JFJQN8 KF` |
| 0x000142BC | 0x010142BC | `media upside down` |
| 0x00012DDC | 0x01012DDC | `mem1M/4M` |
| 0x00012DD0 | 0x01012DD0 | `mem256K/4M` |
| 0x00013633 | 0x01013633 | `Mismatch - password unchanged` |
| 0x00017B54 | 0x01017B54 | `mk%$@q"lV!A@` |
| 0x00016C7B | 0x01016C7B | `Ml-rO^&&` |
| 0x00018068 | 0x01018068 | `mn,3cU!6` |
| 0x00013FD3 | 0x01013FD3 | `msgin fifo level` |
| 0x000137CC | 0x010137CC | `must be < %d chars long` |
| 0x00007E06 | 0x01007E06 | `N^NuNq /` |
| 0x0000262A | 0x0100262A | `N^NuNqNV` |
| 0x000032DA | 0x010032DA | `N^NuNqNV` |
| 0x00004202 | 0x01004202 | `N^NuNqNV` |
| 0x000069C6 | 0x010069C6 | `N^NuNqNV` |
| 0x0000747A | 0x0100747A | `N^NuNqNV` |
| 0x00007B56 | 0x01007B56 | `N^NuNqNV` |
| 0x00007CA2 | 0x01007CA2 | `N^NuNqNV` |
| 0x00008896 | 0x01008896 | `N^NuNqNV` |
| 0x00008D6E | 0x01008D6E | `N^NuNqNV` |
| 0x0000B7BA | 0x0100B7BA | `N^NuNqNV` |
| 0x0000C1AE | 0x0100C1AE | `N^NuNqNV` |
| 0x0000D9AE | 0x0100D9AE | `N^NuNqNV` |
| 0x00016FF4 | 0x01016FF4 | `Nc@+1cNWz&6cMTq+>rMX&&#sNc@)1cN\x&&#sNTr)TrN\x&%` |
| 0x00013CA4 | 0x01013CA4 | `network ...` |
| 0x0001360E | 0x0101360E | `New password: ` |
| 0x00013F0B | 0x01013F0B | `NeXT ROM Monitor %d.%d (v%d)` |
| 0x0001894F | 0x0101894F | `nfacSu*({` |
| 0x0001391D | 0x0101391D | `Note: bank 0 is the first bank` |
| 0x000159B4 | 0x010159B4 | `NPN)R7O7O)NF7+ 8` |
| 0x00004838 | 0x01004838 | `NsN^NuNV` |
| 0x000068CC | 0x010068CC | `NsN^NuNV` |
| 0x00009110 | 0x01009110 | `NsN^NuNV` |
| 0x00016D1D | 0x01016D1D | `O\Y#VNTp` |
| 0x00014365 | 0x01014365 | `od%d%c: %s %s ` |
| 0x0001ADEC | 0x0101ADEC | `p      p` |
| 0x00014CF4 | 0x01014CF4 | `p  inspect/modify configuration parameters` |
| 0x00015AA9 | 0x01015AA9 | `P-8G"87A` |
| 0x00015EE5 | 0x01015EE5 | `P8F)8$)FJN` |
| 0x00015D11 | 0x01015D11 | `P@PJP<L)POP:N$)EMPENPNQ` |
| 0x00015E9C | 0x01015E9C | `P@PJPG)PN` |
| 0x00013782 | 0x01013782 | `Password: ` |
| 0x00015671 | 0x01015671 | `PNQ:S:Q$` |
| 0x00018ADC | 0x01018ADC | `pu*(utcX*e{` |
| 0x00018BAB | 0x01018BAB | `Q_u*(r=A` |
| 0x00016D74 | 0x01016D74 | `qA5Nz$MT_J!` |
| 0x00015BE3 | 0x01015BE3 | `QJP8)POPK` |
| 0x00016D4A | 0x01016D4A | `qTrMdz$NVrJ` |
| 0x00014F33 | 0x01014F33 | `R [radix]  set input radix` |
| 0x00014D78 | 0x01014D78 | `r [regname]  open processor register` |
| 0x00016D81 | 0x01016D81 | `r91rMz$MV` |
| 0x00016D66 | 0x01016D66 | `r9?Nz$NvJ` |
| 0x00016D59 | 0x01016D59 | `rC\Nz$N^\p!` |
| 0x00016D3B | 0x01016D3B | `rcN\Y$NTuJ!` |
| 0x000140DC | 0x010140DC | `READ CAPACITY` |
| 0x00013F29 | 0x01013F29 | `really power down? ` |
| 0x0001447B | 0x0101447B | `RECALIBRATE` |
| 0x000140EA | 0x010140EA | `REQ SENSE` |
| 0x00017BA0 | 0x01017BA0 | `rl:"#Au!l` |
| 0x00016C97 | 0x01016C97 | `rMTy\l%Va` |
| 0x00016CE6 | 0x01016CE6 | `rO\l#VOJ` |
| 0x00016CD9 | 0x01016CD9 | `rO\l%VOJ&"%` |
| 0x00016CCE | 0x01016CCE | `rO\l%VOJ(` |
| 0x00016D0F | 0x01016D0F | `rO\Y#VOa&` |
| 0x00016D01 | 0x01016D01 | `rO\Y#VOJ%&` |
| 0x00016CF3 | 0x01016CF3 | `rO\Y#VOJ&` |
| 0x00016F5E | 0x01016F5E | `rz$Ln05Lz$Ln05Lz$L[0?Lz$L[(` |
| 0x00014F04 | 0x01014F04 | `S [fcode]  open function code (address space)` |
| 0x00014D9E | 0x01014D9E | `s [systemreg]  open system register` |
| 0x00018589 | 0x01018589 | `s)0Z>?S6dk` |
| 0x00014035 | 0x01014035 | `scmsgin: no current sd` |
| 0x00014073 | 0x01014073 | `scmsgin: no FUNCCMPLT` |
| 0x00013F5F | 0x01013F5F | `scstart: bad state` |
| 0x0001412E | 0x0101412E | `sdcmd bad state: %d` |
| 0x000141B8 | 0x010141B8 | `sdfail bad state: %d` |
| 0x000142AD | 0x010142AD | `sector timeout` |
| 0x00014148 | 0x01014148 | `Selection timeout on target` |
| 0x00012FF3 | 0x01012FF3 | `serial port A is alternate console` |
| 0x00014289 | 0x01014289 | `short read` |
| 0x00012D4E | 0x01012D4E | `softint1` |
| 0x00012DC6 | 0x01012DC6 | `softint1` |
| 0x00012ED5 | 0x01012ED5 | `softint1` |
| 0x00012F38 | 0x01012F38 | `softint1` |
| 0x00012D45 | 0x01012D45 | `softint2` |
| 0x00012DBD | 0x01012DBD | `softint2` |
| 0x00012ECC | 0x01012ECC | `softint2` |
| 0x00012F2F | 0x01012F2F | `softint2` |
| 0x0001B3D4 | 0x0101B3D4 | `Sony MPX-111N` |
| 0x0001888E | 0x0101888E | `sSu*(tIa;*2eu` |
| 0x000132A5 | 0x010132A5 | `system ...` |
| 0x00017B30 | 0x01017B30 | `t*&F!Gt,%5VlM-%D` |
| 0x00013FA9 | 0x01013FA9 | `target aborted` |
| 0x00013FC3 | 0x01013FC3 | `target aborted2` |
| 0x0001417E | 0x0101417E | `Target busy` |
| 0x0001418B | 0x0101418B | `Target disconnected` |
| 0x00013E29 | 0x01013E29 | `tftp: %s` |
| 0x00013E49 | 0x01013E49 | `tftp: timeout` |
| 0x00002C31 | 0x01002C31 | `TN^NuNqNV` |
| 0x000155AF | 0x010155AF | `U!U&U-U@V` |
| 0x00018B3E | 0x01018B3E | `u*(tl{W*Ze` |
| 0x000188F0 | 0x010188F0 | `u*(yufa<2[{` |
| 0x00018A7E | 0x01018A7E | `u*(yvfWGUy` |
| 0x00018A5E | 0x01018A5E | `u*({wed<|` |
| 0x00018091 | 0x01018091 | `U-c] ?[wcU-UG UE|h?-Wn4m<e8,39n4G5z c+6` |
| 0x00018173 | 0x01018173 | `U0z2gV0e?D0EX30Ec c/9c U 9` |
| 0x00015FE3 | 0x01015FE3 | `UFUGUHUIUJUKULUMUNUOUPUQURUSUTUUUVUWUXUYU^U_U`UlV` |
| 0x0001863F | 0x0101863F | `Ufzaeh?x` |
| 0x00014064 | 0x01014064 | `Unexpected msg` |
| 0x0001890F | 0x0101890F | `unfpu*({vtf;ey` |
| 0x0001892F | 0x0101892F | `ung_u*({y` |
| 0x00013DF7 | 0x01013DF7 | `unknown binary format` |
| 0x00018AF9 | 0x01018AF9 | `upu*(tC`WT2eo` |
| 0x00003548 | 0x01003548 | `UUUU!|UUUU` |
| 0x00017C03 | 0x01017C03 | `V.b^!@]}fV.VH!QF` |
| 0x00016FBE | 0x01016FBE | `V@.1\Tgz$FLTH&` |
| 0x000138B2 | 0x010138B2 | `Value at time of failure: %x` |
| 0x00013BE8 | 0x01013BE8 | `Value at time of failure: 0x%x` |
| 0x00013A17 | 0x01013A17 | `VRAM failure at 0x%x:  read 0x%08x, expected 0x%08x, bad ...` |
| 0x00013A63 | 0x01013A63 | `VRAM failure at 0x%x:  read 0x%08x, expected 0x%08x, bad ...` |
| 0x000189C4 | 0x010189C4 | `W\.(u*({` |
| 0x000140F4 | 0x010140F4 | `waiting for drive to come ready` |
| 0x00018247 | 0x01018247 | `Wk{ejm@z #3` |
| 0x000188CF | 0x010188CF | `wSu*(ug<*2l{` |
| 0x00018071 | 0x01018071 | `w}-Xq!@ ` |
| 0x00003166 | 0x01003166 | `XO$EQJ K`` |
| 0x00003480 | 0x01003480 | `XO$EQJ K`` |
| 0x00018860 | 0x01018860 | `ye9{*({W` |
| 0x000180D6 | 0x010180D6 | `z <Q 8U&3h [< ? U 5z!Ei#3iX` |
| 0x00016FD2 | 0x01016FD2 | `z$Nq.>Nz$N\.VNz$NV@-1}Nz$NTq->Oz$` |
| 0x00016C88 | 0x01016C88 | `z+rN{^&%Vd` |
| 0x00018C6D | 0x01018C6D | `{*(ku*(k{*(ku*(k{*)ku**` |
| 0x000188E0 | 0x010188E0 | `{*({nfX/B` |
| 0x00018149 | 0x01018149 | `{kUmswi#Uo%F` |
| 0x00018C49 | 0x01018C49 | `{tWSu*({` |
| 0x00017FD9 | 0x01017FD9 | `}!EiR!jh$#>:!iU ` |
| 0x00017034 | 0x01017034 | `}Qz2Sz2rRz&` |

---

## Complete String List (By Offset)

All strings extracted from ROM, sorted by offset:

| Offset (Ghidra) | Offset (NeXT) | Length | String |
|----------------|---------------|--------|--------|
| 0x0000262A | 0x0100262A | 8 | `N^NuNqNV` |
| 0x00002C31 | 0x01002C31 | 9 | `TN^NuNqNV` |
| 0x00002C4C | 0x01002C4C | 10 | `K(N^NuNqNV` |
| 0x00003166 | 0x01003166 | 9 | `XO$EQJ K`` |
| 0x000032DA | 0x010032DA | 8 | `N^NuNqNV` |
| 0x00003480 | 0x01003480 | 9 | `XO$EQJ K`` |
| 0x00003548 | 0x01003548 | 10 | `UUUU!|UUUU` |
| 0x00003CE9 | 0x01003CE9 | 8 | `@"<UUUUI` |
| 0x00003E02 | 0x01003E02 | 8 | ` <UUUU"<` |
| 0x00004202 | 0x01004202 | 8 | `N^NuNqNV` |
| 0x00004838 | 0x01004838 | 8 | `NsN^NuNV` |
| 0x00004A24 | 0x01004A24 | 8 | `.:N^NuNV` |
| 0x00004D62 | 0x01004D62 | 8 | `0v(@&LHx` |
| 0x00005600 | 0x01005600 | 8 | `"^N^NuNV` |
| 0x00005D5A | 0x01005D5A | 9 | `a&"<UUUUa` |
| 0x00005F0C | 0x01005F0C | 9 | `&H$<UUUU`` |
| 0x000068CC | 0x010068CC | 8 | `NsN^NuNV` |
| 0x000069C6 | 0x010069C6 | 8 | `N^NuNqNV` |
| 0x0000747A | 0x0100747A | 8 | `N^NuNqNV` |
| 0x00007608 | 0x01007608 | 9 | ` JTJ"KTK0` |
| 0x00007624 | 0x01007624 | 9 | ` JXJ"KXK ` |
| 0x00007B56 | 0x01007B56 | 8 | `N^NuNqNV` |
| 0x00007CA2 | 0x01007CA2 | 8 | `N^NuNqNV` |
| 0x00007E06 | 0x01007E06 | 8 | `N^NuNq /` |
| 0x00008896 | 0x01008896 | 8 | `N^NuNqNV` |
| 0x00008D6E | 0x01008D6E | 8 | `N^NuNqNV` |
| 0x00009110 | 0x01009110 | 8 | `NsN^NuNV` |
| 0x00009DDF | 0x01009DDF | 8 | `H`6 IXI ` |
| 0x0000B7BA | 0x0100B7BA | 8 | `N^NuNqNV` |
| 0x0000C1AE | 0x0100C1AE | 8 | `N^NuNqNV` |
| 0x0000D9AE | 0x0100D9AE | 8 | `N^NuNqNV` |
| 0x0000DBCF | 0x0100DBCF | 8 | `jXO`6Hx'` |
| 0x0000F3BD | 0x0100F3BD | 10 | `(B(B{B(Bz/` |
| 0x0000F456 | 0x0100F456 | 8 | `0+B`7@Bb` |
| 0x0000F464 | 0x0100F464 | 8 | `f` +BTLE` |
| 0x0000F49E | 0x0100F49E | 14 | `0+Bb7@Bb +BTLE` |
| 0x0000F4C6 | 0x0100F4C6 | 9 | `'kBTB\.- ` |
| 0x0000F644 | 0x0100F644 | 10 | `7BBR7kB~Bt` |
| 0x0000F739 | 0x0100F739 | 14 | `kBb7@B`o.0+BbH` |
| 0x0000FC61 | 0x0100FC61 | 10 | `:Bs`L7DBv ` |
| 0x0000FDF0 | 0x0100FDF0 | 13 | `BjBjBjBhBjBf`` |
| 0x0000FDFF | 0x0100FDFF | 11 | ``BjBjBjBhHx` |
| 0x00010240 | 0x01010240 | 8 | `dlV3f(2<` |
| 0x00012004 | 0x01012004 | 59 | ` $'*-0257:<>@BDFGIKMNPQSTVWYZ\]^`abdefgijklmopqrstuvwyz{|}~` |
| 0x00012C5B | 0x01012C5B | 8 | `intrstat` |
| 0x00012C72 | 0x01012C72 | 8 | `systimer` |
| 0x00012C7B | 0x01012C7B | 9 | `enetTXDMA` |
| 0x00012C85 | 0x01012C85 | 9 | `enetRXDMA` |
| 0x00012C97 | 0x01012C97 | 10 | `opticalDMA` |
| 0x00012CA2 | 0x01012CA2 | 10 | `printerDMA` |
| 0x00012CAD | 0x01012CAD | 11 | `soundoutDMA` |
| 0x00012CB9 | 0x01012CB9 | 10 | `soundinDMA` |
| 0x00012D13 | 0x01012D13 | 8 | `soundrun` |
| 0x00012D34 | 0x01012D34 | 10 | `kybd/mouse` |
| 0x00012D45 | 0x01012D45 | 8 | `softint2` |
| 0x00012D4E | 0x01012D4E | 8 | `softint1` |
| 0x00012D57 | 0x01012D57 | 8 | `intrmask` |
| 0x00012D95 | 0x01012D95 | 8 | `DSPreset` |
| 0x00012D9E | 0x01012D9E | 8 | `DSPblock` |
| 0x00012DBD | 0x01012DBD | 8 | `softint2` |
| 0x00012DC6 | 0x01012DC6 | 8 | `softint1` |
| 0x00012DD0 | 0x01012DD0 | 10 | `mem256K/4M` |
| 0x00012DDC | 0x01012DDC | 8 | `mem1M/4M` |
| 0x00012DE5 | 0x01012DE5 | 9 | `timeripl7` |
| 0x00012E26 | 0x01012E26 | 8 | `systimer` |
| 0x00012E2F | 0x01012E2F | 9 | `enetTXDMA` |
| 0x00012E39 | 0x01012E39 | 9 | `enetRXDMA` |
| 0x00012E4B | 0x01012E4B | 10 | `printerDMA` |
| 0x00012E56 | 0x01012E56 | 11 | `soundoutDMA` |
| 0x00012E62 | 0x01012E62 | 10 | `soundinDMA` |
| 0x00012EA5 | 0x01012EA5 | 8 | `soundrun` |
| 0x00012EBD | 0x01012EBD | 10 | `kybd/mouse` |
| 0x00012ECC | 0x01012ECC | 8 | `softint2` |
| 0x00012ED5 | 0x01012ED5 | 8 | `softint1` |
| 0x00012F07 | 0x01012F07 | 8 | `DSPreset` |
| 0x00012F10 | 0x01012F10 | 8 | `DSPblock` |
| 0x00012F2F | 0x01012F2F | 8 | `softint2` |
| 0x00012F38 | 0x01012F38 | 8 | `softint1` |
| 0x00012F41 | 0x01012F41 | 9 | `DSPtxdint` |
| 0x00012F69 | 0x01012F69 | 8 | `DSPmemen` |
| 0x00012F79 | 0x01012F79 | 12 | `boot command` |
| 0x00012F86 | 0x01012F86 | 10 | `DRAM tests` |
| 0x00012F91 | 0x01012F91 | 28 | `perform power-on system test` |
| 0x00012FAF | 0x01012FAF | 15 | `sound out tests` |
| 0x00012FC0 | 0x01012FC0 | 10 | `SCSI tests` |
| 0x00012FCC | 0x01012FCC | 19 | `loop until keypress` |
| 0x00012FE1 | 0x01012FE1 | 17 | `verbose test mode` |
| 0x00012FF3 | 0x01012FF3 | 34 | `serial port A is alternate console` |
| 0x00013016 | 0x01013016 | 48 | `allow any ROM command even if password protected` |
| 0x00013047 | 0x01013047 | 53 | `allow boot from any device even if password protected` |
| 0x0001307D | 0x0101307D | 55 | `allow optical drive #0 eject even if password protected` |
| 0x000130B5 | 0x010130B5 | 50 | `enable parity checking if parity memory is present` |
| 0x000130FB | 0x010130FB | 19 | `16MB of nibble mode` |
| 0x0001310F | 0x0101310F | 18 | `4MB of nibble mode` |
| 0x00013122 | 0x01013122 | 18 | `1MB of nibble mode` |
| 0x0001313D | 0x0101313D | 17 | `16MB of page mode` |
| 0x0001314F | 0x0101314F | 16 | `4MB of page mode` |
| 0x00013160 | 0x01013160 | 26 | `1MB of page mode (illegal)` |
| 0x0001317B | 0x0101317B | 26 | `16MB of parity nibble mode` |
| 0x00013196 | 0x01013196 | 25 | `4MB of parity nibble mode` |
| 0x000131B0 | 0x010131B0 | 25 | `1MB of parity nibble mode` |
| 0x000131CA | 0x010131CA | 24 | `16MB of parity page mode` |
| 0x000131E3 | 0x010131E3 | 23 | `4MB of parity page mode` |
| 0x000131FB | 0x010131FB | 33 | `1MB of parity page mode (illegal)` |
| 0x0001321D | 0x0101321D | 17 | `32MB of page mode` |
| 0x0001322F | 0x0101322F | 16 | `8MB of page mode` |
| 0x00013240 | 0x01013240 | 16 | `2MB of page mode` |
| 0x00013251 | 0x01013251 | 24 | `32MB of parity page mode` |
| 0x0001326A | 0x0101326A | 23 | `8MB of parity page mode` |
| 0x00013282 | 0x01013282 | 23 | `2MB of parity page mode` |
| 0x000132A5 | 0x010132A5 | 10 | `system ...` |
| 0x000132B0 | 0x010132B0 | 37 | `Main Memory Configuration Test Failed` |
| 0x000132D8 | 0x010132D8 | 23 | `Main Memory Test Failed` |
| 0x000132F7 | 0x010132F7 | 23 | `VRAM Memory Test Failed` |
| 0x00013310 | 0x01013310 | 29 | `Secondary Cache ram Test Fail` |
| 0x00013330 | 0x01013330 | 27 | `Secondary Tag ram Test Fail` |
| 0x0001334E | 0x0101334E | 12 | `CPU MC68040 ` |
| 0x0001335B | 0x0101335B | 20 | `%d MHz, memory %d nS` |
| 0x00013371 | 0x01013371 | 18 | `Backplane slot #%d` |
| 0x00013385 | 0x01013385 | 35 | `Ethernet address: %x:%x:%x:%x:%x:%x` |
| 0x000133AA | 0x010133AA | 46 | `Warning: non-volatile memory is uninitialized.` |
| 0x000133DA | 0x010133DA | 73 | `Memory sockets %d-%d configured for %s SIMMs but have %s ...` |
| 0x00013425 | 0x01013425 | 77 | `Memory sockets %d and %d configured for %s SIMMs but have...` |
| 0x0001347F | 0x0101347F | 82 | `Memory sockets %d and %d (%s) configured for %s SIMMs but...` |
| 0x000134D3 | 0x010134D3 | 16 | `Memory size %dMB` |
| 0x000134E4 | 0x010134E4 | 16 | `, parity enabled` |
| 0x000134F7 | 0x010134F7 | 42 | `can't continue without some working memory` |
| 0x00013526 | 0x01013526 | 35 | `System test failed.  Error code %x.` |
| 0x0001354D | 0x0101354D | 19 | `System test passed.` |
| 0x0001356B | 0x0101356B | 24 | `No default boot command.` |
| 0x00013588 | 0x01013588 | 50 | `parity error: status 0x%x, address 0x%x, data 0x%x` |
| 0x000135BC | 0x010135BC | 17 | `bogus stack frame` |
| 0x000135CF | 0x010135CF | 39 | `Exception #%d (0x%x) at pc 0x%x sp 0x%x` |
| 0x000135F8 | 0x010135F8 | 14 | `faultaddr 0x%x` |
| 0x0001360E | 0x0101360E | 14 | `New password: ` |
| 0x0001361D | 0x0101361D | 21 | `Retype new password: ` |
| 0x00013633 | 0x01013633 | 29 | `Mismatch - password unchanged` |
| 0x00013657 | 0x01013657 | 56 | `Memory sockets %d-%d have %s SIMMs installed (0x%x-0x%x)` |
| 0x00013691 | 0x01013691 | 60 | `Memory sockets %d and %d have %s SIMMs installed (0x%x-0x%x)` |
| 0x000136CF | 0x010136CF | 65 | `Memory sockets %d and %d (%s) have %s SIMMs installed (0x...` |
| 0x00013712 | 0x01013712 | 18 | `Old error code: %x` |
| 0x00013725 | 0x01013725 | 19 | `Last error code: %x` |
| 0x0001373A | 0x0101373A | 21 | `Function code %d (%s)` |
| 0x00013751 | 0x01013751 | 22 | `default input radix %d` |
| 0x00013782 | 0x01013782 | 10 | `Password: ` |
| 0x00013794 | 0x01013794 | 30 | `usage error, type "?" for help` |
| 0x000137CC | 0x010137CC | 23 | `must be < %d chars long` |
| 0x000137EF | 0x010137EF | 72 | `There must be a disk inserted in drive #0 before you can ...` |
| 0x00013854 | 0x01013854 | 18 | `DRAM error type %d` |
| 0x00013868 | 0x01013868 | 38 | `Check socket (0 is the first socket): ` |
| 0x00013894 | 0x01013894 | 28 | `Memory error at location: %x` |
| 0x000138B2 | 0x010138B2 | 28 | `Value at time of failure: %x` |
| 0x000138D0 | 0x010138D0 | 32 | `Coupling dependent memory fault!` |
| 0x000138F2 | 0x010138F2 | 41 | `One or more SIMM at memory bank %d is bad` |
| 0x0001391D | 0x0101391D | 30 | `Note: bank 0 is the first bank` |
| 0x0001393D | 0x0101393D | 29 | `Bank %d has mixed mode SIMM's` |
| 0x0001395C | 0x0101395C | 65 | `All of the SIMMs must be parity SIMMs if you want parity ...` |
| 0x0001399F | 0x0101399F | 40 | `Check socket (0 is the first socket): %d` |
| 0x000139CA | 0x010139CA | 43 | `One or both SIMMs in memory bank %d are bad` |
| 0x000139F7 | 0x010139F7 | 29 | `Bank %d has mixed size SIMMs.` |
| 0x00013A17 | 0x01013A17 | 74 | `VRAM failure at 0x%x:  read 0x%08x, expected 0x%08x, bad ...` |
| 0x00013A63 | 0x01013A63 | 74 | `VRAM failure at 0x%x:  read 0x%08x, expected 0x%08x, bad ...` |
| 0x00013AAF | 0x01013AAF | 14 | `SCSI DMA intr?` |
| 0x00013ABF | 0x01013ABF | 29 | `Sound Out Over Run Interrupt.` |
| 0x00013ADF | 0x01013ADF | 20 | `Sound Out DMA error!` |
| 0x00013AF5 | 0x01013AF5 | 15 | `Testing the FPU` |
| 0x00013B2D | 0x01013B2D | 15 | `, Event Counter` |
| 0x00013B3D | 0x01013B3D | 11 | `, Sound Out` |
| 0x00013B4B | 0x01013B4B | 30 | `Starting Extended Self Test...` |
| 0x00013B6B | 0x01013B6B | 18 | `Extended SCSI Test` |
| 0x00013B80 | 0x01013B80 | 40 | `Press and hold any key to exit self test` |
| 0x00013BAC | 0x01013BAC | 26 | `Cache RAM selftest failure` |
| 0x00013BC8 | 0x01013BC8 | 30 | `Memory error at location: 0x%x` |
| 0x00013BE8 | 0x01013BE8 | 30 | `Value at time of failure: 0x%x` |
| 0x00013C08 | 0x01013C08 | 33 | `Expected: 0x%x     Received: 0x%x` |
| 0x00013C2C | 0x01013C2C | 27 | `Cache tag selftest failure.` |
| 0x00013C56 | 0x01013C56 | 8 | `disk ...` |
| 0x00013CA4 | 0x01013CA4 | 11 | `network ...` |
| 0x00013CC9 | 0x01013CC9 | 10 | `floppy ...` |
| 0x00013CD4 | 0x01013CD4 | 35 | `Ethernet (try thin interface first)` |
| 0x00013CFB | 0x01013CFB | 43 | `Ethernet (try twisted pair interface first)` |
| 0x00013D2A | 0x01013D2A | 9 | `SCSI disk` |
| 0x00013D37 | 0x01013D37 | 12 | `Optical disk` |
| 0x00013D44 | 0x01013D44 | 11 | `Floppy disk` |
| 0x00013D50 | 0x01013D50 | 16 | `Boot command: %s` |
| 0x00013D62 | 0x01013D62 | 30 | `Default boot device not found.` |
| 0x00013D82 | 0x01013D82 | 10 | `(%d,%d,%d)` |
| 0x00013D8D | 0x01013D8D | 11 | `boot %s%s%s` |
| 0x00013D9A | 0x01013D9A | 11 | `diagnostics` |
| 0x00013DA6 | 0x01013DA6 | 54 | `Usage: b [device[(ctrl,unit,part)] [filename] [flags]]` |
| 0x00013DDE | 0x01013DDE | 13 | `boot devices:` |
| 0x00013DF7 | 0x01013DF7 | 21 | `unknown binary format` |
| 0x00013E0E | 0x01013E0E | 18 | `Booting %s from %s` |
| 0x00013E29 | 0x01013E29 | 8 | `tftp: %s` |
| 0x00013E33 | 0x01013E33 | 14 | `%s(%d,%d,%d)%s` |
| 0x00013E49 | 0x01013E49 | 13 | `tftp: timeout` |
| 0x00013E58 | 0x01013E58 | 28 | `Requesting BOOTP information` |
| 0x00013E96 | 0x01013E96 | 10 | ` [timeout]` |
| 0x00013EA2 | 0x01013EA2 | 16 | `0123456789abcdef` |
| 0x00013EBD | 0x01013EBD | 18 | `enreg_read failed ` |
| 0x00013ED1 | 0x01013ED1 | 19 | `enreg_write failed ` |
| 0x00013EEA | 0x01013EEA | 22 | `en_write: tx not ready` |
| 0x00013F0B | 0x01013F0B | 28 | `NeXT ROM Monitor %d.%d (v%d)` |
| 0x00013F29 | 0x01013F29 | 19 | `really power down? ` |
| 0x00013F3D | 0x01013F3D | 17 | `Error during boot` |
| 0x00013F4F | 0x01013F4F | 15 | `Didn't complete` |
| 0x00013F5F | 0x01013F5F | 18 | `scstart: bad state` |
| 0x00013F72 | 0x01013F72 | 14 | `software error` |
| 0x00013F81 | 0x01013F81 | 12 | `parity error` |
| 0x00013F8E | 0x01013F8E | 16 | `selection failed` |
| 0x00013F9F | 0x01013F9F | 9 | `bus error` |
| 0x00013FA9 | 0x01013FA9 | 14 | `target aborted` |
| 0x00013FB8 | 0x01013FB8 | 10 | `fifo level` |
| 0x00013FC3 | 0x01013FC3 | 15 | `target aborted2` |
| 0x00013FD3 | 0x01013FD3 | 16 | `msgin fifo level` |
| 0x00013FE4 | 0x01013FE4 | 20 | `scintr program error` |
| 0x00013FF9 | 0x01013FF9 | 18 | `SCSI command phase` |
| 0x0001400C | 0x0101400C | 22 | `SCSI bad i/o direction` |
| 0x00014023 | 0x01014023 | 17 | `SCSI msgout phase` |
| 0x00014035 | 0x01014035 | 22 | `scmsgin: no current sd` |
| 0x0001404C | 0x0101404C | 22 | `SCSI unexpected msg:%d` |
| 0x00014064 | 0x01014064 | 14 | `Unexpected msg` |
| 0x00014073 | 0x01014073 | 21 | `scmsgin: no FUNCCMPLT` |
| 0x00014091 | 0x01014091 | 13 | `SCSI Bus Hung` |
| 0x000140A0 | 0x010140A0 | 12 | `no SCSI disk` |
| 0x000140AE | 0x010140AE | 30 | `booting SCSI target %d, lun %d` |
| 0x000140CE | 0x010140CE | 12 | `dev blk len?` |
| 0x000140DC | 0x010140DC | 13 | `READ CAPACITY` |
| 0x000140EA | 0x010140EA | 9 | `REQ SENSE` |
| 0x000140F4 | 0x010140F4 | 31 | `waiting for drive to come ready` |
| 0x00014114 | 0x01014114 | 19 | `bad dev blk size %d` |
| 0x0001412E | 0x0101412E | 19 | `sdcmd bad state: %d` |
| 0x00014148 | 0x01014148 | 27 | `Selection timeout on target` |
| 0x00014165 | 0x01014165 | 23 | `Failed, sense key: 0x%x` |
| 0x0001417E | 0x0101417E | 11 | `Target busy` |
| 0x0001418B | 0x0101418B | 19 | `Target disconnected` |
| 0x000141A0 | 0x010141A0 | 22 | `Driver refused command` |
| 0x000141B8 | 0x010141B8 | 20 | `sdfail bad state: %d` |
| 0x000141CE | 0x010141CE | 27 | `dma_cleanup: negative resid` |
| 0x000141EA | 0x010141EA | 35 | `dma_start: bad DMA buffer alignment` |
| 0x0001420E | 0x0101420E | 9 | `Bad label` |
| 0x00014219 | 0x01014219 | 20 | `No bootfile in label` |
| 0x0001422F | 0x0101422F | 26 | `dev blk len %d, fs sect %d` |
| 0x0001424B | 0x0101424B | 20 | `Can't load blk0 boot` |
| 0x00014261 | 0x01014261 | 16 | `Bad version 0x%x` |
| 0x00014273 | 0x01014273 | 9 | `Bad blkno` |
| 0x0001427E | 0x0101427E | 9 | `Bad cksum` |
| 0x00014289 | 0x01014289 | 10 | `short read` |
| 0x00014295 | 0x01014295 | 23 | `uncorrectable ECC error` |
| 0x000142AD | 0x010142AD | 14 | `sector timeout` |
| 0x000142BC | 0x010142BC | 17 | `media upside down` |
| 0x000142CE | 0x010142CE | 16 | `no disk inserted` |
| 0x000142DF | 0x010142DF | 10 | `PLL failed` |
| 0x00014307 | 0x01014307 | 15 | `no optical disk` |
| 0x00014318 | 0x01014318 | 25 | `no valid disk label found` |
| 0x00014333 | 0x01014333 | 23 | `bad ctrl or unit number` |
| 0x00014365 | 0x01014365 | 14 | `od%d%c: %s %s ` |
| 0x00014379 | 0x01014379 | 11 | `(error #%d)` |
| 0x00014385 | 0x01014385 | 8 | ` %d:0:%d` |
| 0x0001438F | 0x0101438F | 22 | `fd: RECALIBRATE FAILED` |
| 0x000143A7 | 0x010143A7 | 24 | `fd: CONTROLLER I/O ERROR` |
| 0x000143C1 | 0x010143C1 | 18 | `RECALIBRATE FAILED` |
| 0x000143D5 | 0x010143D5 | 20 | `No Floppy Disk Drive` |
| 0x000143EB | 0x010143EB | 22 | `No Floppy Disk Present` |
| 0x00014403 | 0x01014403 | 25 | `Floppy Disk not Formatted` |
| 0x0001441E | 0x0101441E | 30 | `Unknown Floppy Disk error (%d)` |
| 0x0001443E | 0x0101443E | 27 | `Floppy Disk not Initialized` |
| 0x0001445B | 0x0101445B | 25 | `fd_intr: BOGUS fvp->state` |
| 0x0001447B | 0x0101447B | 11 | `RECALIBRATE` |
| 0x00014498 | 0x01014498 | 44 | `fd%d: Sector %d(d) cmd = %s; status = %d: %s` |
| 0x000144C6 | 0x010144C6 | 20 | `Bad Controller Phase` |
| 0x000144DB | 0x010144DB | 15 | `Controller hang` |
| 0x000144EB | 0x010144EB | 24 | `fc: Controller Reset: %s` |
| 0x00014505 | 0x01014505 | 38 | `fd: Bogus density (%d) in fc_specify()` |
| 0x0001452D | 0x0101452D | 46 | `fc_send_cmd: Error sending command bytes  (%d)` |
| 0x0001455D | 0x0101455D | 39 | `fc_send_cmd: Error getting status bytes` |
| 0x00014586 | 0x01014586 | 33 | `dma_bytes_moved: DMA buf overflow` |
| 0x00014AEF | 0x01014AEF | 9 | `!ddP<<FPd` |
| 0x00014CD8 | 0x01014CD8 | 26 | `NeXT ROM monitor commands:` |
| 0x00014CF4 | 0x01014CF4 | 42 | `p  inspect/modify configuration parameters` |
| 0x00014D20 | 0x01014D20 | 28 | `a [n]  open address register` |
| 0x00014D3E | 0x01014D3E | 29 | `m  print memory configuration` |
| 0x00014D5D | 0x01014D5D | 25 | `d [n]  open data register` |
| 0x00014D78 | 0x01014D78 | 36 | `r [regname]  open processor register` |
| 0x00014D9E | 0x01014D9E | 35 | `s [systemreg]  open system register` |
| 0x00014DC3 | 0x01014DC3 | 54 | `e [lwb] [alist] [format]  examine memory location addr` |
| 0x00014DFB | 0x01014DFB | 37 | `ec  print recorded system error codes` |
| 0x00014E22 | 0x01014E22 | 46 | `ej [drive #]  eject optical disk (default = 0)` |
| 0x00014E52 | 0x01014E52 | 19 | `eo  (same as above)` |
| 0x00014E67 | 0x01014E67 | 45 | `ef [drive #]  eject floppy disk (default = 0)` |
| 0x00014E96 | 0x01014E96 | 41 | `c  continue execution at last pc location` |
| 0x00014EC1 | 0x01014EC1 | 65 | `b [device[(ctrl,unit,part)] [filename] [flags]]  boot fro...` |
| 0x00014F04 | 0x01014F04 | 45 | `S [fcode]  open function code (address space)` |
| 0x00014F33 | 0x01014F33 | 26 | `R [radix]  set input radix` |
| 0x00014F56 | 0x01014F56 | 52 | `[lwb] select long/word/byte length (default = long).` |
| 0x00014F8C | 0x01014F8C | 71 | `[alist] is starting address or list of addresses to cycli...` |
| 0x00014FD5 | 0x01014FD5 | 54 | `Examine command, with no arguments, uses last [alist].` |
| 0x0001500C | 0x0101500C | 33 | `Copyright (c) 1988-1990 NeXT Inc.` |
| 0x000155AF | 0x010155AF | 9 | `U!U&U-U@V` |
| 0x00015671 | 0x01015671 | 8 | `PNQ:S:Q$` |
| 0x00015688 | 0x01015688 | 9 | `$)PFQ8Q:Q` |
| 0x000159B4 | 0x010159B4 | 16 | `NPN)R7O7O)NF7+ 8` |
| 0x000159E6 | 0x010159E6 | 8 | `=:EP8784` |
| 0x000159F6 | 0x010159F6 | 8 | `K F 4(IK` |
| 0x00015A33 | 0x01015A33 | 12 | `K JANFJQF8%3` |
| 0x00015A70 | 0x01015A70 | 11 | `M:JFJQN8 KF` |
| 0x00015AA9 | 0x01015AA9 | 8 | `P-8G"87A` |
| 0x00015BE3 | 0x01015BE3 | 9 | `QJP8)POPK` |
| 0x00015BF4 | 0x01015BF4 | 10 | `7OPN)NM:JF` |
| 0x00015CE2 | 0x01015CE2 | 10 | `)=9J=F AJN` |
| 0x00015D11 | 0x01015D11 | 23 | `P@PJP<L)POP:N$)EMPENPNQ` |
| 0x00015D55 | 0x01015D55 | 12 | `:NF)FN)F5F(N` |
| 0x00015D8F | 0x01015D8F | 10 | `:P8)8F)8)8` |
| 0x00015DC4 | 0x01015DC4 | 10 | `:PA)8F)8)8` |
| 0x00015DFB | 0x01015DFB | 10 | `:NF)8F)8)8` |
| 0x00015E34 | 0x01015E34 | 10 | `:N4)8F)8)8` |
| 0x00015E6D | 0x01015E6D | 12 | `:N()8F)8(F(N` |
| 0x00015E9C | 0x01015E9C | 9 | `P@PJPG)PN` |
| 0x00015EA9 | 0x01015EA9 | 9 | `)8F)8$PNQ` |
| 0x00015EE5 | 0x01015EE5 | 10 | `P8F)8$)FJN` |
| 0x00015FE3 | 0x01015FE3 | 49 | `UFUGUHUIUJUKULUMUNUOUPUQURUSUTUUUVUWUXUYU^U_U`UlV` |
| 0x00016C7B | 0x01016C7B | 8 | `Ml-rO^&&` |
| 0x00016C88 | 0x01016C88 | 10 | `z+rN{^&%Vd` |
| 0x00016C97 | 0x01016C97 | 9 | `rMTy\l%Va` |
| 0x00016CA5 | 0x01016CA5 | 13 | `&rMTg\l%VFNG*` |
| 0x00016CB7 | 0x01016CB7 | 8 | `\l%VOG(!` |
| 0x00016CC0 | 0x01016CC0 | 13 | `!rO\l%VOJ'!&%` |
| 0x00016CCE | 0x01016CCE | 9 | `rO\l%VOJ(` |
| 0x00016CD9 | 0x01016CD9 | 11 | `rO\l%VOJ&"%` |
| 0x00016CE6 | 0x01016CE6 | 8 | `rO\l#VOJ` |
| 0x00016CF3 | 0x01016CF3 | 9 | `rO\Y#VOJ&` |
| 0x00016D01 | 0x01016D01 | 10 | `rO\Y#VOJ%&` |
| 0x00016D0F | 0x01016D0F | 9 | `rO\Y#VOa&` |
| 0x00016D1D | 0x01016D1D | 8 | `O\Y#VNTp` |
| 0x00016D3B | 0x01016D3B | 11 | `rcN\Y$NTuJ!` |
| 0x00016D4A | 0x01016D4A | 11 | `qTrMdz$NVrJ` |
| 0x00016D59 | 0x01016D59 | 11 | `rC\Nz$N^\p!` |
| 0x00016D66 | 0x01016D66 | 9 | `r9?Nz$NvJ` |
| 0x00016D74 | 0x01016D74 | 11 | `qA5Nz$MT_J!` |
| 0x00016D81 | 0x01016D81 | 9 | `r91rMz$MV` |
| 0x00016DF0 | 0x01016DF0 | 8 | `\Lz$LW^d` |
| 0x00016E15 | 0x01016E15 | 9 | `?Lz$L^T^d` |
| 0x00016E28 | 0x01016E28 | 8 | `Lz$Lr\Vx` |
| 0x00016E39 | 0x01016E39 | 9 | `5Lz$LrM^a` |
| 0x00016E4A | 0x01016E4A | 10 | `5Lz$TCMVt!` |
| 0x00016E5A | 0x01016E5A | 10 | `!1rz$TI;LZ` |
| 0x00016E6A | 0x01016E6A | 11 | `&Arz$TDEJ&!` |
| 0x00016E79 | 0x01016E79 | 10 | `&;rz$T@&;8` |
| 0x00016E88 | 0x01016E88 | 21 | `3CLrz$T@'3B+h1:=Lrz$V` |
| 0x00016EA2 | 0x01016EA2 | 9 | `)l3EM\z$V` |
| 0x00016EAC | 0x01016EAC | 11 | `&%+o:Mr\z$V` |
| 0x00016EB9 | 0x01016EB9 | 9 | `+mMuV\z$V` |
| 0x00016EC7 | 0x01016EC7 | 9 | `+rL^T]z$V` |
| 0x00016ED1 | 0x01016ED1 | 8 | `+rwx\z$V` |
| 0x00016F0E | 0x01016F0E | 78 | `\z$V(:8+rVw\z$V&DB+rLT_}z$T<=J+o=Murz$T3CEIB+mCNrz$T;KLJ+...` |
| 0x00016F5E | 0x01016F5E | 27 | `rz$Ln05Lz$Ln05Lz$L[0?Lz$L[(` |
| 0x00016F7A | 0x01016F7A | 23 | `(?Lz$LV0\Lz$LV0\Lz$LT@'` |
| 0x00016F92 | 0x01016F92 | 26 | `'1rLz$LT@/1rLz$Mn/5Mz$WL['` |
| 0x00016FB5 | 0x01016FB5 | 8 | `\/VT}z$a` |
| 0x00016FBE | 0x01016FBE | 14 | `V@.1\Tgz$FLTH&` |
| 0x00016FD2 | 0x01016FD2 | 33 | `z$Nq.>Nz$N\.VNz$NV@-1}Nz$NTq->Oz$` |
| 0x00016FF4 | 0x01016FF4 | 48 | `Nc@+1cNWz&6cMTq+>rMX&&#sNc@)1cN\x&&#sNTr)TrN\x&%` |
| 0x00017034 | 0x01017034 | 11 | `}Qz2Sz2rRz&` |
| 0x0001756B | 0x0101756B | 10 | `jffTUUUUUU` |
| 0x0001758F | 0x0101758F | 10 | `ffUDUUUUUU` |
| 0x000175B3 | 0x010175B3 | 10 | `eUT@UUUUUU` |
| 0x00017B23 | 0x01017B23 | 10 | `'5lc7hZ)'j` |
| 0x00017B30 | 0x01017B30 | 16 | `t*&F!Gt,%5VlM-%D` |
| 0x00017B42 | 0x01017B42 | 17 | `.%UI$Fm($8;f"FlV ` |
| 0x00017B54 | 0x01017B54 | 12 | `mk%$@q"lV!A@` |
| 0x00017B77 | 0x01017B77 | 9 | `f:!E:pxwJ` |
| 0x00017B81 | 0x01017B81 | 12 | `m5:##785V:k_` |
| 0x00017B92 | 0x01017B92 | 8 | `]g"#Ag:l` |
| 0x00017BA0 | 0x01017BA0 | 9 | `rl:"#Au!l` |
| 0x00017BCE | 0x01017BCE | 9 | `!#XEPV,:5` |
| 0x00017BDD | 0x01017BDD | 8 | `-5fV"8]}` |
| 0x00017C03 | 0x01017C03 | 16 | `V.b^!@]}fV.VH!QF` |
| 0x00017C29 | 0x01017C29 | 8 | `f,8Ft9@!` |
| 0x00017C39 | 0x01017C39 | 11 | `8At!EV!f)5f` |
| 0x00017C4A | 0x01017C4A | 14 | `!:ZV:V'5k"s!@F` |
| 0x00017C5C | 0x01017C5C | 15 | `"Fl$5lZ!:V{!AG#` |
| 0x00017C9A | 0x01017C9A | 22 | `"Vr$}w5kZY![]5x}V"SI$;` |
| 0x00017CDF | 0x01017CDF | 15 | `:3f53k53f53k!V2` |
| 0x00017CEF | 0x01017CEF | 10 | `4vW2w@E2OZ` |
| 0x00017D3D | 0x01017D3D | 10 | `!!L8Z!b!8!` |
| 0x00017FC1 | 0x01017FC1 | 23 | `FJ+$3U9L,$DFh-$Uv#Ej'#6` |
| 0x00017FD9 | 0x01017FD9 | 16 | `}!EiR!jh$#>:!iU ` |
| 0x00017FEF | 0x01017FEF | 22 | `i##[c i 8iUkcD c""3Fc8` |
| 0x0001800D | 0x0101800D | 10 | `cEi8""7n3U` |
| 0x0001801E | 0x0101801E | 9 | `jd!"@qc8c` |
| 0x00018047 | 0x01018047 | 17 | `? "[zEwU)3{X "869` |
| 0x00018059 | 0x01018059 | 14 | `+@3 "WDIU+83z"` |
| 0x00018068 | 0x01018068 | 8 | `mn,3cU!6` |
| 0x00018071 | 0x01018071 | 8 | `w}-Xq!@ ` |
| 0x00018091 | 0x01018091 | 39 | `U-c] ?[wcU-UG UE|h?-Wn4m<e8,39n4G5z c+6` |
| 0x000180CD | 0x010180CD | 8 | `c(3c 9z=` |
| 0x000180D6 | 0x010180D6 | 27 | `z <Q 8U&3h [< ? U 5z!Ei#3iX` |
| 0x000180F2 | 0x010180F2 | 14 | `8EG A"ce!6lhU ` |
| 0x00018101 | 0x01018101 | 11 | `imU Um"Eih ` |
| 0x00018125 | 0x01018125 | 22 | `!Uo#wriT7YQX[iCwU!Uo#<` |
| 0x00018149 | 0x01018149 | 12 | `{kUmswi#Uo%F` |
| 0x00018173 | 0x01018173 | 26 | `U0z2gV0e?D0EX30Ec c/9c U 9` |
| 0x000181BF | 0x010181BF | 9 | `ejmiz  Og` |
| 0x0001822A | 0x0101822A | 10 | ` Zz Z z "I` |
| 0x0001823A | 0x0101823A | 8 | `B~BXz #w` |
| 0x00018247 | 0x01018247 | 11 | `Wk{ejm@z #3` |
| 0x0001825A | 0x0101825A | 11 | `ftiz %X_[Fr` |
| 0x000183AC | 0x010183AC | 12 | `6hH'#C0Vo)"0` |
| 0x000183C0 | 0x010183C0 | 12 | `+"Sj!Ce%!48}` |
| 0x00018400 | 0x01018400 | 8 | `  4c0S6d` |
| 0x0001843B | 0x0101843B | 8 | ` ZyBGc'0` |
| 0x0001844D | 0x0101844D | 9 | ` UCpS)60x` |
| 0x00018494 | 0x01018494 | 11 | `>+Ui1b:06*0` |
| 0x000184BD | 0x010184BD | 10 | ``&0`0hx?6x` |
| 0x000184C8 | 0x010184C8 | 8 | `:WS6S$0c` |
| 0x00018525 | 0x01018525 | 8 | `dqp OZ!:` |
| 0x00018559 | 0x01018559 | 18 | ``#WD/`8/cC/`8/c6S.` |
| 0x0001856C | 0x0101856C | 8 | `0S.oQ`.p` |
| 0x00018589 | 0x01018589 | 10 | `s)0Z>?S6dk` |
| 0x0001859A | 0x0101859A | 11 | ` 0pW4Z`W]du` |
| 0x0001863F | 0x0101863F | 8 | `Ufzaeh?x` |
| 0x00018822 | 0x01018822 | 8 | `f9{*)osW` |
| 0x00018843 | 0x01018843 | 12 | `e9{*({W]*/Be` |
| 0x00018853 | 0x01018853 | 12 | `cSu*(t<H+Weu` |
| 0x00018860 | 0x01018860 | 8 | `ye9{*({W` |
| 0x00018870 | 0x01018870 | 12 | `cSu*(tAU+2eu` |
| 0x00018881 | 0x01018881 | 12 | `9{*(x]TW*/Bn` |
| 0x0001888E | 0x0101888E | 13 | `sSu*(tIa;*2eu` |
| 0x000188A1 | 0x010188A1 | 12 | `9{*(xtcWT/Bn` |
| 0x000188CF | 0x010188CF | 12 | `wSu*(ug<*2l{` |
| 0x000188E0 | 0x010188E0 | 9 | `{*({nfX/B` |
| 0x000188F0 | 0x010188F0 | 11 | `u*(yufa<2[{` |
| 0x0001890F | 0x0101890F | 14 | `unfpu*({vtf;ey` |
| 0x0001892F | 0x0101892F | 9 | `ung_u*({y` |
| 0x0001894F | 0x0101894F | 9 | `nfacSu*({` |
| 0x00018961 | 0x01018961 | 9 | `fZe<9{*({` |
| 0x00018970 | 0x01018970 | 11 | `*ZeBcXSu*({` |
| 0x00018982 | 0x01018982 | 8 | `ea>9{*({` |
| 0x0001898D | 0x0101898D | 9 | `,IcYSu*({` |
| 0x00018998 | 0x01018998 | 12 | `+<I=;/*9{*({` |
| 0x000189A8 | 0x010189A8 | 11 | `*\T+T;Su*({` |
| 0x000189B7 | 0x010189B7 | 9 | `<E/-9{*({` |
| 0x000189C4 | 0x010189C4 | 8 | `W\.(u*({` |
| 0x000189CE | 0x010189CE | 13 | `< <E;*3*9{*({` |
| 0x000189DC | 0x010189DC | 13 | `2WxWmX+2Su*({` |
| 0x000189EB | 0x010189EB | 10 | `=Bq?*9{*({` |
| 0x000189F8 | 0x010189F8 | 10 | `faqeYSu*({` |
| 0x00018A09 | 0x01018A09 | 8 | `fa=9{*({` |
| 0x00018A5E | 0x01018A5E | 9 | `u*({wed<|` |
| 0x00018A7E | 0x01018A7E | 10 | `u*(yvfWGUy` |
| 0x00018ADC | 0x01018ADC | 11 | `pu*(utcX*e{` |
| 0x00018AF0 | 0x01018AF0 | 8 | `a<;/2n}{` |
| 0x00018AF9 | 0x01018AF9 | 13 | `upu*(tC`WT2eo` |
| 0x00018B1B | 0x01018B1B | 13 | `epu*(tCsWT4en` |
| 0x00018B3E | 0x01018B3E | 10 | `u*(tl{W*Ze` |
| 0x00018BAB | 0x01018BAB | 8 | `Q_u*(r=A` |
| 0x00018BCA | 0x01018BCA | 8 | `L _u*(y:` |
| 0x00018BFD | 0x01018BFD | 8 | `_{*(xZ[Z` |
| 0x00018C07 | 0x01018C07 | 15 | `lu{~) tSu*({<yA` |
| 0x00018C49 | 0x01018C49 | 8 | `{tWSu*({` |
| 0x00018C6D | 0x01018C6D | 23 | `{*(ku*(k{*(ku*(k{*)ku**` |
| 0x00018C85 | 0x01018C85 | 19 | `j{**#ju**(j{**)ju*+` |
| 0x00018C99 | 0x01018C99 | 15 | `i{*+#iu*+(i{*+0` |
| 0x0001A890 | 0x0101A890 | 16 | `0123456789abcdef` |
| 0x0001ADEC | 0x0101ADEC | 8 | `p      p` |
| 0x0001B045 | 0x0101B045 | 8 | `   @    ` |
| 0x0001B050 | 0x0101B050 | 10 | `          ` |
| 0x0001B134 | 0x0101B134 | 10 | `9:;<@=1234` |
| 0x0001B13F | 0x0101B13F | 13 | `5BCDEGHJKLMOP` |
| 0x0001B15F | 0x0101B15F | 8 | `.076/A8&` |
| 0x0001B340 | 0x0101B340 | 11 | `Canon OMD-1` |
| 0x0001B3D4 | 0x0101B3D4 | 13 | `Sony MPX-111N` |

---

**Total strings documented**: 472
**ROM size**: 131072 bytes (128KB)
