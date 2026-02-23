# NeXTdimension i860 Firmware - Call Graph Analysis
================================================================================

## Summary Statistics

Total instructions: 16384
Functions identified: 77
Call relationships: 77

## Exception Handlers

- **Reset Handler**: 0xFFF00000
- **Alignment Fault**: 0xFFF00008
- **Page Fault**: 0xFFF00010
- **Data Fault**: 0xFFF00018
- **Instruction Fault**: 0xFFF00020
- **Trap (System Call)**: 0xFFF00028
- **External Interrupt**: 0xFFF00030
- **Reserved**: 0xFFF00038

## Call Graph (Top-Level Functions)

Functions that are never called (potential entry points):

- 0xFFF00158
  - Calls: 0xFD8D7ED8
- 0xFFF0015C
  - Calls: 0xF9BDB714
- 0xFFF01480
  - Calls: 0x06E114F4
- 0xFFF03474
  - Calls: 0x042134E8
- 0xFFF03704
  - Calls: 0x001038B8
- 0xFFF03EF4
  - Calls: 0x04213F68
- 0xFFF0415C
  - Calls: 0xFA384B10
- 0xFFF041EC
  - Calls: 0x01C90988
- 0xFFF04FEC
  - Calls: 0x00005190
- 0xFFF06230
  - Calls: 0x00005FF0
- 0xFFF0676C
  - Calls: 0x0008C700
- 0xFFF06D14
  - Calls: 0xFE006E58
- 0xFFF07C80
  - Calls: 0xFA047DE4
- 0xFFF08158
  - Calls: 0xFB987F18
- 0xFFF08734
  - Calls: 0x07FC84F4
- 0xFFF09BA8
  - Calls: 0x05D4A55C
- 0xFFF0A048
  - Calls: 0x07FE449C
- 0xFFF0B0C0
  - Calls: 0x07F8AE80
- 0xFFF0B9AC
  - Calls: 0xFF6CB76C
- 0xFFF0BAE8
  - Calls: 0x00038104

## Hot Spots (Most Frequently Called Functions)

- 0xFDB17B40: called by 2 functions
- 0xFD8D7ED8: called by 1 functions
- 0xF9BDB714: called by 1 functions
- 0x06E114F4: called by 1 functions
- 0x042134E8: called by 1 functions
- 0x001038B8: called by 1 functions
- 0x04213F68: called by 1 functions
- 0xFA384B10: called by 1 functions
- 0x01C90988: called by 1 functions
- 0x00005190: called by 1 functions
- 0x00005FF0: called by 1 functions
- 0x0008C700: called by 1 functions
- 0xFE006E58: called by 1 functions
- 0xFA047DE4: called by 1 functions
- 0xFB987F18: called by 1 functions
- 0x07FC84F4: called by 1 functions
- 0x05D4A55C: called by 1 functions
- 0x07FE449C: called by 1 functions
- 0x07F8AE80: called by 1 functions
- 0xFF6CB76C: called by 1 functions

## Hardware Access Patterns

### Mailbox Accesses (7 total)

- 0xFFF07000: 3 accesses
- 0xFFF09000: 2 accesses
- 0xFFF04000: 1 accesses
- 0xFFF06000: 1 accesses

### VRAM Accesses (146 total)

- 0xFFF07000: 20 accesses
- 0xFFF09000: 19 accesses
- 0xFFF0B000: 18 accesses
- 0xFFF0E000: 13 accesses
- 0xFFF04000: 11 accesses
- 0xFFF06000: 9 accesses
- 0xFFF0A000: 9 accesses
- 0xFFF0C000: 9 accesses
- 0xFFF03000: 8 accesses
- 0xFFF0D000: 7 accesses

