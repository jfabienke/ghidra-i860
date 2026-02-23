---
title: "NeXTdimension Release Notes"
source: "index.html"
format: "HTML"
section: "ReleaseNotes"
converted: "2025-11-09"
---

# NeXTdimension Release Notes

## Hardware Specifications

The NeXTdimension graphics accelerator board features:

  * **Processor:** Intel i860XP @ 33/40 MHz
  * **RAM:** 32MB DRAM (expandable to 64MB)
  * **VRAM:** 16MB dedicated video memory
  * **Resolution:** Up to 1120x832 @ 32-bit color
  * **Video Input:** NTSC/PAL composite and S-Video



## Software Capabilities

### Display PostScript Acceleration

The following operations are hardware-accelerated:

``` Graphics Operation Speedup \----------------- ------- Path rendering 5-10x Text rendering 3-7x Image scaling 4-8x Alpha compositing 3-5x Color space conversion 6-12x ``` 

### 3D Graphics

The NeXTdimension includes a 3D graphics library optimized for the i860 processor:

```objc // Initialize 3D context N3DContext *context = [[N3DContext alloc] init]; // Create and render a 3D object N3DShape *cube = [N3DShape cube]; [context renderShape:cube]; ``` 

## Programming Notes

### Memory Architecture

The NeXTdimension has three memory regions:

Region | Size | Purpose  
---|---|---  
DRAM | 32-64MB | General purpose  
VRAM | 16MB | Frame buffer  
SRAM | 512KB | Fast cache  
  
### I860 Programming

For optimal performance on the i860:

  1. Use VLIW dual-instruction mode
  2. Leverage pipelined FP operations
  3. Minimize pipeline stalls
  4. Use special FP registers (KR, KI, T)



## Known Issues

  * Video capture requires firmware version 1.2 or later
  * Some PostScript Level 2 features not accelerated
  * Maximum texture size for 3D: 1024x1024



## For More Information

See the complete NeXTdimension Developer's Guide for detailed programming information.
