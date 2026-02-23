---
title: "Display PostScript Reference"
source: "index.html"
format: "HTML"
section: "GeneralRef"
converted: "2025-11-09"
---

# Display PostScript Programming

## Overview

Display PostScript extends the PostScript page description language to provide interactive graphics capabilities. This guide explains how to use Display PostScript in NeXTSTEP applications.

## Basic Drawing Operations

### Drawing a Line

```objc \- (void)drawRect:(NSRect)rect { PSsetgray(0.0); // Set color to black PSmoveto(10, 10); // Move to start point PSlineto(100, 100); // Draw line PSstroke(); // Render the path } ``` 

### Common PostScript Operators

Operator | Description | Example  
---|---|---  
`PSmoveto` | Move to point | PSmoveto(x, y)  
`PSlineto` | Draw line to point | PSlineto(x, y)  
`PSstroke` | Render path | PSstroke()  
`PSsetgray` | Set gray level (0-1) | PSsetgray(0.5)  
  
## NeXTdimension Acceleration

When running on a NeXTdimension board, Display PostScript operations can be accelerated by the i860 processor:

  * **Path tessellation:** 5-10x faster
  * **Alpha compositing:** 3-5x faster
  * **Image interpolation:** 4-8x faster



The acceleration is automatic; no code changes required.

## Performance Tips

  1. Batch PostScript commands
  2. Use single-operator forms when possible
  3. Cache computed paths
  4. Use user paths for repeated shapes


