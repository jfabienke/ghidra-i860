# Example Conversion Output

This document shows what the converted NeXTSTEP documentation will look like after processing.

## Example 1: Concepts Document

**Original**: `Concepts/ObjectOrientedProgramming.htmld/index.html`
**Output**: `markdown/Concepts/ObjectOrientedProgramming.md`

```markdown
---
title: "Object-Oriented Programming in NeXTSTEP"
source: "ObjectOrientedProgramming.htmld/index.html"
format: "HTML"
section: "Concepts"
converted: "2025-11-09"
---

<!-- Page 1 -->

## Object-Oriented Programming

NeXTSTEP is built on a foundation of object-oriented programming (OOP).
This chapter introduces the key concepts of OOP as implemented in the
NeXTSTEP development environment.

### Introduction

Object-oriented programming organizes software design around data, or
**objects**, rather than functions and logic. An object can be defined
as a data field that has unique attributes and behavior.

### Key Principles

#### Encapsulation

Encapsulation is the bundling of data with the methods that operate on
that data. It restricts direct access to some of an object's components.

```objc
@interface BankAccount : NSObject {
    @private
    double balance;
}
- (void)deposit:(double)amount;
- (void)withdraw:(double)amount;
- (double)balance;
@end
```

#### Inheritance

Inheritance enables new objects to take on the properties of existing
objects. A class that is used as the basis for inheritance is called a
superclass or base class.

```objc
@interface CheckingAccount : BankAccount {
    double overdraftLimit;
}
- (void)setOverdraftLimit:(double)limit;
@end
```

#### Polymorphism

Polymorphism allows objects of different types to be accessed through
the same interface. Each type can provide its own independent
implementation of this interface.

### The NeXTSTEP Class Hierarchy

All NeXTSTEP classes inherit from `NSObject`, which provides:

- Memory management
- Runtime introspection
- Object comparison
- Archiving support

### Further Reading

See also:

- [Dynamic Loading](DynamicLoading.md)
- [Foundation Framework Reference](../GeneralRef/Foundation/index.md)
- [Memory Management](../ProgrammingTopics/MemoryManagement.md)
```

## Example 2: API Reference

**Original**: `GeneralRef/Foundation/NSString.htmld/index.html`
**Output**: `markdown/GeneralRef/Foundation/NSString.md`

```markdown
---
title: "NSString Class Reference"
source: "NSString.htmld/index.html"
format: "HTML"
section: "GeneralRef"
converted: "2025-11-09"
---

## NSString

**Inherits from:** NSObject
**Conforms to:** NSCopying, NSMutableCopying, NSCoding

### Overview

The `NSString` class provides objects for working with Unicode strings.
Strings are immutable; use `NSMutableString` for modifiable strings.

### Creating Strings

#### Class Methods

```objc
+ (id)string
```

Returns an empty string.

```objc
+ (id)stringWithFormat:(NSString *)format, ...
```

Returns a string created by using a given format string as a template.

**Parameters:**
- `format` - A format string. See "Formatting Strings" for details.
- `...` - A comma-separated list of arguments to substitute into format.

**Return Value:** A string created by using format as a template.

### Instance Methods

```objc
- (NSUInteger)length
```

Returns the number of Unicode characters in the receiver.

```objc
- (unichar)characterAtIndex:(NSUInteger)index
```

Returns the character at a given array position.

**Parameters:**
- `index` - The index of the character to retrieve.

**Return Value:** The character at the index specified by `index`.

**Raises:** NSRangeException if `index` is beyond the end of the receiver.

### Constants

#### String Encodings

| Constant | Value | Description |
|----------|-------|-------------|
| NSASCIIStringEncoding | 1 | 7-bit ASCII encoding |
| NSNEXTSTEPStringEncoding | 2 | 8-bit ASCII with NeXT extensions |
| NSUTF8StringEncoding | 4 | UTF-8 encoding |

### Related Classes

- NSMutableString
- NSAttributedString
- NSCharacterSet
```

## Example 3: Programming Guide

**Original**: `ProgrammingTopics/DisplayPostScript.pdf`
**Output**: `markdown/ProgrammingTopics/DisplayPostScript.md`

```markdown
---
title: "Display PostScript Programming Guide"
source: "DisplayPostScript.pdf"
format: "PDF"
pages: 156
converted: "2025-11-09"
---

<!-- Page 1 -->

## Display PostScript Programming

### Introduction

Display PostScript extends the PostScript page description language
to provide interactive graphics capabilities. This guide explains how
to use Display PostScript in NeXTSTEP applications.

### Architecture Overview

Display PostScript consists of three main components:

1. **Client Library** - C functions for application use
2. **PostScript Server** - Rendering engine
3. **Window Server** - Display management

### Basic Operations

#### Drawing a Line

```objc
- (void)drawRect:(NSRect)rect {
    PSsetgray(0.0);        // Set color to black
    PSmoveto(10, 10);      // Move to start point
    PSlineto(100, 100);    // Draw line
    PSstroke();            // Render the path
}
```

#### Using Custom Operators

You can define custom PostScript operators for efficiency:

```postscript
/drawBox {
    % x y width height drawBox
    4 dict begin
    /height exch def
    /width exch def
    /y exch def
    /x exch def

    newpath
    x y moveto
    width 0 rlineto
    0 height rlineto
    width neg 0 rlineto
    closepath
    stroke
    end
} def
```

Call from Objective-C:

```objc
PSWDrawBox(10, 10, 50, 50);
```

### Performance Considerations

For best performance:

- Batch PostScript commands
- Use single-operator forms when possible
- Cache computed paths
- Use user paths for repeated shapes

### NeXTdimension Acceleration

When running on a NeXTdimension board, Display PostScript operations
can be accelerated by the i860 processor:

- Path tessellation: **5-10x faster**
- Alpha compositing: **3-5x faster**
- Image interpolation: **4-8x faster**

The acceleration is automatic; no code changes required.

### Examples

See the following example programs:

- `DrawDemo` - Basic drawing operations
- `PathDemo` - Complex path manipulation
- `ImageDemo` - Image processing
```

## Example 4: Master Index

**Output**: `markdown/INDEX.md` (excerpt)

```markdown
# NeXTSTEP 3.3 Developer Documentation Index

**Generated:** 2025-11-09 14:30:00
**Total Documents:** 247
**Sections:** 5

---

## Table of Contents

- [Documentation by Section](#documentation-by-section)
- [Documentation by Topic](#documentation-by-topic)
- [API Reference Index](#api-reference-index)
- [Quick Navigation](#quick-navigation)

---

## Documentation by Section

### Concepts

*45 documents*

- [Application Architecture](Concepts/AppArchitecture.md)
  - The Application Object
  - Event Handling
  - The Responder Chain
- [Display PostScript](Concepts/DisplayPostScript.md)
  - PostScript Language
  - Imaging Model
  - Coordinate Systems
- [Object-Oriented Programming](Concepts/ObjectOrientedProgramming.md)
  - Encapsulation
  - Inheritance
  - Polymorphism

### GeneralRef

*124 documents*

- [Application Kit](GeneralRef/AppKit/index.md)
- [Foundation Framework](GeneralRef/Foundation/index.md)
  - NSObject
  - NSString
  - NSArray
  - NSDictionary

---

## Documentation by Topic

### Display PostScript

- [Display PostScript Programming](ProgrammingTopics/DisplayPostScript.md)
- [Display PostScript Concepts](Concepts/DisplayPostScript.md)
- [Graphics and Drawing](GeneralRef/AppKit/Graphics.md)
- [PostScript Operators](GeneralRef/PostScriptRef.md)

### Object-Oriented Programming

- [Object-Oriented Programming Concepts](Concepts/OOP.md)
- [The Objective-C Language](ProgrammingTopics/ObjC.md)
- [Dynamic Loading](Concepts/DynamicLoading.md)

---

## API Reference Index

| API | Documents | Location |
| --- | --------- | -------- |
| `NSObject` | 87 | [Foundation Framework](GeneralRef/Foundation/NSObject.md) |
| `NSString` | 65 | [Foundation Framework](GeneralRef/Foundation/NSString.md) |
| `NSView` | 54 | [Application Kit](GeneralRef/AppKit/NSView.md) |
| `PSsetgray` | 23 | [Display PostScript](GeneralRef/PostScriptRef.md) |

---

## Quick Navigation

### Essential Documents

- [Getting Started Guide](Concepts/GettingStarted.md)
- [Application Programming Overview](Concepts/AppProgramming.md)
- [Interface Builder Guide](ProgrammingTopics/InterfaceBuilder.md)

### NeXTdimension-Specific

- [3D Graphics Library](GeneralRef/3DKit/index.md)
- [Display PostScript Performance](ProgrammingTopics/DisplayPostScript.md)
- [Graphics Acceleration](Concepts/GraphicsAcceleration.md)
```

## Benefits of This Format

### For Human Readers

✅ **Clean and Readable** - Standard Markdown format
✅ **Well Organized** - Logical hierarchy preserved
✅ **Easy Navigation** - Comprehensive index and cross-links
✅ **Code Examples** - Properly formatted and highlighted
✅ **Searchable** - Plain text, works with any search tool

### For LLMs (Claude, GPT, etc.)

✅ **Structured Headers** - Easy to parse hierarchy
✅ **Metadata Rich** - YAML frontmatter in every file
✅ **Code Context** - Language-tagged code blocks
✅ **Cross References** - Internal links preserved
✅ **Topic Mapping** - Automatic categorization
✅ **API Index** - Quick lookup of classes/functions

### For Development

✅ **Version Control** - Text files work well with git
✅ **Diff Friendly** - Easy to see changes
✅ **Easily Updated** - Standard text format
✅ **Tool Compatible** - Works with existing Markdown tools

## File Organization

The output maintains logical organization:

```
markdown/
├── INDEX.md                      # Master index
├── INDEX.json                    # Machine-readable index
├── Concepts/                     # High-level concepts
│   ├── AppArchitecture.md
│   ├── DisplayPostScript.md
│   └── ObjectOrientedProgramming.md
├── GeneralRef/                   # API reference
│   ├── AppKit/
│   │   ├── NSView.md
│   │   └── NSWindow.md
│   └── Foundation/
│       ├── NSObject.md
│       └── NSString.md
├── ProgrammingTopics/            # How-to guides
│   ├── DisplayPostScript.md
│   └── MemoryManagement.md
└── ReleaseNotes/                 # Version info
    ├── InterfaceBuilder.md
    └── Compiler.md
```

## Next Steps

1. Run the conversion with `python3 convert_all.py --all`
2. Review the output in `markdown/`
3. Browse starting from `markdown/INDEX.md`
4. Use for reference in NeXTdimension development
5. Share with LLMs for context-aware assistance

---

This example demonstrates the high-quality output you'll get from the conversion process!
