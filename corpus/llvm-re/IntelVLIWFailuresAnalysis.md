# Intel's VLIW Failures: A Comparative Analysis of the i860 and Itanium

**Last Updated:** 2024-12-27 15:15 PST  
**Author:** i860 LLVM Backend Team

## Executive Summary

Intel failed twice with VLIW (Very Long Instruction Word) architectures - first with the i860 (1989-1990s) and then with Itanium (2001-2017). Despite 12 years of advancement in compiler technology between the two projects, both failed for remarkably similar reasons: overestimation of compiler capabilities, ignoring market realities, and fundamental misunderstandings about general-purpose computing workloads. This analysis examines both failures to extract lessons for computer architecture design.

## Table of Contents

1. [The VLIW Promise](#the-vliw-promise)
2. [Timeline of Failures](#timeline-of-failures)
3. [Common Failure Patterns](#common-failure-patterns)
4. [Technical Analysis](#technical-analysis)
5. [Market and Ecosystem Factors](#market-and-ecosystem-factors)
6. [Where VLIW Actually Works](#where-vliw-actually-works)
7. [Lessons Learned](#lessons-learned)
8. [Conclusion](#conclusion)

## The VLIW Promise

### The Theory
VLIW architectures promised to deliver supercomputer performance by:
- Moving scheduling complexity from hardware to compiler
- Eliminating complex out-of-order execution hardware
- Achieving higher clock speeds through simpler hardware
- Exploiting instruction-level parallelism (ILP) statically

### The Fundamental Assumption
**"Compilers can analyze code and find parallelism better than hardware"**

This assumption proved false for general-purpose computing in both 1989 and 2001.

## Timeline of Failures

### i860 (1989-1990s)
- **1989**: Launched as "Cray on a chip"
- **1990-1992**: Adoption struggles, compiler inadequacy becomes apparent
- **1993**: Intel shifts focus away from i860
- **1995**: Effectively discontinued
- **Total Loss**: ~$100 million

### Itanium (2001-2017)
- **1994**: Project begins (with HP)
- **2001**: First Itanium ships, immediate performance disappointment
- **2001-2005**: Multiple revisions, compiler still inadequate
- **2005**: AMD's x86-64 dominates market
- **2017**: Intel discontinues development
- **Total Loss**: ~$10+ billion

## Common Failure Patterns

### 1. The Compiler Problem

#### i860 Reality
```asm
// What compilers produced:
add    r16, r17, r18    // Core unit: integer add
fnop                    // FP unit: wasted cycle

// What was needed (hand-coded):
add    r16, r17, r18    // Core unit: integer add  
pfmul  f4, f5, f6       // FP unit: floating multiply
```
- Compilers achieved ~40% slot utilization
- Hand-coded assembly was 2-3x faster

#### Itanium Reality
```asm
// What compilers produced:
{.mii
    ld8 r1 = [r2]      // M-unit: load
    nop.i 0            // I-unit: wasted
    nop.i 0            // I-unit: wasted
}

// 6 execution units, typically 2-3 NOPs per bundle
```
- Even worse utilization than i860 (3-6 slots vs 2)
- Intel's own compiler took 5+ years to mature

### 2. Binary Compatibility Disaster

| Architecture | Problem | Impact |
|--------------|---------|---------|
| i860 | Each chip revision had different latencies | Software vendors gave up |
| Itanium | Each generation needed recompilation | ISVs refused to support |
| x86 (contrast) | 1990 binaries run fast in 2024 | Dominant ecosystem |

### 3. Real-World Code Mismatch

#### VLIW Assumes:
```c
// Ideal VLIW code - regular, predictable, parallel
for (int i = 0; i < 1000; i++) {
    a[i] = b[i] * c[i] + d[i];  // Beautiful parallelism!
}
```

#### Reality Delivers:
```c
// Actual code - irregular, unpredictable, sequential
while (node != NULL) {
    if (node->value > threshold) {
        result = process(node->data);
        if (result < 0) break;
    }
    node = node->next;  // Pointer chasing
}
```

### 4. The Ecosystem Problem

| Factor | i860 | Itanium |
|--------|------|---------|
| Compilers | Green Hills C barely functional | Intel compiler years late |
| Debuggers | Minimal | Expensive, limited |
| OS Support | None really | Windows dropped, Linux weak |
| Developer Tools | Almost none | Very expensive |
| Result | Developers fled | Developers fled |

## Technical Analysis

### Architectural Complexity Comparison

#### i860 (Relative Simplicity)
- 2-way VLIW (integer + FP)
- 32 integer + 32 FP registers
- Simple pipeline
- ~20K lines for modern compiler backend

#### Itanium (Extreme Complexity)
- 3-way VLIW with templates
- 128 integer + 128 FP + 64 predicate + 8 branch registers
- Speculation, predication, rotation
- ~150-200K lines for compiler backend

### The Fundamental VLIW Flaws

1. **Exposed Microarchitecture**
   - Software must know hardware details
   - Changes break optimization
   - No abstraction layer

2. **Static Scheduling**
   - Cannot adapt to runtime behavior
   - Cache misses destroy schedule
   - Branch misprediction kills performance

3. **Compiler Dependency**
   - Performance requires perfect static analysis
   - Impossible for pointer-chasing code
   - Halting problem limitations

4. **Market Timing**
   - Assumes compilers will improve
   - Market won't wait
   - Competition keeps moving

## Market and Ecosystem Factors

### Why x86 Won Both Times

1. **Binary Compatibility**
   ```
   x86 Promise: "Your software investment is protected"
   VLIW Promise: "Recompile for each chip generation"
   ```

2. **Incremental Evolution**
   - x86: Gradual improvements, compatibility maintained
   - VLIW: Revolutionary changes, compatibility broken

3. **Hardware Solves Problems**
   - x86: Out-of-order execution finds ILP dynamically
   - VLIW: Compiler must find ILP statically

### The Compiler Fantasy Timeline

| Year | Intel's Belief | Reality |
|------|----------------|---------|
| 1989 | "Compilers will soon be good enough" | They weren't |
| 1995 | "Compilers are almost there" | Still weren't |
| 2001 | "Now compilers are surely ready" | Nope |
| 2005 | "Our compiler is finally good" | Too late |
| 2024 | "Compilers still can't extract ILP well" | Fundamental limit |

## Where VLIW Actually Works

### Success Stories

1. **Digital Signal Processors (DSPs)**
   - Regular, predictable loops
   - Programmers accept assembly/intrinsics
   - No binary compatibility concerns
   - Example: TI C6000 series

2. **Graphics Processing Units (GPUs)**
   - Massive data parallelism
   - Different kind of VLIW (SIMT)
   - Domain-specific compilation
   - Example: Modern GPUs

3. **Specialized Accelerators**
   - Known workloads
   - Custom compilation
   - No general-purpose needs
   - Example: AI accelerators

### The Pattern

```
VLIW Success Factors:
✓ Narrow, well-defined domain
✓ Regular, predictable workloads  
✓ Acceptance of assembly/intrinsics
✓ No binary compatibility requirements
✓ Specialized compilers acceptable

VLIW Failure Factors:
✗ General-purpose computing
✗ Irregular, unpredictable code
✗ Compiler must do everything
✗ Binary compatibility essential
✗ Broad market appeal needed
```

## Lessons Learned

### 1. Compiler Capabilities Have Limits
- Static analysis cannot predict runtime behavior
- Pointer aliasing is often undecidable
- Real code has unpredictable patterns

### 2. Markets Value Compatibility
- Software investment protection trumps performance
- Ecosystems take decades to build
- Breaking compatibility breaks trust

### 3. Dynamic Beats Static
- Runtime adaptation is essential
- Hardware speculation works better
- Out-of-order execution handles real code

### 4. Simplicity Wins
- i860 failed with 2-way VLIW
- Itanium failed with 3-way + complexity
- Simple architectures easier to compile for

### 5. Learn from History
- Intel repeated the same mistakes
- 12 years didn't change fundamentals
- Institutional memory is important

## The Cost of Not Learning

| Metric | i860 | Itanium | Ratio |
|--------|------|---------|-------|
| Development Time | 3 years | 7 years | 2.3x |
| Financial Loss | ~$100M | ~$10B | 100x |
| Market Impact | Limited | Severe | - |
| Reputation Damage | Moderate | Severe | - |
| Opportunity Cost | High | Extreme | - |

## Conclusion

Intel's VLIW failures demonstrate a persistent misunderstanding of general-purpose computing requirements. Both the i860 and Itanium bet on compiler technology solving problems that compilers fundamentally cannot solve - extracting parallelism from inherently sequential, unpredictable code with complex control flow and pointer-based data structures.

The tragedy is not just the financial losses but the opportunity cost. The enormous engineering talent and resources spent on both projects could have advanced computing in directions that actually worked. Instead, we got two beautiful architectures that proved the same point twice: **in general-purpose computing, dynamic scheduling beats static scheduling every time.**

### The Ultimate Irony

While Intel spent billions trying to make VLIW work for general-purpose computing, simpler RISC architectures and Intel's own x86 (with out-of-order execution) continued to dominate. The market's message was clear both times: **compatibility, adaptability, and dynamic optimization beat theoretical elegance.**

### Final Lesson

The definition of insanity is doing the same thing twice and expecting different results. Intel's VLIW journey from i860 to Itanium is a cautionary tale about the importance of:
- Learning from past failures
- Understanding market requirements
- Recognizing fundamental technical limits
- Valuing simplicity and compatibility

The i860 LLVM backend project demonstrates that even "failed" architectures can teach us valuable lessons. By implementing a modern compiler for the i860, we can appreciate both its elegant simplicity and understand why that wasn't enough for market success.

---

*"Those who cannot remember the past are condemned to repeat it." - George Santayana*

*This analysis is part of the i860 LLVM Backend project, demonstrating that even "failed" architectures deserve study and understanding.*