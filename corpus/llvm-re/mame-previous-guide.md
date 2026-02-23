# Enhancing MAME/Previous i860 Emulation with LLVM Backend Learnings

**Last Updated:** 2025-07-24 11:35 EEST  
**Author:** John Fabienke, NeXTdimension Enhancement Project  
**Status:** Comprehensive Enhancement Guide

## Executive Summary

This document outlines how the architectural knowledge, performance models, and validation infrastructure developed for the i860 LLVM backend can be contributed back to improve the MAME/Previous i860 emulator. The current MAME implementation is XR-only and uses simplified timing models. Our work provides a complete blueprint for upgrading it to a cycle-accurate, XP-capable emulator.

## Table of Contents

1. [Current State Analysis](#current-state-analysis)
2. [Contribution Opportunities](#contribution-opportunities)
3. [XR to XP Upgrade Plan](#xr-to-xp-upgrade-plan)
4. [Implementation Details](#implementation-details)
5. [Validation Strategy](#validation-strategy)

## Current State Analysis

### MAME/Previous i860 Core Review

The existing MAME i860 core (integrated into Previous) is a well-written but limited implementation from the mid-1990s:

#### Key Limitations Identified

1. **XR-Only Implementation**
   - No dual-issue (VLIW) support
   - Missing XP-specific instructions (ldio, stio, pfam, pfsm, etc.)
   - No MMU support for 4MB pages
   - No MESI cache coherency protocol

2. **Simplified Timing Model**
   - Fixed cycle counts per instruction
   - No pipeline modeling
   - No dual-issue bundle validation
   - No accurate memory latency simulation

3. **Limited Architectural Features**
   - Basic instruction cache only
   - No data cache emulation
   - Simplified trap handling
   - Missing XP-specific registers (EPSR, BEAR)

### Code Structure Analysis

```cpp
// Current MAME execution loop (simplified)
void i860_cpu_device::run_cycle() {
    uint32_t insn = fetch_instruction();  // 32-bit only
    decode_exec(insn);                    // Sequential execution
    m_icount -= get_insn_cycles();        // Fixed timing
}
```

This structure cannot model the i860 XP's dual-issue capabilities or cycle-accurate performance.

## Contribution Opportunities

### 1. Pipeline Model and Cycle Accuracy

**Our Contribution:** The `I860PipelineModel` from i860-sim provides a complete, validated model of the i860 XP's 5-stage dual-issue pipeline.

**Benefits to MAME:**
- Transform from functional to performance-accurate emulation
- Enable real performance analysis
- Find timing-related bugs
- Provide authentic hardware behavior

**Integration Example:**
```cpp
// Enhanced MAME execution with pipeline model
void i860_cpu_device::run_cycle_pipelined() {
    // Use our pipeline model
    I860PipelineModel pipeline;
    
    // Fetch potential bundle
    uint64_t bundle = fetch_bundle();
    
    // Validate and execute through pipeline
    if (pipeline.canDualIssue(bundle)) {
        pipeline.executeDualIssue(bundle);
        m_icount -= pipeline.getCycleCount();
    } else {
        pipeline.executeSingle(bundle >> 32);
        m_icount -= pipeline.getCycleCount();
    }
}
```

### 2. Bundle Validation Infrastructure

**Our Contribution:** The `BundleValidator` contains complete rules for legal VLIW bundles.

**Benefits to MAME:**
- Accurate disassembly of 64-bit bundles
- Enhanced debugger capabilities
- Detection of illegal instruction pairings
- Proper bundle-aware stepping

**Implementation:**
```cpp
class MAMEBundleValidator {
    bool isValidBundle(uint32_t core_insn, uint32_t fp_insn) {
        // Port our validation logic
        if (!isCoreSideInstruction(core_insn)) return false;
        if (!isFPSideInstruction(fp_insn)) return false;
        if (hasDataDependency(core_insn, fp_insn)) return false;
        if (hasResourceConflict(core_insn, fp_insn)) return false;
        return true;
    }
};
```

### 3. Instruction Semantics and Patterns

**Our Contribution:** TableGen patterns describing high-level computational patterns.

**Benefits to MAME:**
- Clear documentation of instruction purpose
- Guide for implementing complex operations
- Test generation patterns

### 4. Comprehensive Test Suite

**Our Contribution:** Extensive test corpus covering architectural edge cases.

**Benefits to MAME:**
- Validation suite for emulator correctness
- Regression testing
- Performance verification
- Edge case coverage

## XR to XP Upgrade Plan

### Phase 1: Add XP Feature Flags and State (1-2 days)

#### 1.1 CPU Type Configuration
```cpp
// i860.hpp additions
class i860_cpu_device {
    bool m_is_xp;           // XP variant flag
    uint32_t m_epsr;        // Extended PSR (XP only)
    uint32_t m_bear;        // Bus Error Address (XP only)
    uint32_t m_ccr;         // Concurrency Control (XP only)
    
    // Cache state for MESI
    struct cache_line {
        uint32_t tag;
        uint8_t mesi_state;  // M/E/S/I
        uint8_t data[32];
    };
    cache_line m_dcache[128][4];  // 16KB, 4-way
};
```

#### 1.2 MMU Large Page Support
```cpp
// Enhanced address translation
uint32_t get_address_translation_xp(uint32_t vaddr) {
    uint32_t pde = read_pde(vaddr);
    
    if (pde & PS_BIT) {  // 4MB page
        return (pde & 0xFFC00000) | (vaddr & 0x3FFFFF);
    } else {  // 4KB page
        return get_address_translation_xr(vaddr);
    }
}
```

### Phase 2: Implement XP Instructions (3-5 days)

#### 2.1 I/O Instructions
```cpp
// ldio/stio implementation
void insn_ldio(uint32_t insn) {
    uint32_t addr = get_ea(insn);
    uint32_t data = io_read32(addr);  // Bypass cache
    set_reg(get_dest(insn), data);
}

void insn_stio(uint32_t insn) {
    uint32_t addr = get_ea(insn);
    uint32_t data = get_reg(get_src(insn));
    io_write32(addr, data);  // Bypass cache
}
```

#### 2.2 Dual-Operation Instructions
```cpp
// PFAM implementation (Pipelined Floating Multiply-Add)
void insn_pfam(uint32_t insn) {
    float fs1 = get_fpreg(FS1(insn));
    float fs2 = get_fpreg(FS2(insn));
    float fs3 = get_fpreg(FS3(insn));
    
    float result = (fs1 * fs2) + fs3;  // Fused operation
    
    set_fpreg(FD(insn), result);
    m_fp_pipeline_busy = 3;  // 3-cycle latency
}
```

#### 2.3 Update Decode Tables
```cpp
// Add XP instructions to decode tables
const decode_entry xp_decode_tbl[] = {
    { 0x13000010, 0xFFFF801F, insn_ldio },   // ldio
    { 0x13000014, 0xFFFF801F, insn_stio },   // stio
    { 0x48000420, 0xFC00073F, insn_pfam },   // pfam
    { 0x48000520, 0xFC00073F, insn_pfsm },   // pfsm
    // ... more XP instructions
};
```

### Phase 3: Implement Dual-Issue Pipeline (5-7 days)

#### 3.1 Refactor Execution Loop
```cpp
void i860_cpu_device::run_cycle_xp() {
    if (m_dim) {  // Dual Instruction Mode
        uint64_t bundle = fetch_bundle();
        uint32_t core_insn = bundle >> 32;
        uint32_t fp_insn = bundle & 0xFFFFFFFF;
        
        if (BundleValidator::isValid(core_insn, fp_insn)) {
            // Execute both in parallel
            execute_core(core_insn);
            execute_fp(fp_insn);
            update_pipeline_state();
        } else {
            // Invalid bundle - trap
            generate_trap(INSTRUCTION_FAULT);
        }
    } else {
        // Single instruction mode
        run_cycle_xr();
    }
}
```

#### 3.2 Pipeline State Management
```cpp
class PipelineState {
    struct Stage {
        uint32_t instruction;
        uint32_t pc;
        bool valid;
    };
    
    Stage IF, ID, EX, MEM, WB;
    
    void advance() {
        WB = MEM;
        MEM = EX;
        EX = ID;
        ID = IF;
        IF = fetch_next();
    }
    
    bool hasHazard(uint32_t insn1, uint32_t insn2) {
        // Check for data dependencies
        return detectRAW(insn1, insn2) || 
               detectWAW(insn1, insn2) || 
               detectWAR(insn1, insn2);
    }
};
```

### Phase 4: Data Cache and MESI Protocol (Optional, 3-5 days)

#### 4.1 Cache Implementation
```cpp
class DataCache {
    static const int SETS = 128;
    static const int WAYS = 4;
    
    struct CacheLine {
        uint32_t tag;
        uint8_t mesi;     // 0=I, 1=S, 2=E, 3=M
        uint32_t data[8]; // 32 bytes
    };
    
    CacheLine lines[SETS][WAYS];
    
    bool access(uint32_t addr, bool write) {
        int set = (addr >> 5) & 0x7F;
        uint32_t tag = addr >> 12;
        
        // Search for hit
        for (int way = 0; way < WAYS; way++) {
            if (lines[set][way].tag == tag && 
                lines[set][way].mesi != MESI_INVALID) {
                // Handle MESI transitions
                if (write) {
                    lines[set][way].mesi = MESI_MODIFIED;
                }
                return true;  // Hit
            }
        }
        return false;  // Miss
    }
};
```

## Implementation Details

### Integration with i860-sim

Our cycle-accurate simulator can be directly integrated:

```cpp
// Use i860-sim as reference implementation
#include "I860Simulator.h"

class MAMESimulatorBridge {
    I860Simulator sim;
    
    void syncState(i860_cpu_device* cpu) {
        // Copy MAME state to simulator
        sim.setGPR(cpu->m_iregs);
        sim.setFPR(cpu->m_fregs);
        sim.setPSR(cpu->m_psr);
    }
    
    void validate(uint32_t insn) {
        // Compare MAME execution with simulator
        sim.step();
        assert(sim.getPC() == cpu->m_pc);
    }
};
```

### Testing Infrastructure

```cpp
// Automated test runner using our LLVM test suite
class TestRunner {
    void runLLVMTests() {
        for (auto& test : llvm_test_suite) {
            // Compile with LLVM
            auto binary = compileLLVM(test);
            
            // Run on enhanced MAME
            auto mame_result = runMAME(binary);
            
            // Validate against i860-sim
            auto sim_result = runSimulator(binary);
            
            assert(mame_result == sim_result);
        }
    }
};
```

## Validation Strategy

### 1. Instruction-Level Validation
- Run our LLVM test suite on enhanced MAME
- Compare results with i860-sim
- Verify cycle counts match

### 2. Pipeline Validation
- Use microbenchmarks to verify dual-issue behavior
- Validate hazard detection
- Confirm latency modeling

### 3. System-Level Validation
- Run NeXTSTEP on enhanced Previous
- Verify XP features work correctly
- Performance should match hardware

### 4. Regression Testing
- Ensure XR compatibility maintained
- All existing software continues to work
- No performance regressions

## Contribution Summary

| Asset | Contribution | Impact |
|-------|--------------|--------|
| **Pipeline Model** | Cycle-accurate 5-stage pipeline | Transforms to performance-accurate emulation |
| **Bundle Validator** | VLIW pairing rules | Enables accurate dual-issue emulation |
| **XP Instructions** | Complete ISA additions | Full XP processor support |
| **Test Suite** | Comprehensive validation | Ensures correctness |
| **Performance Data** | Validated cycle counts | Authentic timing behavior |

## Conclusion

By contributing our LLVM backend learnings to MAME/Previous, we can:

1. **Upgrade** the emulator from XR-only to full XP support
2. **Transform** it from functional to cycle-accurate
3. **Validate** our compiler against authentic hardware behavior
4. **Benefit** the entire retro-computing community

This creates a virtuous cycle where our compiler work improves emulation, and better emulation validates our compiler—a true win-win for digital preservation and compiler research.

---

*This guide represents a concrete plan for enhancing the world's leading open-source i860 emulator with the architectural knowledge gained from our LLVM backend project.*