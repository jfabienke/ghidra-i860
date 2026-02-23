# Phase 2 Completion Plan: Call Graph Growth

## Current Status

**Phase 2 Progress**: 75% complete

### What We Have ✅
- All 5 functions identified and located
- Entry points documented (0xFFF06728, 0xFFF06750)
- Hot spots mapped (0xFFF07000, 0xFFF09000, 0xFFF0B000)
- Dispatch mechanism understood (inline conditionals)
- Main architecture documented
- Function boundaries known

### What's Missing ⏳
- Detailed annotation of each function
- Parameter analysis
- Complete call/branch target documentation
- Register usage conventions
- Function reference cards
- Inline code region documentation

---

## Phase 2 Requirements

From the original project plan:

| Task | Status | Priority |
|------|--------|----------|
| Function prologue/epilogue extraction | ✅ Complete | - |
| Function boundary mapping | ✅ Complete | - |
| Caller/callee relationships | ⏳ Partial | HIGH |
| Parameter passing analysis | ⏳ Not started | HIGH |
| Complete function annotations | ⏳ Partial | HIGH |

**Goal**: Achieve 100% Phase 2 completion

---

## Completion Roadmap

### Task 1: Annotate All 5 Functions (HIGH PRIORITY)
**Estimated Time**: 10-15 hours
**Status**: 20% complete (main function partially done)

#### Subtasks:
1. **Function 1 (0xFFF03790)** - Unknown purpose
   - Extract function code
   - Analyze control flow
   - Identify hardware access patterns
   - Determine purpose
   - Document parameters
   - **Time**: 2-3 hours

2. **Main Function (0xFFF06728/750)** - 50% done
   - Complete prologue annotation
   - Document initialization sequence (cold start)
   - Map all 18 `bri %r2` targets
   - Annotate hot spot (0xFFF07000)
   - Document main loop structure
   - Identify command opcodes
   - **Time**: 4-5 hours

3. **Function 4 (0xFFF07A10)** - Not started
   - Extract function code
   - Analyze purpose
   - Document relationships
   - **Time**: 2-3 hours

4. **Secondary Function (0xFFF07C14)** - Not started
   - Map to two hot spots
   - Document secondary processing loop
   - Analyze difference from main
   - **Time**: 3-4 hours

---

### Task 2: Parameter Analysis (HIGH PRIORITY)
**Estimated Time**: 3-4 hours
**Status**: Not started

#### Analysis Required:

**For Each Function, Document**:
- Input registers (r16-r31 per i860 convention)
- Output registers
- Preserved registers (callee-save)
- Stack frame usage
- Local variable allocation

**Method**:
```bash
# For each function, analyze:
# 1. Prologue to see what's saved
# 2. First instructions to see what's read
# 3. Epilogue to see what's restored
# 4. Returns to see what's returned

# Example for main function:
sed -n '6608,6630p' ND_i860_CLEAN.bin.asm  # Prologue
sed -n '8000,8020p' ND_i860_CLEAN.bin.asm  # Epilogue
```

**Deliverable**: Parameter tables for all 5 functions

---

### Task 3: Complete Call/Branch Analysis (MEDIUM PRIORITY)
**Estimated Time**: 2-3 hours
**Status**: Partially complete

#### Remaining Work:

1. **Document all 39 indirect branches in main**
   - Where they are
   - What register they use
   - Likely targets
   - Purpose

2. **Trace the 3 external calls**
   - 0xFFF0676C → 0xFFF8C700
   - 0xFFF06D14 → 0xFDF06E58
   - 0xFFF07C80 → 0xF9F47DE4
   - What do these do?

3. **Map all internal branches**
   - br, bc, bnc, bte, btne
   - Conditional logic
   - Loop structures

**Deliverable**: Complete call graph diagram

---

### Task 4: Register Usage Conventions (MEDIUM PRIORITY)
**Estimated Time**: 2-3 hours
**Status**: Not started

#### Analysis Required:

**Standard i860 Convention**:
- r0: Always zero
- r1: Stack pointer
- r2: Return address
- r3-r15: Scratch (caller-save)
- r16-r31: Preserved (callee-save)

**Verify in NeXTdimension firmware**:
- Which registers are used for parameters?
- Which are saved/restored?
- Any deviations from convention?

**Method**:
```python
# Analyze register usage across all functions
# Count: ld/st operations on each register
# Identify patterns
```

**Deliverable**: Register usage reference card

---

### Task 5: Create Function Reference Cards (LOW PRIORITY)
**Estimated Time**: 2-3 hours
**Status**: Not started

#### For Each Function:

Create a reference card with:
```markdown
## Function Name
**Address**: 0xFFFFFFFF
**Stack**: XXXX bytes
**Purpose**: Brief description

### Parameters
- Input: r16 (x), r17 (y), ...
- Output: r16 (status)

### Calls
- Function X at 0xYYYYYYYY
- Function Z at 0xZZZZZZZZ

### Called By
- Function A
- Interrupt handler

### Hot Spots
- 0xHHHHHHHH (description)

### Pseudocode
```c
void function_name(params) {
    // High-level logic
}
```

### Notes
- Special behaviors
- Optimization notes
```

**Deliverable**: 5 function reference cards

---

## Detailed Task Breakdown

### Week 1: Core Annotations (12-15 hours)

#### Day 1-2: Main Function Deep Dive (4-5 hours)
**Goal**: Complete annotation of 0xFFF06728/750

**Steps**:
1. Extract complete function (lines 6608-~7818)
2. Identify all code regions:
   - Prologue
   - Cold start initialization
   - Warm start entry
   - Main loop
   - Hot spot (0xFFF07000)
   - Conditional branches
   - Epilogue (if exists)
3. Trace all 18 `bri %r2` instances:
   - What loads %r2?
   - What are the targets?
   - Pattern analysis
4. Document command processing flow
5. Create detailed annotations

**Deliverable**: Fully annotated main function

---

#### Day 3: Secondary Function Analysis (3-4 hours)
**Goal**: Annotate 0xFFF07C14

**Steps**:
1. Extract function (lines 7947-~11270)
2. Identify structure
3. Map two hot spots:
   - 0xFFF09000 (+1275 lines)
   - 0xFFF0B000 (+3323 lines)
4. Compare with main function
5. Determine purpose

**Deliverable**: Annotated secondary function

---

#### Day 4: Helper Functions (4-6 hours)
**Goal**: Annotate functions 1 and 4

**Steps**:
1. **Function 1 (0xFFF03790)**:
   - Extract code
   - Analyze purpose
   - Look for calls to/from it
   - Document

2. **Function 4 (0xFFF07A10)**:
   - Extract code
   - Compare with main (same stack size)
   - Determine relationship
   - Document

**Deliverable**: All helper functions annotated

---

### Week 2: Analysis & Documentation (8-10 hours)

#### Day 5: Parameter Analysis (3-4 hours)
**Goal**: Document all function parameters

**Method**:
```bash
# For each function:

# 1. Extract prologue
sed -n 'START,START+20p' ND_i860_CLEAN.bin.asm

# 2. Look for register usage in first 50 instructions
# 3. Identify which registers are read (parameters)
# 4. Identify which are written (results)
# 5. Check epilogue for saves/restores

# 6. Create parameter table
```

**Deliverable**: Parameter tables for all functions

---

#### Day 6: Call Graph Completion (2-3 hours)
**Goal**: Complete call/branch documentation

**Tasks**:
1. Document all 39 indirect branches
2. Create call graph diagram
3. Map function relationships
4. Identify entry points vs. called functions

**Deliverable**: Complete call graph

---

#### Day 7: Register Conventions (2-3 hours)
**Goal**: Document register usage patterns

**Analysis**:
- Count register access patterns
- Verify against i860 conventions
- Note any deviations
- Create reference card

**Deliverable**: Register usage guide

---

#### Day 8: Reference Cards (2-3 hours)
**Goal**: Create function reference cards

**Tasks**:
1. Create card for each of 5 functions
2. Add pseudocode
3. Document relationships
4. Add usage examples

**Deliverable**: 5 reference cards

---

## Tools & Scripts Needed

### Script 1: Function Extractor
```python
# extract_function.py
# Usage: ./extract_function.py <start_line> <end_line> <output_file>
# Extracts function from disassembly with context
```

### Script 2: Register Usage Analyzer
```python
# analyze_registers.py
# Counts register access patterns across function
# Identifies input/output registers
```

### Script 3: Branch Tracer
```python
# trace_branches.py
# Follows all branch targets
# Creates control flow graph
```

### Script 4: Call Graph Generator
```python
# generate_callgraph.py
# Builds complete call graph
# Outputs as diagram or markdown
```

---

## Deliverables Checklist

### Documentation Files:
- [ ] `FUNCTION_1_ANALYSIS.md` (0xFFF03790)
- [ ] `MAIN_FUNCTION_COMPLETE.md` (0xFFF06728/750)
- [ ] `FUNCTION_4_ANALYSIS.md` (0xFFF07A10)
- [ ] `SECONDARY_FUNCTION_COMPLETE.md` (0xFFF07C14)
- [ ] `PARAMETER_ANALYSIS.md` (All functions)
- [ ] `CALL_GRAPH_COMPLETE.md` (Complete graph)
- [ ] `REGISTER_CONVENTIONS.md` (Usage guide)
- [ ] `FUNCTION_REFERENCE_CARDS.md` (All 5 cards)

### Annotated Code:
- [ ] `ND_i860_CLEAN_ANNOTATED.asm` (Updated with all 5 functions)

### Diagrams:
- [ ] Complete call graph (visual)
- [ ] Control flow for each function
- [ ] Data flow diagrams

---

## Success Criteria

Phase 2 is **100% complete** when:

✅ All 5 functions fully annotated
✅ Parameter tables for each function
✅ Complete call graph documented
✅ Register usage conventions established
✅ Function reference cards created
✅ All relationships mapped
✅ Hot spots integrated into function docs
✅ Pseudocode for all major functions

**Expected Outcome**: Complete understanding of every function in the firmware

---

## Quick Start: Next 2 Hours

If you want to make immediate progress:

### Hour 1: Annotate Function 1
```bash
# 1. Extract function 1
sed -n '3562,3700p' ND_i860_CLEAN.bin.asm > function_1.asm

# 2. Analyze it
# - What does it do?
# - What hardware does it access?
# - Who calls it?

# 3. Create FUNCTION_1_ANALYSIS.md
```

### Hour 2: Complete Main Function Hot Spot
```bash
# 1. Extract hot spot region
sed -n '7170,7220p' ND_i860_CLEAN.bin.asm > hot_spot_0xFFF07000.asm

# 2. Annotate in detail:
# - The 4x unrolled loop
# - FPU optimization (ixfr)
# - VRAM writes to 0x401C
# - Data flow

# 3. Add to MAIN_FUNCTION_COMPLETE.md
```

---

## Estimated Total Time

| Task | Time |
|------|------|
| Annotate all 5 functions | 12-15 hours |
| Parameter analysis | 3-4 hours |
| Call graph completion | 2-3 hours |
| Register conventions | 2-3 hours |
| Reference cards | 2-3 hours |
| **Total** | **21-28 hours** |

**With focused work**: 3-4 days of full-time effort

**With part-time work**: 1-2 weeks

---

## Priority Order

If time is limited, complete in this order:

**Priority 1** (Must Have):
1. Main function annotation (0xFFF06728/750)
2. Secondary function annotation (0xFFF07C14)
3. Parameter analysis for main functions

**Priority 2** (Should Have):
4. Function 4 annotation (0xFFF07A10)
5. Complete call graph
6. Register conventions

**Priority 3** (Nice to Have):
7. Function 1 annotation (0xFFF03790)
8. Reference cards
9. Diagrams

---

## Integration with Phase 3

Once Phase 2 is complete, Phase 3 (Thematic Analysis) becomes straightforward:

**Phase 3 Tasks** (enabled by Phase 2):
- Group functions by theme (already clear from Phase 2)
- Document command protocols (extract from annotations)
- Create implementation guides (based on pseudocode)

**Phase 2 → Phase 3 Flow**:
```
Complete Function Annotations (Phase 2)
    ↓
Identify Command Types (Phase 3)
    ↓
Group by Function (Phase 3)
    ↓
Create Protocol Docs (Phase 3)
    ↓
GaCKliNG Implementation Guide (Phase 3)
```

---

## Next Steps

### Immediate Actions:

1. **Choose starting point**:
   - Option A: Complete main function (most important)
   - Option B: Quick wins (annotate function 1 and 4 first)
   - Option C: Systematic (go in address order)

2. **Set up workspace**:
   ```bash
   # Create working directory
   mkdir phase2_annotations
   cd phase2_annotations

   # Extract each function to its own file
   # for easier analysis
   ```

3. **Start with one function**:
   - Extract it
   - Analyze it thoroughly
   - Document it completely
   - Move to next

### Recommended: Start with Main Function

**Why**:
- Most important
- Already 50% understood
- Unblocks everything else
- Highest value

**How**:
```bash
# 1. Extract main function
sed -n '6608,7818p' ND_i860_CLEAN.bin.asm > main_function.asm

# 2. Analyze in sections:
# - Prologue (lines 6608-6620)
# - Cold start (lines 6620-6650)
# - Warm start entry (line 6618)
# - Main loop (lines 6650-7800)
# - Hot spot (lines 7170-7220)

# 3. Document each section

# 4. Create MAIN_FUNCTION_COMPLETE.md
```

---

## Conclusion

**Phase 2 Completion is Achievable!**

With the architectural understanding we now have (95%), completing Phase 2 is straightforward work:
- No more mysteries
- Clear structure
- Known boundaries
- Documented relationships

**Estimated**: 21-28 hours of focused analysis
**Result**: Complete function-level understanding of entire firmware
**Value**: Enables GaCKliNG implementation and Phase 3 thematic analysis

---

**Ready to begin?** Start with the main function annotation - it's the highest value task and already 50% complete!

