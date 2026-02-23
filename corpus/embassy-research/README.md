# NeXTdimension Embassy Firmware Documentation

This directory contains comprehensive documentation for the NeXTdimension i860 firmware development.

## Architecture Specifications

### Embassy Framework
- **[i860-firmware-SBB-embassy-architecture.md](i860-firmware-SBB-embassy-architecture.md)** - Complete Embassy-based architecture specification with deferred interrupt processing
- **[firmware-implementation-examples.md](firmware-implementation-examples.md)** - Detailed implementation examples for DMA, mailbox, video controller

## Reverse Engineering Research

### ROM and Firmware Analysis
- **[ROM_ANALYSIS.md](ROM_ANALYSIS.md)** - ROM structure and boot sequence
- **[ROM_BOOT_SEQUENCE_DETAILED.md](ROM_BOOT_SEQUENCE_DETAILED.md)** - Detailed boot process
- **[ND_ROM_STRUCTURE.md](ND_ROM_STRUCTURE.md)** - ROM organization
- **[ND_ROM_DISASSEMBLY_ANALYSIS.md](ND_ROM_DISASSEMBLY_ANALYSIS.md)** - Disassembly findings
- **[EMBEDDED_I860_KERNEL_ANALYSIS.md](EMBEDDED_I860_KERNEL_ANALYSIS.md)** - Kernel structure analysis

### Kernel Architecture
- **[KERNEL_ARCHITECTURE_COMPLETE.md](KERNEL_ARCHITECTURE_COMPLETE.md)** - Complete kernel architecture
- **[KERNEL_TEXT_SEGMENT_STRUCTURE.md](KERNEL_TEXT_SEGMENT_STRUCTURE.md)** - Text segment layout
- **[GaCK_KERNEL_RESEARCH.md](GaCK_KERNEL_RESEARCH.md)** - GaCK kernel research
- **[GACK_KERNEL_MEMORY_MAP.md](GACK_KERNEL_MEMORY_MAP.md)** - Kernel memory layout

### Memory Architecture
- **[NEXTDIMENSION_MEMORY_MAP_COMPLETE.md](NEXTDIMENSION_MEMORY_MAP_COMPLETE.md)** - Complete memory map
- **[FINAL_VERIFIED_MEMORY_MAP.md](FINAL_VERIFIED_MEMORY_MAP.md)** - Verified memory regions
- **[ND_MACHDRIVER_MEMORY_MAP.md](ND_MACHDRIVER_MEMORY_MAP.md)** - Mach driver memory

### Code Analysis
- **[I860_CODE_INVENTORY.md](I860_CODE_INVENTORY.md)** - Inventory of i860 code
- **[I860_CODE_PATTERNS.md](I860_CODE_PATTERNS.md)** - Common code patterns
- **[CALLGRAPH_ANALYSIS.md](CALLGRAPH_ANALYSIS.md)** - Function call graph analysis
- **[CALL_GRAPH_COMPLETE.md](CALL_GRAPH_COMPLETE.md)** - Complete call graph
- **[DISASSEMBLY_ANALYSIS_FINDINGS.md](DISASSEMBLY_ANALYSIS_FINDINGS.md)** - Disassembly findings

## Protocol Specifications

### Host Communication
- **[HOST_I860_PROTOCOL_SPEC.md](HOST_I860_PROTOCOL_SPEC.md)** - Host-to-i860 communication protocol
- **[MAILBOX_PROTOCOL.md](MAILBOX_PROTOCOL.md)** - Mailbox communication details
- **[GACKLING_PROTOCOL_DESIGN.md](GACKLING_PROTOCOL_DESIGN.md)** - GaCKling protocol design
- **[GACKLING_PROTOCOL_DESIGN_V1.1.md](GACKLING_PROTOCOL_DESIGN_V1.1.md)** - Protocol v1.1

### Implementation Guides
- **[GACKLING_IMPLEMENTATION_GUIDE.md](GACKLING_IMPLEMENTATION_GUIDE.md)** - GaCKling implementation
- **[GACKLING_EXTRACTION_GUIDE.md](GACKLING_EXTRACTION_GUIDE.md)** - Code extraction guide
- **[GACKLING_INTERRUPT_IMPLEMENTATION_GUIDE.md](GACKLING_INTERRUPT_IMPLEMENTATION_GUIDE.md)** - Interrupt handling

## Graphics and Video

### Graphics Architecture
- **[GRAPHICS_ACCELERATION_GUIDE.md](GRAPHICS_ACCELERATION_GUIDE.md)** - Graphics acceleration
- **[GRAPHICS_PRIMITIVES_MAP.md](GRAPHICS_PRIMITIVES_MAP.md)** - Primitive functions
- **[FONT_CACHE_ARCHITECTURE.md](FONT_CACHE_ARCHITECTURE.md)** - Font caching system

### Video System
- **[VIDEO_MODE_IMPLEMENTATION_GUIDE.md](VIDEO_MODE_IMPLEMENTATION_GUIDE.md)** - Video mode setup
- **[FIRMWARE_SPLASH_SCREEN_ANALYSIS.md](FIRMWARE_SPLASH_SCREEN_ANALYSIS.md)** - Splash screen implementation

## PostScript Implementation

### DPS Analysis
- **[DPS_EXECUTE_IMPLEMENTATION.md](DPS_EXECUTE_IMPLEMENTATION.md)** - Display PostScript execution
- **[CMD_DPS_EXECUTE_FINAL_ANALYSIS.md](CMD_DPS_EXECUTE_FINAL_ANALYSIS.md)** - DPS command analysis
- **[CMD_DPS_EXECUTE_VERIFICATION_REPORT.md](CMD_DPS_EXECUTE_VERIFICATION_REPORT.md)** - Verification report

### PostScript Operators
- **[POSTSCRIPT_OPERATORS_CORRECTED.md](POSTSCRIPT_OPERATORS_CORRECTED.md)** - Operator implementations
- **[COMMAND_CLASSIFICATION_CORRECTED.md](COMMAND_CLASSIFICATION_CORRECTED.md)** - Command classification
- **[COMMAND_REFERENCE_CARDS.md](COMMAND_REFERENCE_CARDS.md)** - Quick reference

## Dispatch and Control Flow

### Dispatch Mechanisms
- **[DISPATCH_MECHANISM_ANALYSIS.md](DISPATCH_MECHANISM_ANALYSIS.md)** - Dispatch architecture
- **[DISPATCH_AND_HANDLERS_ANALYSIS.md](DISPATCH_AND_HANDLERS_ANALYSIS.md)** - Handler dispatch
- **[DISPATCH_TABLE_SEARCH_RESULTS.md](DISPATCH_TABLE_SEARCH_RESULTS.md)** - Dispatch table findings
- **[HANDLER_MAPPING_COMPLETE.md](HANDLER_MAPPING_COMPLETE.md)** - Complete handler map

### Function Analysis
- **[MAIN_FUNCTION_COMPLETE.md](MAIN_FUNCTION_COMPLETE.md)** - Main function analysis
- **[ENTRY_POINT_ANALYSIS.md](ENTRY_POINT_ANALYSIS.md)** - Entry point details
- **[HELPER_FUNCTIONS_ANALYSIS.md](HELPER_FUNCTIONS_ANALYSIS.md)** - Helper functions
- **[FUNC_0xFFF07000_ANALYSIS.md](FUNC_0xFFF07000_ANALYSIS.md)** - Specific function analysis

## System Integration

### Driver Analysis
- **[ND_MACHDRIVER_ANALYSIS.md](ND_MACHDRIVER_ANALYSIS.md)** - Mach driver architecture
- **[NDSERVER_ANALYSIS.md](NDSERVER_ANALYSIS.md)** - ND server implementation

### Parameter Conventions
- **[PARAMETER_CONVENTIONS.md](PARAMETER_CONVENTIONS.md)** - Calling conventions and parameters
- **[OPERATOR_SIZE_VERIFICATION_REPORT.md](OPERATOR_SIZE_VERIFICATION_REPORT.md)** - Size verification

## Section-by-Section Analysis

### Bootstrap and Initialization
- **[SECTION1-2_BOOTSTRAP.md](SECTION1-2_BOOTSTRAP.md)** - Bootstrap code
- **[SECTION3_VERIFICATION_CARD.md](SECTION3_VERIFICATION_CARD.md)** - Mach kernel verification

### VM and Handlers
- **[SECTION4_VERIFICATION_CARD.md](SECTION4_VERIFICATION_CARD.md)** - VM subsystem
- **[SECTION4_DETAILED_MAP.md](SECTION4_DETAILED_MAP.md)** - Detailed VM map
- **[SECTION5_VERIFICATION_CARD.md](SECTION5_VERIFICATION_CARD.md)** - Handler verification

### Graphics and Media
- **[SECTION6_VERIFICATION_CARD.md](SECTION6_VERIFICATION_CARD.md)** - Graphics subsystem
- **[SECTION7_X86_CODE_DISCOVERY.md](SECTION7_X86_CODE_DISCOVERY.md)** - x86 emulation code
- **[SECTION7_NEXTTV_APP_DISCOVERY.md](SECTION7_NEXTTV_APP_DISCOVERY.md)** - NeXTTV application

### System Services
- **[SECTION11_VERIFICATION_CARD.md](SECTION11_VERIFICATION_CARD.md)** - Debug services
- **[SECTIONS12_MAIN_KERNEL_MAP.md](SECTIONS12_MAIN_KERNEL_MAP.md)** - Main kernel map
- **[SECTIONS12_VERIFICATION_REPORT.md](SECTIONS12_VERIFICATION_REPORT.md)** - Verification report

## Performance Analysis

- **[I860XP_RUST_PERFORMANCE_ANALYSIS.md](I860XP_RUST_PERFORMANCE_ANALYSIS.md)** - Rust performance on i860XP

## Hardware Research

- **[VRAM_UPGRADE_INVESTIGATION.md](VRAM_UPGRADE_INVESTIGATION.md)** - VRAM expansion research
- **[FIRMWARE_PATCHING_ALTERNATIVE.md](FIRMWARE_PATCHING_ALTERNATIVE.md)** - Patching approaches

## Project Status

- **[NEXTDIMENSION_RESEARCH_COMPLETE.md](NEXTDIMENSION_RESEARCH_COMPLETE.md)** - Overall research status
- **[ANNOTATION_PROJECT_STATUS.md](ANNOTATION_PROJECT_STATUS.md)** - Annotation progress
- **[SECTION_VALIDATION_REPORT.md](SECTION_VALIDATION_REPORT.md)** - Section validation

## Phase Reports

- **[PHASE1_STATIC_ANALYSIS_RESULTS.md](PHASE1_STATIC_ANALYSIS_RESULTS.md)** - Phase 1 results
- **[PHASE2_COMPLETE_SUMMARY.md](PHASE2_COMPLETE_SUMMARY.md)** - Phase 2 summary
- **[PHASE2_COMPLETION_PLAN.md](PHASE2_COMPLETION_PLAN.md)** - Phase 2 plan
- **[PHASE4_DEEP_ANALYSIS.md](PHASE4_DEEP_ANALYSIS.md)** - Deep analysis phase

## Session Summaries

- **[SESSION_FINAL_SUMMARY.md](SESSION_FINAL_SUMMARY.md)** - Final session summary
- **[SESSION_SUMMARY_DISPATCH_ANALYSIS.md](SESSION_SUMMARY_DISPATCH_ANALYSIS.md)** - Dispatch analysis session
- **[SESSION_SUMMARY_NEXT_STEPS_COMPLETE.md](SESSION_SUMMARY_NEXT_STEPS_COMPLETE.md)** - Next steps

## Reverse Engineering Process

- **[REVERSE_ENGINEERING_PLAYBOOK.md](REVERSE_ENGINEERING_PLAYBOOK.md)** - Methodology and best practices
- **[REVERSE_ENGINEERING_PROCESS.md](REVERSE_ENGINEERING_PROCESS.md)** - Process documentation

## Historical

- **[THE_EMACS_CHANGELOG_INCIDENT.md](THE_EMACS_CHANGELOG_INCIDENT.md)** - Historical note

---

**Total Documents:** 77 research and analysis documents

These documents represent extensive reverse engineering work on the NeXTdimension ROM firmware and provide invaluable context for understanding the i860 architecture, protocols, and implementation patterns used in the original hardware.
