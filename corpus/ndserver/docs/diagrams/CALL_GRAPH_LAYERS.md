# NDserver Layer-Focused Call Graph

Simplified view showing the hierarchical layer structure of the NDserver architecture.

## Layer Architecture Overview

```mermaid
graph TB
    %% Styling
    classDef layer3 fill:#ff6b6b,stroke:#c92a2a,stroke-width:3px,color:#fff
    classDef layer2 fill:#4ecdc4,stroke:#0fb9b1,stroke-width:2px,color:#fff
    classDef layer1 fill:#45b7d1,stroke:#2a9bb7,stroke-width:2px,color:#fff
    classDef layer0 fill:#96ceb4,stroke:#6ba883,stroke-width:1px,color:#000
    classDef isolated fill:#ffd93d,stroke:#f6c324,stroke-width:1px,color:#000

    %% Layer 3: Entry Point
    subgraph L3["Layer 3: Entry Point (1 function)"]
        L3_Main["ND_ServerMain<br/>0x2dc6<br/>662 bytes<br/><br/>Parses CLI arguments<br/>Opens device<br/>Orchestrates boot sequence"]:::layer3
    end

    %% Layer 2: Coordinators
    subgraph L2["Layer 2: Coordinators (3 functions)"]
        L2_Init["ND_InitializeBoardWithParameters<br/>0x5bb8<br/>184 bytes<br/><br/>Configures board state<br/>Enters message loop"]:::layer2
        L2_Setup["ND_SetupBoardWithParameters<br/>0x5af6<br/>194 bytes<br/><br/>Hardware initialization<br/>DMA setup<br/>Slot registration"]:::layer2
        L2_Load["ND_LoadFirmwareAndStart<br/>0x5a3e<br/>184 bytes<br/><br/>Loads i860 kernel<br/>Starts processor"]:::layer2
    end

    %% Layer 1: Intermediate
    subgraph L1["Layer 1: Intermediate (4 functions)"]
        L1_Msg["ND_MessageReceiveLoop<br/>0x399c<br/>832 bytes<br/><br/>Main service loop<br/>Mach IPC receiver"]:::layer1
        L1_Kernel["ND_LoadKernelFromFile<br/>0x6f94<br/>158 bytes<br/><br/>Opens kernel file<br/>Validates format"]:::layer1
        L1_Map["ND_MapFDWithValidation<br/>0x7032<br/>64 bytes<br/><br/>Memory maps FD<br/>Returns mapped pointer"]:::layer1
        L1_DMA["ND_ValidateDMADescriptor<br/>0x7072<br/>42 bytes<br/><br/>Checks DMA alignment<br/>Validates bounds"]:::layer1
    end

    %% Layer 0: Leaf Functions
    subgraph L0["Layer 0: Leaf Functions (21 functions)"]
        L0_Core["<b>Core Operations (6)</b><br/><br/>• ND_MessageDispatcher (272B)<br/>• ND_RegisterBoardSlot (366B)<br/>• ND_ProcessDMATransfer (976B)<br/>• ND_WriteBranchInstruction (352B)<br/>• ND_URLFileDescriptorOpen (164B)<br/>• ND_LoadKernelSegments (304B)"]:::layer0

        L0_Handlers["<b>Message Handlers (11)</b><br/><br/>• ValidateAndConfigureMessage<br/>• CMD1EDC Handler<br/>• CMD43C Handler<br/>• CMD28 Handler<br/>• CMD434_Alt Handler<br/>• CMD838 Handler<br/>• CMD42C Handlers (×2)<br/>• CMD434 Handler<br/>• ValidateMessageType1<br/>• ValidateAndExecuteCommand"]:::layer0

        L0_Validate["<b>Validators (4)</b><br/><br/>• ValidateMessageAndDispatch<br/>• ValidateMessageType1_3Param<br/>• ValidateAndDispatchMessage0x30<br/>• MemoryTransferDispatcher"]:::layer0
    end

    %% Isolated Functions
    subgraph Isolated["Isolated Functions (59 total)"]
        ISO_Hardware["<b>Hardware Access (12)</b><br/><br/>• HardwareAccess_0x3874 (296B)<br/>• 11 × MMIO accessors (40-62B)<br/><br/>Direct hardware/register access<br/>MMIO region: 0x040105b0"]:::isolated

        ISO_Callback["<b>Callbacks (24)</b><br/><br/>Small functions (22-140 bytes)<br/>Called via function pointers<br/>Dispatch table entries"]:::isolated

        ISO_Utility["<b>Utility/Helper (33)</b><br/><br/>• PostScript Ops (31 functions)<br/>• Generic helpers (2)<br/><br/>Graphics primitives<br/>String/data manipulation"]:::isolated
    end

    %% Layer connections
    L3_Main --> L2
    L2 --> L1
    L1 --> L0

    %% Specific connections
    L2_Init --> L1_Msg
    L2_Load --> L1_Kernel
    L2_Load --> L1_Map
    L2_Setup --> L1_DMA

    L1_Msg --> L0_Handlers
    L1_Msg --> L0_Validate
    L1_Kernel --> L0_Core

    %% Indirect connections to isolated
    L0_Core -.indirect.-> ISO_Hardware
    L0_Handlers -.dispatch.-> ISO_Callback
    L0_Core -.utility.-> ISO_Utility

    %% Annotations
    L3_Main -.phase 1.-> L2_Setup
    L3_Main -.phase 2.-> L2_Load
    L3_Main -.phase 3.-> L2_Init
```

## Layer Details

### Layer 3: Entry Point (1 function)
**Purpose**: Command-line parsing and boot orchestration

| Function | Size | Complexity | Role |
|----------|------|------------|------|
| ND_ServerMain | 662 bytes | High | Parses `-w <slot>` argument, opens IOKit device, orchestrates 3-phase boot |

**Boot Phases**:
1. **Setup**: Hardware initialization (ND_SetupBoardWithParameters)
2. **Load**: Firmware loading and i860 start (ND_LoadFirmwareAndStart)
3. **Service**: Message loop (ND_InitializeBoardWithParameters → ND_MessageReceiveLoop)

### Layer 2: Coordinators (3 functions)
**Purpose**: High-level phase orchestration

| Function | Size | Calls | Role |
|----------|------|-------|------|
| ND_SetupBoardWithParameters | 194 bytes | 5 | Hardware init, DMA setup, slot registration |
| ND_LoadFirmwareAndStart | 184 bytes | 5 | Kernel loading, i860 processor start |
| ND_InitializeBoardWithParameters | 184 bytes | 5 | Final configuration, enter service loop |

**Key Insight**: Each coordinator makes exactly 5 internal calls, suggesting consistent design pattern.

### Layer 1: Intermediate (4 functions)
**Purpose**: Specialized orchestration for core subsystems

| Function | Size | Calls | Subsystem |
|----------|------|-------|-----------|
| ND_MessageReceiveLoop | 832 bytes | 5 | IPC/Messaging |
| ND_LoadKernelFromFile | 158 bytes | 1 | File I/O |
| ND_MapFDWithValidation | 64 bytes | 1 | Memory mapping |
| ND_ValidateDMADescriptor | 42 bytes | 1 | DMA validation |

**Largest Function**: MessageReceiveLoop at 832 bytes - main service loop handling Mach IPC.

### Layer 0: Leaf Functions (21 functions)
**Purpose**: Actual implementation work - no internal calls to analyzed functions

**Categorization**:

1. **Core Operations (6 functions)**:
   - `ND_MessageDispatcher` (272B) - Routes messages to handlers
   - `ND_RegisterBoardSlot` (366B) - IOKit slot registration
   - `ND_ProcessDMATransfer` (976B) - **Largest function** - complex DMA engine
   - `ND_WriteBranchInstruction` (352B) - Writes i860 boot code, releases reset
   - `ND_URLFileDescriptorOpen` (164B) - Opens file URLs
   - `ND_LoadKernelSegments` (304B) - Parses and loads kernel segments

2. **Message Handlers (11 functions)**:
   - Command-specific handlers (CMD1EDC, CMD43C, CMD28, CMD434, CMD838, CMD42C)
   - Message validators
   - Sizes: 158-234 bytes (consistent pattern)

3. **Validators (4 functions)**:
   - Message validation and dispatch
   - Type checking and parameter validation
   - MemoryTransferDispatcher (608B) - routes memory operations

### Isolated Functions (59 functions)
**Purpose**: Indirectly called via function pointers, dispatch tables, or dead code

**Categories**:

1. **Hardware Access (12 functions)**:
   - Direct MMIO register access
   - Critical: `HardwareAccess_0x3874` (296B) - accesses 0x04010290
   - 11 small accessors (40-62 bytes) - all touch 0x040105b0

2. **Callbacks (24 functions)**:
   - Small (22-140 bytes)
   - Called via function pointers
   - Dispatch table entries
   - Pattern: `link/unlk` stack frame for callbacks

3. **Utility/Helper (33 functions)**:
   - **31 PostScript operations** - Graphics primitives (0x3cdc-0x5dea)
   - 2 generic helpers
   - Sizes: 208-462 bytes

## Execution Flow

### Boot Sequence
```
Start → Layer 3 (Parse CLI)
      ↓
      Layer 2 Phase 1 (Setup Hardware)
      ↓
      Layer 2 Phase 2 (Load Firmware)
      ↓
      Layer 2 Phase 3 (Init & Loop)
      ↓
      Layer 1 (Message Loop)
      ↓
      Layer 0 (Message Dispatch)
      ↓
      Isolated (Handlers execute)
```

### Message Processing Loop
```
MessageReceiveLoop (L1)
  ↓
MessageDispatcher (L0)
  ↓
Command Handlers (L0 + Isolated)
  ↓
Hardware Access (Isolated)
  ↓
Callback Execution (Isolated)
```

## Design Patterns

### Consistent Coordinator Pattern
All Layer 2 coordinators:
- Size: 184-194 bytes (very consistent)
- Internal calls: Exactly 5 each
- Role: Phase orchestration only, no direct work

### Message Handler Pattern
Layer 0 message handlers:
- Size: 158-234 bytes
- Naming: `ND_MessageHandler_CMD<hex>` or `ND_Validate*`
- Consistent validation → dispatch → execute flow

### Callback Pattern
Isolated callbacks:
- Small size (22-140 bytes)
- Stack frame (`link/unlk`)
- 1-2 external calls
- Likely function pointer targets

## Metrics

| Metric | Value |
|--------|-------|
| **Total Functions** | 88 |
| **Average Function Size** | ~200 bytes |
| **Largest Function** | ND_ProcessDMATransfer (976B) |
| **Smallest Functions** | Callbacks (22B) |
| **Call Depth** | 4 layers (0-3) |
| **Isolated Ratio** | 67% (59/88) |
| **Critical Path Length** | 6 functions (Main → Setup → DMA → Transfer) |

## Notes

- **Layer depth**: Shallow 4-layer architecture suggests clean separation of concerns
- **Isolation**: 67% isolated functions typical for event-driven daemon with callbacks
- **Consistency**: Layer 2 shows remarkable consistency (184-194 bytes, 5 calls each)
- **Largest component**: DMA engine at 976 bytes - handles complex scatter-gather DMA
- **Most complex**: MessageReceiveLoop at 832 bytes - Mach IPC state machine
- **Hardware access**: Concentrated in isolated functions (not in main call path)
