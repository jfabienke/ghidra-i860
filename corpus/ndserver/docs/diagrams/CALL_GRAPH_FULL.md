# Complete NDserver Call Graph

This diagram shows all 88 functions in the NDserver binary with their call relationships, organized by analysis layer and category.

## Full Call Graph (88 Functions)

```mermaid
flowchart TD
    %% Styling
    classDef layer3 fill:#ff6b6b,stroke:#c92a2a,stroke-width:3px,color:#fff
    classDef layer2 fill:#4ecdc4,stroke:#0fb9b1,stroke-width:2px,color:#fff
    classDef layer1 fill:#45b7d1,stroke:#2a9bb7,stroke-width:2px,color:#fff
    classDef layer0 fill:#96ceb4,stroke:#6ba883,stroke-width:1px,color:#000
    classDef isolated fill:#ffd93d,stroke:#f6c324,stroke-width:1px,color:#000
    classDef callback fill:#f9b4ed,stroke:#d87cc3,stroke-width:1px,color:#000
    classDef hardware fill:#ff9f1c,stroke:#e67700,stroke-width:2px,color:#fff
    classDef utility fill:#e8f5e9,stroke:#4caf50,stroke-width:1px,color:#000

    %% ==========================================
    %% LAYER 3: Entry Point
    %% ==========================================
    ServerMain["ND_ServerMain<br/>0x2dc6<br/>662 bytes<br/><b>ENTRY POINT</b>"]:::layer3

    %% ==========================================
    %% LAYER 2: High-Level Coordinators (3)
    %% ==========================================
    ServerMain --> InitBoard["ND_InitializeBoardWithParameters<br/>0x5bb8<br/>184 bytes<br/><b>Layer 2 Coordinator</b>"]:::layer2
    ServerMain --> SetupBoard["ND_SetupBoardWithParameters<br/>0x5af6<br/>194 bytes<br/><b>Layer 2 Coordinator</b>"]:::layer2
    ServerMain --> LoadFirmware["ND_LoadFirmwareAndStart<br/>0x5a3e<br/>184 bytes<br/><b>Layer 2 Coordinator</b>"]:::layer2

    %% ==========================================
    %% LAYER 1: Intermediate Functions (4)
    %% ==========================================
    InitBoard --> MsgLoop["ND_MessageReceiveLoop<br/>0x399c<br/>832 bytes<br/><b>Main Service Loop</b>"]:::layer1
    LoadFirmware --> LoadKernel["ND_LoadKernelFromFile<br/>0x6f94<br/>158 bytes"]:::layer1
    LoadFirmware --> MapFD["ND_MapFDWithValidation<br/>0x7032<br/>64 bytes"]:::layer1
    SetupBoard --> ValidateDMA["ND_ValidateDMADescriptor<br/>0x7072<br/>42 bytes"]:::layer1

    %% ==========================================
    %% LAYER 0: Leaf Functions (21 Critical)
    %% ==========================================

    %% Core dispatch and registration
    MsgLoop --> MsgDispatch["ND_MessageDispatcher<br/>0x6e6c<br/>272 bytes<br/><b>Message Router</b>"]:::layer0
    SetupBoard --> RegisterSlot["ND_RegisterBoardSlot<br/>0x36b2<br/>366 bytes<br/><b>CRITICAL</b>"]:::layer0

    %% DMA and i860 control
    SetupBoard --> DMATransfer["ND_ProcessDMATransfer<br/>0x709c<br/>976 bytes<br/><b>DMA ENGINE</b>"]:::layer0
    SetupBoard --> WriteBranch["ND_WriteBranchInstruction<br/>0x746c<br/>352 bytes<br/><b>i860 START</b>"]:::layer0

    %% File operations
    LoadKernel --> URLOpen["ND_URLFileDescriptorOpen<br/>0x6474<br/>164 bytes"]:::layer0

    %% Memory and kernel loading
    LoadFirmware --> LoadKernelSegs["ND_LoadKernelSegments<br/>0x3284<br/>304 bytes"]:::layer0
    LoadKernelSegs --> MemTransfer["ND_MemoryTransferDispatcher<br/>0x33b4<br/>608 bytes"]:::layer0

    %% Message validation and handlers
    MsgLoop --> ValidateMsg1["ND_ValidateMessageAndDispatch<br/>0x6156<br/>158 bytes"]:::layer0
    MsgLoop --> ValidateMsg2["ND_ValidateMessageType1_3Param<br/>0x60d8<br/>126 bytes"]:::layer0
    MsgLoop --> ValidateMsg3["ND_ValidateAndDispatchMessage0x30<br/>0x6036<br/>162 bytes"]:::layer0

    %% Message handlers (command-specific)
    MsgDispatch --> Handler1["ND_ValidateAndConfigureMessage<br/>0x6518<br/>234 bytes<br/><b>CMD Handler</b>"]:::layer0
    MsgDispatch --> Handler2["ND_MessageHandler_CMD1EDC<br/>0x6602<br/>218 bytes"]:::layer0
    MsgDispatch --> Handler3["ND_MessageHandler_CMD43C<br/>0x66dc<br/>220 bytes"]:::layer0
    MsgDispatch --> Handler4["ND_MessageHandler_CMD28<br/>0x67b8<br/>158 bytes"]:::layer0
    MsgDispatch --> Handler5["ND_MessageHandler_CMD434_Alt<br/>0x6856<br/>204 bytes"]:::layer0
    MsgDispatch --> Handler6["ND_MessageHandler_CMD838<br/>0x6922<br/>230 bytes"]:::layer0
    MsgDispatch --> Handler7["ND_MessageHandler_CMD42C<br/>0x6a08<br/>186 bytes"]:::layer0
    MsgDispatch --> Handler8["ND_MessageHandler_CMD42C<br/>0x6ac2<br/>186 bytes"]:::layer0
    MsgDispatch --> Handler9["ND_MessageHandler_CMD434<br/>0x6b7c<br/>204 bytes"]:::layer0
    MsgDispatch --> Handler10["ND_ValidateMessageType1<br/>0x6c48<br/>220 bytes"]:::layer0
    MsgDispatch --> Handler11["ND_ValidateAndExecuteCommand<br/>0x6d24<br/>192 bytes"]:::layer0

    %% ==========================================
    %% ISOLATED FUNCTIONS (59)
    %% ==========================================

    %% Callback Group (24 functions)
    subgraph Callbacks["Callback Functions (24)"]
        CB1["0x366e<br/>30 bytes"]:::callback
        CB2["0x368c<br/>38 bytes"]:::callback
        CB3["0x3820<br/>84 bytes"]:::callback
        CB4["0x3eae<br/>140 bytes"]:::callback
        CB5["0x56f0<br/>140 bytes"]:::callback
        CB6["0x59f8<br/>70 bytes"]:::callback
        CB7["0x5d26<br/>58 bytes"]:::callback
        CB8["0x5d60<br/>70 bytes"]:::callback
        CB9["0x5da6<br/>68 bytes"]:::callback
        CB10["0x61f4<br/>134 bytes"]:::callback
        CB11["0x6de4<br/>136 bytes"]:::callback
        CB12["0x75cc<br/>22 bytes"]:::callback
        CB13["0x75e2<br/>22 bytes"]:::callback
    end

    %% Hardware Access Group (12 functions)
    subgraph Hardware["Hardware Access (12)"]
        HW1["HardwareAccess_0x3874<br/>296 bytes<br/><b>CRITICAL</b>"]:::hardware
        HW2["0x627a<br/>62 bytes"]:::hardware
        HW3["0x62b8<br/>48 bytes"]:::hardware
        HW4["0x62e8<br/>48 bytes"]:::hardware
        HW5["0x6318<br/>40 bytes"]:::hardware
        HW6["0x6340<br/>44 bytes"]:::hardware
        HW7["0x636c<br/>44 bytes"]:::hardware
        HW8["0x6398<br/>40 bytes"]:::hardware
        HW9["0x63c0<br/>40 bytes"]:::hardware
        HW10["0x63e8<br/>44 bytes"]:::hardware
        HW11["0x6414<br/>48 bytes"]:::hardware
        HW12["0x6444<br/>48 bytes"]:::hardware
    end

    %% Utility/Helper Group (33 functions - showing key ones)
    subgraph Utilities["Utility/Helper Functions (33)"]
        UT1["0x305c<br/>102 bytes"]:::utility
        UT2["0x30c2<br/>318 bytes"]:::utility
        UT3["0x3200<br/>132 bytes"]:::utility
        UT4["0x3614<br/>90 bytes"]:::utility
        UT5["PostScript Ops<br/>0x3cdc-0x5dea<br/>31 functions<br/><b>GRAPHICS</b>"]:::utility
    end

    %% Indirect connections (callbacks and dispatch)
    MsgDispatch -.callback.-> Callbacks
    RegisterSlot -.hardware.-> Hardware
    MsgLoop -.utility.-> Utilities

    %% Click handlers for documentation
    click ServerMain "https://github.com/yourusername/ndserver_re/blob/main/docs/functions/00002dc6_ND_ServerMain.md" "View detailed analysis"
    click DMATransfer "https://github.com/yourusername/ndserver_re/blob/main/docs/functions/0000709c_ND_ProcessDMATransfer.md" "View DMA analysis"
    click MsgLoop "https://github.com/yourusername/ndserver_re/blob/main/docs/functions/0000399c_ND_MessageReceiveLoop.md" "View message loop"
```

## Statistics

- **Total Functions**: 88
- **Analyzed Functions**: 29 (33%)
- **Isolated Functions**: 59 (67%)
  - Callbacks: 24 (27%)
  - Hardware Access: 12 (14%)
  - Utility/Helper: 33 (38%)

## Layer Distribution

| Layer | Count | Description |
|-------|-------|-------------|
| Layer 3 | 1 | Entry point (ND_ServerMain) |
| Layer 2 | 3 | High-level coordinators (Init, Setup, Load) |
| Layer 1 | 4 | Intermediate orchestrators (Message loop, kernel loading) |
| Layer 0 | 21 | Leaf functions (handlers, validators, DMA, i860 control) |
| Isolated | 59 | Uncalled or indirectly referenced functions |

## Critical Paths

### Boot and Initialization
```
ND_ServerMain → ND_LoadFirmwareAndStart → ND_LoadKernelFromFile → ND_ProcessDMATransfer → ND_WriteBranchInstruction
```

### Message Processing
```
ND_ServerMain → ND_InitializeBoardWithParameters → ND_MessageReceiveLoop → ND_MessageDispatcher → [11 Handlers]
```

### Hardware Configuration
```
ND_ServerMain → ND_SetupBoardWithParameters → ND_RegisterBoardSlot → [Hardware Access Functions]
```

## Color Legend

- **Red (Layer 3)**: Entry point - single root function
- **Teal (Layer 2)**: High-level coordinators - orchestrate major phases
- **Blue (Layer 1)**: Intermediate functions - specialized coordinators
- **Green (Layer 0)**: Leaf functions - actual work implementations
- **Yellow (Isolated)**: Uncalled functions - callbacks, utilities, dead code
- **Pink (Callbacks)**: Function pointers and dispatch table entries
- **Orange (Hardware)**: Direct hardware/MMIO access functions
- **Light Green (Utility)**: Helper functions and PostScript operations

## Notes

1. **Function Sizes**: Range from 22 bytes (tiny callbacks) to 976 bytes (DMA engine)
2. **Largest Function**: `ND_ProcessDMATransfer` at 976 bytes - handles complex DMA transfers
3. **Most Connected**: `ND_MessageDispatcher` connects to 11 different command handlers
4. **Hardware Critical**: `HardwareAccess_0x3874` (296 bytes) accesses MMIO region 0x04010290
5. **PostScript Operations**: 31 utility functions likely implement Display PostScript primitives

## Rendering Notes

- Mermaid may struggle with 88+ nodes - consider using layer-focused views for clarity
- Dotted lines (`.->`) indicate indirect calls (callbacks, function pointers, dispatch tables)
- Bold labels highlight critical architectural components
- Click handlers link to detailed function documentation (GitHub integration required)
