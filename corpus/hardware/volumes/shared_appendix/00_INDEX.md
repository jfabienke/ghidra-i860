# Shared Appendix — Cross-Volume Reference Materials

**Purpose**: Central repository for reference data used across all three volumes

**Contents**:
- Complete register maps
- Glossary of terms
- ASCII diagrams and memory maps
- Timing charts and specifications
- Test data and validation checksums
- Bibliography and sources

---

## Appendix A: Complete Register Map

**File**: [appendix_a_register_map.md](appendix_a_register_map.md)

Every documented register with:
- Absolute address
- Access type (R/W/RO/WO)
- Size (8/16/32-bit)
- Board specificity (Cube/Station/Both)
- Volume reference
- Confidence level

**Organization**:
- By address (ascending)
- By subsystem
- By board variant

---

## Appendix B: Glossary

**File**: [appendix_b_glossary.md](appendix_b_glossary.md)

Complete glossary including:
- Acronyms (ASIC, NBIC, ISP, DMA, etc.)
- NeXT-specific terms (Slot Space, Board Space, etc.)
- Technical terms
- Cross-references to volume definitions

---

## Appendix C: Memory Maps

**File**: [appendix_c_memory_maps.md](appendix_c_memory_maps.md)

ASCII diagrams of all address spaces:
- Global memory map (0x00000000-0xFFFFFFFF)
- MMIO region detail (0x02000000-0x02FFFFFF)
- VRAM layout (0x03000000-0x03FFFFFF)
- Slot space decode (0x0?xxxxxx)
- Board space decode (0x?xxxxxxx)

---

## Appendix D: Timing Charts

**File**: [appendix_d_timing_charts.md](appendix_d_timing_charts.md)

Timing specifications:
- CPU bus cycles
- DMA burst timing
- SCSI bus phases
- Ethernet frame gaps
- Interrupt latency
- VBL timing

---

## Appendix E: Test Data

**File**: [appendix_e_test_data.md](appendix_e_test_data.md)

Validation data:
- ROM checksums (MD5, SHA-256)
- Expected register values
- MMIO access patterns
- Test vectors
- Known-good results

---

## Appendix F: Bibliography

**File**: [appendix_f_bibliography.md](appendix_f_bibliography.md)

Source materials:
- Primary sources (ROM v3.3, Previous emulator)
- Secondary sources (datasheets, manuals)
- Community resources
- Historical documents
- Related projects

---

## Navigation

- [Volume I: System Architecture](../volume1_system_architecture/00_CONTENTS.md)
- [Volume II: Hardware & ASIC](../volume2_hardware_and_asic/00_CONTENTS.md)
- [Volume III: Firmware & Emulation](../volume3_firmware_and_emulation/00_CONTENTS.md)
- [Master Index](../MASTER_INDEX.md)
