MACHDRIVER ?= /Users/jvindahl/Development/previous/reverse-engineering/nextdimension-files/firmware/ND_MachDriver_reloc
EXTRACTED_DIR ?= re/nextdimension/firmware/extracted
CLEAN_TEXT_BYTES ?= 0x31000
GROUND_TRUTH_DOCS ?= re/nextdimension/firmware/docs/firmware-analysis.md re/nextdimension/kernel/docs/analysis-findings.md MEMORY.md

.PHONY: extract-firmware-segments validate-firmware-ground-truth

extract-firmware-segments:
	re/nextdimension/firmware/scripts/extract_machdriver_segments.sh "$(MACHDRIVER)" "$(EXTRACTED_DIR)" "$(CLEAN_TEXT_BYTES)"

validate-firmware-ground-truth: extract-firmware-segments
	re/nextdimension/firmware/scripts/validate_extraction_ground_truth.sh "$(EXTRACTED_DIR)" $(GROUND_TRUTH_DOCS)
