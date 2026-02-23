PYTHON ?= python3

# Example defaults; override on command line.
ND33 ?= artifacts/incoming/nd33/NDserver
OS42 ?= artifacts/incoming/os42/m68k_exec_i860seg.bin

.PHONY: extract-nd33 extract-os42 compare

extract-nd33:
	./scripts/extract_ndserver_components.sh "$(ND33)" artifacts/extracted/nd33

extract-os42:
	./scripts/extract_ndserver_components.sh "$(OS42)" artifacts/extracted/os42

compare:
	$(PYTHON) scripts/compare_ndserver.py \
	  --a "$(ND33)" \
	  --b "$(OS42)" \
	  --out-json reports/ndserver_33_vs_42.json \
	  --out-md reports/ndserver_33_vs_42.md
