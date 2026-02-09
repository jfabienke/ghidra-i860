#!/usr/bin/env python3
"""Stamp Phase 1 analysis outputs with input artifact SHA256 provenance.

Reads each JSON in analysis/phase1/, verifies the input binary exists,
computes its SHA256, and writes a provenance record. Also flags any
outputs that used the buggy call_target()+4 formula.

Usage: python3 stamp_phase1_provenance.py
"""

import json
import hashlib
from pathlib import Path

PHASE1_DIR = Path(__file__).parent.parent / "analysis" / "phase1"
SCRIPTS_DIR = Path(__file__).parent

# Canonical input artifacts and their expected SHA256
ARTIFACTS = {
    "clean_window": Path(__file__).parent.parent / "extracted" / "ND_MachDriver___TEXT_clean_window.bin",
    "kernel": Path(__file__).parent.parent.parent / "kernel" / "i860_kernel.bin",
    "full_text": Path(__file__).parent.parent / "extracted" / "ND_MachDriver___TEXT_section.bin",
}


def sha256_file(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    provenance = {
        "input_artifacts": {},
        "outputs": {},
        "bugs_affecting_outputs": [],
    }

    # Hash all input artifacts
    for name, path in ARTIFACTS.items():
        if path.exists():
            provenance["input_artifacts"][name] = {
                "path": str(path),
                "sha256": sha256_file(path),
                "size_bytes": path.stat().st_size,
            }

    # Hash decoder module
    decoder_path = SCRIPTS_DIR / "i860_decode.py"
    if decoder_path.exists():
        provenance["decoder_sha256"] = sha256_file(decoder_path)

    # Bug record: call_target() had +4 during initial agent run
    provenance["bugs_affecting_outputs"].append({
        "bug": "call_target() added +4 to branch target (should be inst_start + broff26<<2, no +4)",
        "fixed_in": "i860_decode.py self-test update",
        "affected_scripts": ["bri_backward_slice.py (line 189: call targets shifted +4)"],
        "affected_outputs": ["bri_targets.json (call_targets list has +4 offset error; bri backward-slice results unaffected)"],
        "impact": "Call target addresses in bri_targets.json are 4 bytes too high. Does NOT affect the bri source-type classification.",
    })

    # Process each Phase 1 output
    for json_path in sorted(PHASE1_DIR.glob("*.json")):
        if json_path.name == "provenance.json":
            continue
        try:
            data = json.loads(json_path.read_text())
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            provenance["outputs"][json_path.name] = {"error": str(e)}
            continue

        entry = {
            "sha256": sha256_file(json_path),
            "size_bytes": json_path.stat().st_size,
        }

        # Extract input binary reference from metadata
        meta = data.get("metadata", {})
        for key in ("binary", "binary_path", "clean_fw_path", "clean_path", "firmware"):
            if key in meta:
                bp = Path(meta[key])
                # Handle bare filenames by resolving against extracted dir
                if not bp.is_absolute():
                    bp = Path(__file__).parent.parent / "extracted" / bp
                entry["input_binary"] = str(bp)
                if bp.exists():
                    entry["input_sha256"] = sha256_file(bp)
                break

        provenance["outputs"][json_path.name] = entry

    # Write provenance record
    out_path = PHASE1_DIR / "provenance.json"
    out_path.write_text(json.dumps(provenance, indent=2) + "\n")
    print(f"Wrote {out_path}")

    # Summary
    print(f"\nInput artifacts:")
    for name, info in provenance["input_artifacts"].items():
        print(f"  {name}: {info['sha256'][:16]}... ({info['size_bytes']:,} B)")

    print(f"\nOutputs ({len(provenance['outputs'])}):")
    for name, info in provenance["outputs"].items():
        sha_short = info.get("input_sha256", "?")[:16]
        print(f"  {name}: input={sha_short}...")

    if provenance["bugs_affecting_outputs"]:
        print(f"\nBugs affecting outputs ({len(provenance['bugs_affecting_outputs'])}):")
        for bug in provenance["bugs_affecting_outputs"]:
            print(f"  - {bug['bug']}")
            for out in bug["affected_outputs"]:
                print(f"    affects: {out}")


if __name__ == "__main__":
    main()
