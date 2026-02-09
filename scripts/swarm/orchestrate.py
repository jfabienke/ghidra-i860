#!/usr/bin/env python3
"""Swarm orchestrator for ND i860 firmware intent analysis.

Dispatches per-function shards to Claude agents in a pipeline:
  intent → gatekeeper → verifier → contrarian → synthesizer

Usage:
    python -m scripts.swarm.orchestrate <sharded_dir> [options]

Options:
    --model MODEL       Claude model (default: claude-sonnet-4-5-20250929)
    --out DIR           Output directory (default: <sharded_dir>/../swarm_run_<ts>/)
    --dry-run           Assemble prompts without API calls; write to --out
    --max-functions N   Process at most N functions (0 = all, default: 0)
    --skip-contrarian   Skip contrarian pass
    --skip-synthesis    Skip synthesis pass
    --concurrency N     Max parallel API calls (default: 4)
    --resume RUN_ID     Resume a previous run (requires --out pointing to existing dir)

Requires ANTHROPIC_API_KEY environment variable (unless --dry-run).
"""

import argparse
import asyncio
import json
import os
import sys
import time
import uuid
from pathlib import Path

from . import prompts
from .schemas import validate_intent, validate_verification, validate_contrarian
from .store import ClaimStore


# ---------- API wrapper ----------

async def call_claude(client, model, system, messages, semaphore):
    """Call Claude API with rate limiting via semaphore."""
    async with semaphore:
        start = time.monotonic()
        response = await asyncio.to_thread(
            client.messages.create,
            model=model,
            max_tokens=4096,
            system=system,
            messages=messages,
        )
        elapsed_ms = int((time.monotonic() - start) * 1000)

        text = ""
        for block in response.content:
            if block.type == "text":
                text += block.text

        return {
            "text": text,
            "tokens_in": response.usage.input_tokens,
            "tokens_out": response.usage.output_tokens,
            "latency_ms": elapsed_ms,
            "model": response.model,
        }


def parse_json_response(text):
    """Extract JSON from LLM response, handling markdown code fences."""
    text = text.strip()
    if text.startswith("```"):
        # Strip markdown code fence
        lines = text.split("\n")
        # Remove first and last ``` lines
        if lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        text = "\n".join(lines)
    try:
        return json.loads(text)
    except json.JSONDecodeError as e:
        return {"_parse_error": str(e), "_raw_text": text[:2000]}


# ---------- Pipeline stages ----------

async def run_intent(client, model, shard, semaphore):
    """Run intent agent on a single function shard."""
    messages = prompts.build_intent_messages(shard)
    result = await call_claude(
        client, model, prompts.INTENT_SYSTEM, messages, semaphore
    )
    claim = parse_json_response(result["text"])
    return claim, result


async def run_verifier(client, model, shard, claim, semaphore):
    """Run verifier agent on a claim."""
    messages = prompts.build_verifier_messages(shard, claim)
    result = await call_claude(
        client, model, prompts.VERIFIER_SYSTEM, messages, semaphore
    )
    verification = parse_json_response(result["text"])
    return verification, result


async def run_contrarian(client, model, shard, claim, semaphore):
    """Run contrarian agent on a claim."""
    messages = prompts.build_contrarian_messages(shard, claim)
    result = await call_claude(
        client, model, prompts.CONTRARIAN_SYSTEM, messages, semaphore
    )
    contrarian = parse_json_response(result["text"])
    return contrarian, result


async def run_synthesizer(client, model, accepted_claims, callgraph, semaphore):
    """Run synthesizer agent on accepted claims."""
    messages = prompts.build_synthesizer_messages(accepted_claims, callgraph)
    result = await call_claude(
        client, model, prompts.SYNTHESIZER_SYSTEM, messages, semaphore
    )
    synthesis = parse_json_response(result["text"])
    return synthesis, result


# ---------- Dry-run mode ----------

def dry_run_function(shard, output_dir):
    """Write assembled prompts to disk without calling API."""
    func = shard["function"]
    func_id = func["entry"]
    func_dir = output_dir / "dry_run" / f"{func_id}_{func['name']}"
    func_dir.mkdir(parents=True, exist_ok=True)

    # Intent prompt
    messages = prompts.build_intent_messages(shard)
    with open(func_dir / "intent_system.txt", "w") as f:
        f.write(prompts.INTENT_SYSTEM)
    with open(func_dir / "intent_user.txt", "w") as f:
        f.write(messages[0]["content"])

    # Estimate token count (rough: 4 chars per token)
    system_chars = len(prompts.INTENT_SYSTEM)
    user_chars = len(messages[0]["content"])
    est_tokens = (system_chars + user_chars) // 4

    return {
        "function_id": func_id,
        "function_name": func["name"],
        "system_chars": system_chars,
        "user_chars": user_chars,
        "estimated_tokens": est_tokens,
        "insn_count": len(shard["insns"]),
        "priority_tags": shard["context"]["priority_tags"],
    }


# ---------- Main pipeline ----------

async def process_function(client, model, shard, store, run_id,
                           semaphore, skip_contrarian=False):
    """Full pipeline for one function: intent → gate → verify → contrarian."""
    func = shard["function"]
    func_id = func["entry"]
    func_name = func["name"]

    # 1. Intent
    claim, intent_result = await run_intent(client, model, shard, semaphore)

    # Validate intent schema before DB insert
    claim, schema_errors = validate_intent(claim)
    if schema_errors:
        print(f"  SCHEMA_FAIL: {func_id} {func_name}: {schema_errors[0]}")
        # Store raw claim with validation errors attached
        claim["_schema_errors"] = schema_errors
        store.insert_claim(
            run_id, func_id, func_name, claim, intent_result["model"],
            intent_result["tokens_in"], intent_result["tokens_out"],
            intent_result["latency_ms"],
        )
        return {"function_id": func_id, "status": "schema_fail",
                "errors": schema_errors}

    store.insert_claim(
        run_id, func_id, func_name, claim, intent_result["model"],
        intent_result["tokens_in"], intent_result["tokens_out"],
        intent_result["latency_ms"],
    )

    # 2. Gatekeeper (local, no API call)
    passed, reasons = prompts.gatekeeper_check(claim)
    store.insert_gatekeeper_result(run_id, func_id, passed, reasons)

    if not passed:
        print(f"  GATE_FAIL: {func_id} {func_name}: {reasons[0]}")
        return {"function_id": func_id, "status": "gatekeeper_failed",
                "reasons": reasons}

    # 3. Verifier
    verification, verify_result = await run_verifier(
        client, model, shard, claim, semaphore
    )
    verification, v_errors = validate_verification(verification)
    if v_errors:
        print(f"  VERIFY_SCHEMA_FAIL: {func_id}: {v_errors[0]}")
        verification["_schema_errors"] = v_errors
        status = "reject"  # schema failure = automatic reject
    else:
        status = verification.get("status", "reject")
    store.insert_verification(
        run_id, func_id, status, verification, verify_result["model"],
        verify_result["tokens_in"], verify_result["tokens_out"],
        verify_result["latency_ms"],
    )

    # 4. Contrarian (optional)
    if not skip_contrarian and status == "accept":
        contrarian, contra_result = await run_contrarian(
            client, model, shard, claim, semaphore
        )
        contrarian, c_errors = validate_contrarian(contrarian)
        if c_errors:
            print(f"  CONTRA_SCHEMA_FAIL: {func_id}: {c_errors[0]}")
            contrarian["_schema_errors"] = c_errors
            verdict = "schema_fail"
        else:
            verdict = contrarian.get("verdict", "unknown")
        store.insert_contrarian(
            run_id, func_id, verdict, contrarian, contra_result["model"],
            contra_result["tokens_in"], contra_result["tokens_out"],
            contra_result["latency_ms"],
        )
    else:
        verdict = None

    intent_str = claim.get("primary_intent", "?")[:60]
    conf = claim.get("confidence", "?")
    print(f"  {status.upper()}: {func_id} {func_name} "
          f"[conf={conf}] {intent_str}")

    return {
        "function_id": func_id,
        "status": status,
        "confidence": conf,
        "primary_intent": claim.get("primary_intent"),
        "contrarian_verdict": verdict,
    }


async def run_pipeline(args):
    """Main pipeline execution."""
    sharded_dir = Path(args.sharded_dir)
    manifest_path = sharded_dir / "manifest.json"
    if not manifest_path.exists():
        print(f"Error: {manifest_path} not found", file=sys.stderr)
        print("Run the sharder first: python -m scripts.swarm.shard <factpack_dir>",
              file=sys.stderr)
        sys.exit(1)

    with open(manifest_path) as f:
        manifest = json.load(f)

    # Resume validation: --resume requires --out
    if args.resume and not args.out:
        print("Error: --resume requires --out pointing to the previous "
              "run's output directory", file=sys.stderr)
        sys.exit(1)

    # Output directory
    if args.out:
        output_dir = Path(args.out)
    else:
        ts = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
        output_dir = sharded_dir.parent / f"swarm_run_{ts}"
    output_dir.mkdir(parents=True, exist_ok=True)

    run_id = args.resume or str(uuid.uuid4())[:8]

    print(f"Swarm orchestrator")
    print(f"  Shards:    {sharded_dir}")
    print(f"  Output:    {output_dir}")
    print(f"  Run ID:    {run_id}")
    print(f"  Model:     {args.model}")
    print(f"  Functions: {len(manifest['shards'])}")
    print(f"  Concurrency: {args.concurrency}")
    print(f"  Dry run:   {args.dry_run}")
    if args.resume:
        print(f"  Mode:      RESUME")
    print()

    # Load all shards
    shards = {}
    for shard_info in manifest["shards"]:
        shard_path = sharded_dir / shard_info["file"]
        with open(shard_path) as f:
            shard = json.load(f)
        shards[shard_info["entry"]] = shard

    # Set BRI function cache for gatekeeper
    bri_funcs = [
        s["entry"] for s in manifest["shards"]
        if "unresolved_bri" in s.get("priority_tags", [])
    ]
    prompts.set_bri_functions(bri_funcs)

    # Apply max-functions limit
    shard_order = [s["entry"] for s in manifest["shards"]]
    if args.max_functions > 0:
        shard_order = shard_order[:args.max_functions]

    # ---------- Dry-run mode ----------
    if args.dry_run:
        print("=== DRY RUN: assembling prompts without API calls ===\n")
        dry_results = []
        total_tokens = 0
        for func_entry in shard_order:
            shard = shards[func_entry]
            result = dry_run_function(shard, output_dir)
            dry_results.append(result)
            total_tokens += result["estimated_tokens"]
            tags = ", ".join(result["priority_tags"]) or "-"
            print(f"  {result['function_id']} {result['function_name']:<24s} "
                  f"~{result['estimated_tokens']:>5d} tokens  [{tags}]")

        print(f"\nTotal estimated input tokens: {total_tokens:,}")
        print(f"Estimated cost (Sonnet @ $3/MTok in): "
              f"${total_tokens * 3 / 1_000_000:.2f}")
        print(f"Estimated cost (Haiku @ $0.80/MTok in): "
              f"${total_tokens * 0.80 / 1_000_000:.2f}")

        # Write dry-run summary
        summary = {
            "run_id": run_id,
            "mode": "dry_run",
            "model": args.model,
            "function_count": len(dry_results),
            "total_estimated_tokens": total_tokens,
            "functions": dry_results,
        }
        with open(output_dir / "dry_run_summary.json", "w") as f:
            json.dump(summary, f, indent=2)

        print(f"\nDry-run prompts written to {output_dir}/dry_run/")
        print(f"Summary: {output_dir}/dry_run_summary.json")
        return

    # ---------- Live mode ----------
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("Error: ANTHROPIC_API_KEY not set", file=sys.stderr)
        sys.exit(1)

    try:
        import anthropic
    except ImportError:
        print("Error: anthropic SDK not installed. Run: pip install anthropic",
              file=sys.stderr)
        sys.exit(1)

    client = anthropic.Anthropic(api_key=api_key)

    # Initialize store
    store = ClaimStore(output_dir / "claims.db")

    # Create or resume run
    if args.resume:
        if not store.run_exists(run_id):
            print(f"Error: run_id '{run_id}' not found in {output_dir}/claims.db",
                  file=sys.stderr)
            store.close()
            sys.exit(1)
        existing = store.get_completed_function_ids(run_id)
        shard_order = [e for e in shard_order if e not in existing]
        print(f"Resuming: {len(existing)} already done, "
              f"{len(shard_order)} remaining\n")
    else:
        store.create_run(
            run_id,
            factpack_source=str(sharded_dir),
            binary_sha256=manifest.get("binary_sha256"),
            model=args.model,
            config={
                "max_functions": args.max_functions,
                "skip_contrarian": args.skip_contrarian,
                "skip_synthesis": args.skip_synthesis,
                "concurrency": args.concurrency,
            },
        )

    if not shard_order:
        print("All functions already processed.")
        store.close()
        return

    # Process functions with true concurrency via asyncio.gather
    semaphore = asyncio.Semaphore(args.concurrency)
    total = len(shard_order)

    print(f"=== Phase 1: Intent + Verify + Contrarian "
          f"({total} functions, concurrency={args.concurrency}) ===\n")

    # Progress-tracking wrapper
    progress_lock = asyncio.Lock()
    progress = {"done": 0}

    async def process_with_progress(func_entry):
        shard = shards[func_entry]
        func = shard["function"]
        result = await process_function(
            client, args.model, shard, store, run_id, semaphore,
            skip_contrarian=args.skip_contrarian,
        )
        async with progress_lock:
            progress["done"] += 1
            n = progress["done"]
        print(f"  [{n}/{total}] done: {func['entry']} {func['name']}")
        return result

    tasks = [process_with_progress(entry) for entry in shard_order]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Separate successes from exceptions
    final_results = []
    errors = []
    for i, r in enumerate(results):
        if isinstance(r, Exception):
            func_entry = shard_order[i]
            errors.append({"function_id": func_entry, "error": str(r)})
            print(f"  ERROR: {func_entry}: {r}")
        else:
            final_results.append(r)

    # Phase 2: Synthesis
    if not args.skip_synthesis:
        accepted = store.get_accepted_functions(run_id)
        if len(accepted) >= 2:
            print(f"\n=== Phase 2: Synthesis ({len(accepted)} accepted claims) ===\n")

            # Collect accepted claims
            accepted_claims = []
            for fid in accepted:
                claim_row = store.get_claim(run_id, fid)
                if claim_row:
                    accepted_claims.append(claim_row["intent_json"])

            # Build callgraph from shards
            callgraph = []
            for fid in accepted:
                shard = shards.get(fid)
                if shard:
                    for callee in shard.get("callees", []):
                        if callee["entry"] in accepted:
                            callgraph.append((fid, callee["entry"]))

            synthesis, synth_result = await run_synthesizer(
                client, args.model, accepted_claims, callgraph, semaphore
            )
            store.insert_synthesis(
                run_id, synthesis, synth_result["model"],
                synth_result["tokens_in"], synth_result["tokens_out"],
                synth_result["latency_ms"], len(accepted_claims),
            )

            # Write synthesis to file
            with open(output_dir / "synthesis.json", "w") as f:
                json.dump(synthesis, f, indent=2)

            print(f"  Synthesis written to {output_dir}/synthesis.json")
        else:
            print(f"\n  Skipping synthesis: only {len(accepted)} accepted claims")

    # Summary
    stats = store.get_run_stats(run_id)
    print(f"\n=== Run Summary ===")
    print(f"  Claims:           {stats['claims']}")
    print(f"  Accepted:         {stats['verified_accept']}")
    print(f"  Revised:          {stats['verified_revise']}")
    print(f"  Rejected:         {stats['verified_reject']}")
    print(f"  Gate passed:      {stats['gatekeeper_passed']}")
    print(f"  Gate failed:      {stats['gatekeeper_failed']}")
    print(f"  Total tokens in:  {stats['total_tokens_in']:,}")
    print(f"  Total tokens out: {stats['total_tokens_out']:,}")
    if errors:
        print(f"  Errors:           {len(errors)}")
    print(f"\n  Database: {output_dir}/claims.db")
    print(f"  Run ID:   {run_id}")

    # Write results summary
    with open(output_dir / "run_summary.json", "w") as f:
        json.dump({
            "run_id": run_id,
            "model": args.model,
            "stats": stats,
            "results": final_results,
            "errors": errors,
        }, f, indent=2)

    store.close()


def main():
    parser = argparse.ArgumentParser(
        description="Swarm orchestrator for ND i860 intent analysis"
    )
    parser.add_argument("sharded_dir",
                        help="Path to sharded directory (with manifest.json)")
    parser.add_argument("--model", default="claude-sonnet-4-5-20250929",
                        help="Claude model ID")
    parser.add_argument("--out",
                        help="Output directory (required for --resume)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Assemble prompts without API calls")
    parser.add_argument("--max-functions", type=int, default=0,
                        help="Max functions to process (0 = all)")
    parser.add_argument("--skip-contrarian", action="store_true",
                        help="Skip contrarian pass")
    parser.add_argument("--skip-synthesis", action="store_true",
                        help="Skip synthesis pass")
    parser.add_argument("--concurrency", type=int, default=4,
                        help="Max parallel function processing (default: 4)")
    parser.add_argument("--resume",
                        help="Resume a previous run ID (requires --out)")

    args = parser.parse_args()
    asyncio.run(run_pipeline(args))


if __name__ == "__main__":
    main()
