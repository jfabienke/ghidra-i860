#!/usr/bin/env python3
"""Print a concise report for one or all swarm runs.

Usage:
    python -m scripts.swarm.report <claims.db> [--run RUN_ID]
"""

import argparse
import json
import sqlite3
import sys
from pathlib import Path


def report_run(conn, run_id):
    """Print summary for a single run."""
    # Run metadata
    run = conn.execute(
        "SELECT * FROM runs WHERE run_id = ?", (run_id,)
    ).fetchone()
    if not run:
        print(f"  Run {run_id}: not found", file=sys.stderr)
        return

    config = json.loads(run["config_json"]) if run["config_json"] else {}
    backend = config.get("backend", "api")

    # Counts
    claims = conn.execute(
        "SELECT COUNT(*) as n FROM claims WHERE run_id = ?", (run_id,)
    ).fetchone()["n"]

    verdicts = {}
    for status in ("accept", "revise", "reject"):
        verdicts[status] = conn.execute(
            "SELECT COUNT(*) as n FROM verifications "
            "WHERE run_id = ? AND status = ?", (run_id, status)
        ).fetchone()["n"]

    gate_pass = conn.execute(
        "SELECT COUNT(*) as n FROM gatekeeper_results "
        "WHERE run_id = ? AND passed = 1", (run_id,)
    ).fetchone()["n"]
    gate_fail = conn.execute(
        "SELECT COUNT(*) as n FROM gatekeeper_results "
        "WHERE run_id = ? AND passed = 0", (run_id,)
    ).fetchone()["n"]

    # Schema failures (claims with no gatekeeper result = schema fail)
    schema_fail = claims - gate_pass - gate_fail

    # Tokens
    claim_tok = conn.execute(
        "SELECT COALESCE(SUM(intent_tokens_in),0) as ti, "
        "COALESCE(SUM(intent_tokens_out),0) as to_ "
        "FROM claims WHERE run_id = ?", (run_id,)
    ).fetchone()
    verif_tok = conn.execute(
        "SELECT COALESCE(SUM(tokens_in),0) as ti, "
        "COALESCE(SUM(tokens_out),0) as to_ "
        "FROM verifications WHERE run_id = ?", (run_id,)
    ).fetchone()
    contra_tok = conn.execute(
        "SELECT COALESCE(SUM(tokens_in),0) as ti, "
        "COALESCE(SUM(tokens_out),0) as to_ "
        "FROM contrarians WHERE run_id = ?", (run_id,)
    ).fetchone()

    synth_tok = conn.execute(
        "SELECT COALESCE(SUM(tokens_in),0) as ti, "
        "COALESCE(SUM(tokens_out),0) as to_ "
        "FROM syntheses WHERE run_id = ?", (run_id,)
    ).fetchone()

    tok_in = (claim_tok["ti"] + verif_tok["ti"]
              + contra_tok["ti"] + synth_tok["ti"])
    tok_out = (claim_tok["to_"] + verif_tok["to_"]
               + contra_tok["to_"] + synth_tok["to_"])

    # Per-stage breakdown
    n_contrarians = conn.execute(
        "SELECT COUNT(*) as n FROM contrarians WHERE run_id = ?", (run_id,)
    ).fetchone()["n"]

    # Top intents
    top_intents = conn.execute(
        "SELECT function_id, function_name, "
        "json_extract(intent_json, '$.primary_intent') as intent, "
        "json_extract(intent_json, '$.confidence') as conf "
        "FROM claims WHERE run_id = ? "
        "AND function_id IN "
        "(SELECT function_id FROM verifications "
        " WHERE run_id = ? AND status = 'accept') "
        "ORDER BY conf DESC LIMIT 10",
        (run_id, run_id)
    ).fetchall()

    # Print
    print(f"Run {run_id}  model={run['model']}  backend={backend}")
    print(f"  Claims:      {claims:>4d}")
    if schema_fail > 0:
        print(f"  Schema fail: {schema_fail:>4d}")
    print(f"  Gate pass:   {gate_pass:>4d}   fail: {gate_fail}")
    print(f"  Accept:      {verdicts['accept']:>4d}   "
          f"revise: {verdicts['revise']}   "
          f"reject: {verdicts['reject']}")
    print(f"  Contrarians: {n_contrarians:>4d}")
    print(f"  Tokens in:   {tok_in:>10,}   out: {tok_out:>10,}   "
          f"total: {tok_in + tok_out:>10,}")

    if top_intents:
        print(f"  Top accepted:")
        for row in top_intents:
            intent = (row["intent"] or "?")[:55]
            print(f"    {row['function_id']} {row['function_name']:<20s} "
                  f"[{row['conf']:>3}] {intent}")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Report swarm run results"
    )
    parser.add_argument("db", help="Path to claims.db")
    parser.add_argument("--run", help="Report a specific run ID (default: all)")
    args = parser.parse_args()

    db_path = Path(args.db)
    if not db_path.exists():
        print(f"Error: {db_path} not found", file=sys.stderr)
        sys.exit(1)

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row

    if args.run:
        report_run(conn, args.run)
    else:
        runs = conn.execute(
            "SELECT run_id FROM runs ORDER BY started_at"
        ).fetchall()
        if not runs:
            print("No runs found.")
        for row in runs:
            report_run(conn, row["run_id"])

    conn.close()


if __name__ == "__main__":
    main()
