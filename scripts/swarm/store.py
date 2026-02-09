"""SQLite-backed claim store for swarm analysis results.

Stores intent claims, verification results, contrarian challenges,
and synthesis outputs with full provenance tracking.

All per-function tables use composite (run_id, function_id) keys
to preserve cross-run history.
"""

import json
import sqlite3
import time
from pathlib import Path


SCHEMA_SQL = """\
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    started_at REAL,
    factpack_source TEXT,
    binary_sha256 TEXT,
    model TEXT,
    config_json TEXT
);

CREATE TABLE IF NOT EXISTS claims (
    run_id TEXT REFERENCES runs(run_id),
    function_id TEXT,
    function_name TEXT,
    intent_json TEXT,
    intent_model TEXT,
    intent_tokens_in INTEGER,
    intent_tokens_out INTEGER,
    intent_latency_ms INTEGER,
    created_at REAL,
    PRIMARY KEY (run_id, function_id)
);

CREATE TABLE IF NOT EXISTS verifications (
    run_id TEXT REFERENCES runs(run_id),
    function_id TEXT,
    status TEXT CHECK(status IN ('accept', 'revise', 'reject')),
    verification_json TEXT,
    verifier_model TEXT,
    tokens_in INTEGER,
    tokens_out INTEGER,
    latency_ms INTEGER,
    created_at REAL,
    PRIMARY KEY (run_id, function_id)
);

CREATE TABLE IF NOT EXISTS contrarians (
    run_id TEXT REFERENCES runs(run_id),
    function_id TEXT,
    verdict TEXT,
    contrarian_json TEXT,
    contrarian_model TEXT,
    tokens_in INTEGER,
    tokens_out INTEGER,
    latency_ms INTEGER,
    created_at REAL,
    PRIMARY KEY (run_id, function_id)
);

CREATE TABLE IF NOT EXISTS gatekeeper_results (
    run_id TEXT REFERENCES runs(run_id),
    function_id TEXT,
    passed INTEGER,
    reasons_json TEXT,
    created_at REAL,
    PRIMARY KEY (run_id, function_id)
);

CREATE TABLE IF NOT EXISTS syntheses (
    synthesis_id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT REFERENCES runs(run_id),
    synthesis_json TEXT,
    model TEXT,
    tokens_in INTEGER,
    tokens_out INTEGER,
    latency_ms INTEGER,
    input_claim_count INTEGER,
    created_at REAL
);

CREATE INDEX IF NOT EXISTS idx_claims_run ON claims(run_id);
CREATE INDEX IF NOT EXISTS idx_claims_func ON claims(function_id);
CREATE INDEX IF NOT EXISTS idx_verifications_status ON verifications(run_id, status);
"""


class ClaimStore:
    """SQLite-backed store for swarm analysis claims."""

    def __init__(self, db_path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA_SQL)
        self.conn.execute("PRAGMA journal_mode=WAL")

    def close(self):
        self.conn.close()

    # -- Runs --

    def create_run(self, run_id, factpack_source, binary_sha256, model, config):
        self.conn.execute(
            "INSERT INTO runs VALUES (?, ?, ?, ?, ?, ?)",
            (run_id, time.time(), factpack_source, binary_sha256, model,
             json.dumps(config)),
        )
        self.conn.commit()

    def run_exists(self, run_id):
        row = self.conn.execute(
            "SELECT 1 FROM runs WHERE run_id = ?", (run_id,)
        ).fetchone()
        return row is not None

    # -- Claims --

    def insert_claim(self, run_id, function_id, function_name, claim,
                     model, tokens_in, tokens_out, latency_ms):
        self.conn.execute(
            "INSERT INTO claims VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (run_id, function_id, function_name, json.dumps(claim), model,
             tokens_in, tokens_out, latency_ms, time.time()),
        )
        self.conn.commit()

    def get_claim(self, run_id, function_id):
        row = self.conn.execute(
            "SELECT * FROM claims WHERE run_id = ? AND function_id = ?",
            (run_id, function_id),
        ).fetchone()
        if row:
            result = dict(row)
            result["intent_json"] = json.loads(result["intent_json"])
            return result
        return None

    def get_all_claims(self, run_id):
        rows = self.conn.execute(
            "SELECT * FROM claims WHERE run_id = ?", (run_id,)
        ).fetchall()
        results = []
        for row in rows:
            r = dict(row)
            r["intent_json"] = json.loads(r["intent_json"])
            results.append(r)
        return results

    def get_completed_function_ids(self, run_id):
        """Return set of function_ids that have claims in this run."""
        rows = self.conn.execute(
            "SELECT function_id FROM claims WHERE run_id = ?", (run_id,)
        ).fetchall()
        return {r["function_id"] for r in rows}

    # -- Verifications --

    def insert_verification(self, run_id, function_id, status, verification,
                            model, tokens_in, tokens_out, latency_ms):
        self.conn.execute(
            "INSERT INTO verifications VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (run_id, function_id, status, json.dumps(verification), model,
             tokens_in, tokens_out, latency_ms, time.time()),
        )
        self.conn.commit()

    def get_verification(self, run_id, function_id):
        row = self.conn.execute(
            "SELECT * FROM verifications WHERE run_id = ? AND function_id = ?",
            (run_id, function_id),
        ).fetchone()
        if row:
            result = dict(row)
            result["verification_json"] = json.loads(result["verification_json"])
            return result
        return None

    def get_accepted_functions(self, run_id):
        rows = self.conn.execute(
            "SELECT function_id FROM verifications "
            "WHERE run_id = ? AND status = 'accept'",
            (run_id,),
        ).fetchall()
        return [r["function_id"] for r in rows]

    # -- Contrarians --

    def insert_contrarian(self, run_id, function_id, verdict, contrarian,
                          model, tokens_in, tokens_out, latency_ms):
        self.conn.execute(
            "INSERT INTO contrarians VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (run_id, function_id, verdict, json.dumps(contrarian), model,
             tokens_in, tokens_out, latency_ms, time.time()),
        )
        self.conn.commit()

    # -- Gatekeeper --

    def insert_gatekeeper_result(self, run_id, function_id, passed, reasons):
        self.conn.execute(
            "INSERT INTO gatekeeper_results VALUES (?, ?, ?, ?, ?)",
            (run_id, function_id, 1 if passed else 0, json.dumps(reasons),
             time.time()),
        )
        self.conn.commit()

    # -- Synthesis --

    def insert_synthesis(self, run_id, synthesis, model,
                         tokens_in, tokens_out, latency_ms, input_count):
        self.conn.execute(
            "INSERT INTO syntheses (run_id, synthesis_json, model, tokens_in, "
            "tokens_out, latency_ms, input_claim_count, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (run_id, json.dumps(synthesis), model, tokens_in, tokens_out,
             latency_ms, input_count, time.time()),
        )
        self.conn.commit()

    # -- Stats --

    def get_run_stats(self, run_id):
        """Get summary statistics for a run."""
        stats = {}

        row = self.conn.execute(
            "SELECT COUNT(*) as n FROM claims WHERE run_id = ?", (run_id,)
        ).fetchone()
        stats["claims"] = row["n"]

        for status in ("accept", "revise", "reject"):
            row = self.conn.execute(
                "SELECT COUNT(*) as n FROM verifications "
                "WHERE run_id = ? AND status = ?",
                (run_id, status),
            ).fetchone()
            stats[f"verified_{status}"] = row["n"]

        row = self.conn.execute(
            "SELECT COUNT(*) as n FROM gatekeeper_results "
            "WHERE run_id = ? AND passed = 1",
            (run_id,),
        ).fetchone()
        stats["gatekeeper_passed"] = row["n"]

        row = self.conn.execute(
            "SELECT COUNT(*) as n FROM gatekeeper_results "
            "WHERE run_id = ? AND passed = 0",
            (run_id,),
        ).fetchone()
        stats["gatekeeper_failed"] = row["n"]

        row = self.conn.execute(
            "SELECT SUM(intent_tokens_in) as ti, SUM(intent_tokens_out) as to_ "
            "FROM claims WHERE run_id = ?", (run_id,),
        ).fetchone()
        stats["total_tokens_in"] = row["ti"] or 0
        stats["total_tokens_out"] = row["to_"] or 0

        row = self.conn.execute(
            "SELECT SUM(tokens_in) as ti, SUM(tokens_out) as to_ "
            "FROM verifications WHERE run_id = ?", (run_id,),
        ).fetchone()
        stats["total_tokens_in"] += row["ti"] or 0
        stats["total_tokens_out"] += row["to_"] or 0

        row = self.conn.execute(
            "SELECT SUM(tokens_in) as ti, SUM(tokens_out) as to_ "
            "FROM contrarians WHERE run_id = ?", (run_id,),
        ).fetchone()
        stats["total_tokens_in"] += row["ti"] or 0
        stats["total_tokens_out"] += row["to_"] or 0

        row = self.conn.execute(
            "SELECT SUM(tokens_in) as ti, SUM(tokens_out) as to_ "
            "FROM syntheses WHERE run_id = ?", (run_id,),
        ).fetchone()
        stats["total_tokens_in"] += row["ti"] or 0
        stats["total_tokens_out"] += row["to_"] or 0

        return stats
