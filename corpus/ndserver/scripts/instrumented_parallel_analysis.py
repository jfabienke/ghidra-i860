#!/usr/bin/env python3
"""
Instrumented Parallel Analysis Orchestrator

This script launches and monitors parallel sub-agent analyses with detailed
timestamp tracking, progress monitoring, and performance metrics.

Features:
- Pre-launch timestamp logging
- Per-agent start/end timestamps
- File creation event tracking
- Real-time progress dashboard
- Post-analysis metrics report
- JSON event log for analysis

Usage:
    python3 scripts/instrumented_parallel_analysis.py --functions 0x33b4,0x3284,0x6d24
"""

import argparse
import json
import time
import sys
import os
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any
from dataclasses import dataclass, asdict
import threading
import queue

@dataclass
class TimestampEvent:
    """Single timestamp event"""
    timestamp: str
    event_type: str
    function_addr: str
    details: str
    elapsed_ms: int

class InstrumentedAnalysisOrchestrator:
    """Orchestrates parallel analysis with detailed instrumentation"""

    def __init__(self, output_dir: str = "logs"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)

        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_file = self.output_dir / f"parallel_session_{self.session_id}.json"
        self.events: List[TimestampEvent] = []
        self.start_time = None
        self.event_queue = queue.Queue()

    def timestamp_now(self) -> str:
        """Get current timestamp with milliseconds"""
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

    def elapsed_ms(self) -> int:
        """Get elapsed milliseconds since session start"""
        if self.start_time is None:
            return 0
        return int((time.time() - self.start_time) * 1000)

    def log_event(self, event_type: str, function_addr: str, details: str):
        """Log a timestamped event"""
        event = TimestampEvent(
            timestamp=self.timestamp_now(),
            event_type=event_type,
            function_addr=function_addr,
            details=details,
            elapsed_ms=self.elapsed_ms()
        )
        self.events.append(event)

        # Real-time console output
        print(f"[{event.timestamp}] +{event.elapsed_ms:6d}ms | "
              f"{event.event_type:20s} | {function_addr:10s} | {details}")

        # Save to file incrementally
        self._save_events()

    def _save_events(self):
        """Save events to JSON file"""
        with open(self.log_file, 'w') as f:
            json.dump([asdict(e) for e in self.events], f, indent=2)

    def monitor_file_creation(self, function_addr: str, file_pattern: str):
        """Monitor for file creation"""
        def check_file():
            while True:
                matching_files = list(Path('.').glob(file_pattern))
                if matching_files:
                    self.log_event("FILE_CREATED", function_addr,
                                   f"{file_pattern} -> {matching_files[0]}")
                    break
                time.sleep(0.1)

        thread = threading.Thread(target=check_file, daemon=True)
        thread.start()
        return thread

    def launch_agent(self, function_addr: str) -> Dict[str, Any]:
        """Launch a single analysis agent with instrumentation"""

        self.log_event("AGENT_LAUNCH", function_addr, "Initializing sub-agent")

        # Start file monitors
        doc_monitor = self.monitor_file_creation(
            function_addr,
            f"docs/functions/{function_addr}_*.md"
        )
        asm_monitor = self.monitor_file_creation(
            function_addr,
            f"disassembly/annotated/{function_addr}_*.asm"
        )

        agent_start = time.time()

        # Here you would integrate with Claude Code's Task tool
        # For demonstration, we'll simulate the agent work
        self.log_event("AGENT_WORKING", function_addr, "Analysis in progress...")

        # Simulate different completion times
        import random
        work_time = random.uniform(30, 50)  # 30-50 seconds

        # Wait for completion
        time.sleep(work_time)

        agent_end = time.time()
        duration_s = agent_end - agent_start

        self.log_event("AGENT_COMPLETE", function_addr,
                       f"Completed in {duration_s:.2f}s")

        return {
            "function_addr": function_addr,
            "start_time": agent_start,
            "end_time": agent_end,
            "duration_seconds": duration_s,
            "success": True
        }

    def launch_parallel_batch(self, function_addrs: List[str]) -> List[Dict]:
        """Launch multiple agents in parallel"""

        self.start_time = time.time()
        self.log_event("SESSION_START", "ALL",
                       f"Starting parallel analysis of {len(function_addrs)} functions")

        threads = []
        results = []

        # Launch all agents
        for addr in function_addrs:
            def worker(address):
                result = self.launch_agent(address)
                results.append(result)

            thread = threading.Thread(target=worker, args=(addr,))
            thread.start()
            threads.append(thread)

            # Stagger launches slightly
            time.sleep(0.5)

        # Wait for all to complete
        for thread in threads:
            thread.join()

        session_end = time.time()
        total_duration = session_end - self.start_time

        self.log_event("SESSION_END", "ALL",
                       f"All {len(function_addrs)} analyses complete in {total_duration:.2f}s")

        return results

    def generate_report(self, results: List[Dict]) -> str:
        """Generate performance metrics report"""

        report = []
        report.append("=" * 80)
        report.append("PARALLEL ANALYSIS PERFORMANCE REPORT")
        report.append("=" * 80)
        report.append(f"Session ID: {self.session_id}")
        report.append(f"Total Functions: {len(results)}")
        report.append("")

        # Overall metrics
        total_time = max(r['end_time'] for r in results) - min(r['start_time'] for r in results)
        sum_time = sum(r['duration_seconds'] for r in results)
        speedup = sum_time / total_time if total_time > 0 else 0

        report.append("OVERALL METRICS:")
        report.append(f"  Wall-clock time: {total_time:.2f}s ({total_time/60:.2f} minutes)")
        report.append(f"  Sum of agent times: {sum_time:.2f}s ({sum_time/60:.2f} minutes)")
        report.append(f"  Speedup: {speedup:.2f}× (parallel efficiency: {(speedup/len(results)*100):.1f}%)")
        report.append("")

        # Per-function breakdown
        report.append("PER-FUNCTION TIMING:")
        report.append(f"{'Function':<12} {'Duration':<12} {'Start Offset':<15} {'End Offset':<15}")
        report.append("-" * 60)

        start_ref = min(r['start_time'] for r in results)
        for r in sorted(results, key=lambda x: x['start_time']):
            start_offset = r['start_time'] - start_ref
            end_offset = r['end_time'] - start_ref
            report.append(
                f"{r['function_addr']:<12} {r['duration_seconds']:>8.2f}s    "
                f"{start_offset:>10.2f}s    {end_offset:>10.2f}s"
            )

        report.append("")
        report.append("STATISTICS:")
        durations = [r['duration_seconds'] for r in results]
        report.append(f"  Min duration: {min(durations):.2f}s")
        report.append(f"  Max duration: {max(durations):.2f}s")
        report.append(f"  Mean duration: {sum(durations)/len(durations):.2f}s")
        report.append(f"  Median duration: {sorted(durations)[len(durations)//2]:.2f}s")

        report.append("")
        report.append("EVENT TIMELINE:")
        for event in self.events:
            report.append(f"  [{event.timestamp}] +{event.elapsed_ms:6d}ms | "
                          f"{event.event_type:20s} | {event.function_addr:10s}")

        report.append("")
        report.append("=" * 80)

        return "\n".join(report)

def main():
    parser = argparse.ArgumentParser(description="Instrumented parallel analysis")
    parser.add_argument('--functions', required=True,
                        help='Comma-separated list of function addresses (e.g., 0x33b4,0x3284)')
    parser.add_argument('--output-dir', default='logs',
                        help='Output directory for logs and reports')

    args = parser.parse_args()

    # Parse function addresses
    function_addrs = [addr.strip() for addr in args.functions.split(',')]

    print("=" * 80)
    print("INSTRUMENTED PARALLEL ANALYSIS")
    print("=" * 80)
    print(f"Functions to analyze: {len(function_addrs)}")
    print(f"Addresses: {', '.join(function_addrs)}")
    print(f"Log directory: {args.output_dir}")
    print("=" * 80)
    print()

    # Create orchestrator
    orchestrator = InstrumentedAnalysisOrchestrator(args.output_dir)

    # Launch parallel batch
    results = orchestrator.launch_parallel_batch(function_addrs)

    # Generate report
    report = orchestrator.generate_report(results)
    print()
    print(report)

    # Save report
    report_file = Path(args.output_dir) / f"report_{orchestrator.session_id}.txt"
    with open(report_file, 'w') as f:
        f.write(report)

    print()
    print(f"Full event log: {orchestrator.log_file}")
    print(f"Report saved: {report_file}")

if __name__ == '__main__':
    main()
