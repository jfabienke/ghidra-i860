#!/bin/bash
#
# Background Analysis Monitor - Runs as background job with periodic reports
#
# This script monitors parallel analysis progress in the background and writes
# periodic status reports that can be checked via tail or cat.
#
# Usage:
#   ./scripts/background_monitor.sh &
#   MONITOR_PID=$!
#
# Check progress:
#   cat logs/monitor_status.txt
#   tail -f logs/monitor_detailed.log
#
# Stop monitor:
#   kill $MONITOR_PID
#

set -euo pipefail

# Configuration
REPORT_INTERVAL=10  # Report every 10 seconds
STATUS_FILE="logs/monitor_status.txt"
DETAILED_LOG="logs/monitor_detailed.log"
PROGRESS_DB="logs/progress.json"

# Directories to monitor
DOCS_DIR="docs/functions"
ASM_DIR="disassembly/annotated"

# Create logs directory
mkdir -p logs

# Initialize
SESSION_START=$(date +%s)
SESSION_ID=$(date +%Y%m%d_%H%M%S)

# Get baseline counts
BASELINE_DOCS=$(find "$DOCS_DIR" -name "*.md" 2>/dev/null | wc -l | tr -d ' ')
BASELINE_ASM=$(find "$ASM_DIR" -name "*.asm" 2>/dev/null | wc -l | tr -d ' ')

echo "=== Background Monitor Started ===" > "$STATUS_FILE"
echo "Session ID: $SESSION_ID" >> "$STATUS_FILE"
echo "Start time: $(date '+%Y-%m-%d %H:%M:%S')" >> "$STATUS_FILE"
echo "Baseline: $BASELINE_DOCS docs, $BASELINE_ASM asm files" >> "$STATUS_FILE"
echo "" >> "$STATUS_FILE"

echo "[$(date '+%H:%M:%S')] Monitor started (PID: $$)" > "$DETAILED_LOG"

# Function to get current counts
get_counts() {
    local docs=$(find "$DOCS_DIR" -name "*.md" 2>/dev/null | wc -l | tr -d ' ')
    local asm=$(find "$ASM_DIR" -name "*.asm" 2>/dev/null | wc -l | tr -d ' ')
    echo "$docs $asm"
}

# Function to detect new files since last check
detect_new_files() {
    local marker_file="logs/.last_check_${SESSION_ID}"

    if [[ -f "$marker_file" ]]; then
        # Find files newer than marker
        local new_docs=$(find "$DOCS_DIR" -name "*.md" -newer "$marker_file" 2>/dev/null)
        local new_asm=$(find "$ASM_DIR" -name "*.asm" -newer "$marker_file" 2>/dev/null)

        if [[ -n "$new_docs" ]]; then
            echo "$new_docs" | while read -r file; do
                local size=$(wc -l < "$file" 2>/dev/null || echo "?")
                echo "[$(date '+%H:%M:%S.%3N')] NEW DOC: $(basename "$file") ($size lines)" | tee -a "$DETAILED_LOG"
            done
        fi

        if [[ -n "$new_asm" ]]; then
            echo "$new_asm" | while read -r file; do
                local size=$(wc -l < "$file" 2>/dev/null || echo "?")
                echo "[$(date '+%H:%M:%S.%3N')] NEW ASM: $(basename "$file") ($size lines)" | tee -a "$DETAILED_LOG"
            done
        fi
    fi

    # Update marker
    touch "$marker_file"
}

# Function to generate progress report
generate_report() {
    local now=$(date +%s)
    local elapsed=$((now - SESSION_START))
    local elapsed_min=$((elapsed / 60))
    local elapsed_sec=$((elapsed % 60))

    read -r current_docs current_asm <<< "$(get_counts)"

    local new_docs=$((current_docs - BASELINE_DOCS))
    local new_asm=$((current_asm - BASELINE_ASM))

    # Calculate rate
    local rate_docs=0
    local rate_asm=0
    if [[ $elapsed -gt 0 ]]; then
        rate_docs=$(echo "scale=2; $new_docs * 60 / $elapsed" | bc)
        rate_asm=$(echo "scale=2; $new_asm * 60 / $elapsed" | bc)
    fi

    # Build report
    cat > "$STATUS_FILE" <<EOF
=== Background Monitor Status ===
Session ID: $SESSION_ID
Current time: $(date '+%Y-%m-%d %H:%M:%S')
Elapsed: ${elapsed_min}m ${elapsed_sec}s

FILES CREATED:
  Documentation: +$new_docs (total: $current_docs)
  Assembly:      +$new_asm (total: $current_asm)

RATE:
  Docs:   ${rate_docs}/min
  Asm:    ${rate_asm}/min

EXPECTED COMPLETION:
  Pairs: $new_docs/$new_asm matched
  Status: $(if [[ $new_docs -eq $new_asm ]]; then echo "✓ In sync"; else echo "⚠ Mismatch"; fi)

Latest activity: See logs/monitor_detailed.log
Monitor PID: $$
EOF

    # JSON progress for parsing
    cat > "$PROGRESS_DB" <<EOF
{
  "session_id": "$SESSION_ID",
  "timestamp": "$(date -u '+%Y-%m-%dT%H:%M:%SZ')",
  "elapsed_seconds": $elapsed,
  "baseline": {
    "docs": $BASELINE_DOCS,
    "asm": $BASELINE_ASM
  },
  "current": {
    "docs": $current_docs,
    "asm": $current_asm
  },
  "delta": {
    "docs": $new_docs,
    "asm": $new_asm
  },
  "rate_per_minute": {
    "docs": $rate_docs,
    "asm": $rate_asm
  }
}
EOF

    echo "[$(date '+%H:%M:%S')] Report: +$new_docs docs, +$new_asm asm (${elapsed}s elapsed)" >> "$DETAILED_LOG"
}

# Cleanup on exit
cleanup() {
    echo "" | tee -a "$DETAILED_LOG"
    echo "[$(date '+%H:%M:%S')] Monitor stopped" | tee -a "$DETAILED_LOG"
    generate_report  # Final report
    echo "=== Monitor Terminated ===" >> "$STATUS_FILE"
}

trap cleanup EXIT INT TERM

# Main monitoring loop
echo "[$(date '+%H:%M:%S')] Entering monitoring loop (interval: ${REPORT_INTERVAL}s)" >> "$DETAILED_LOG"

while true; do
    # Detect new files
    detect_new_files

    # Generate periodic report
    generate_report

    # Sleep until next interval
    sleep "$REPORT_INTERVAL"
done
