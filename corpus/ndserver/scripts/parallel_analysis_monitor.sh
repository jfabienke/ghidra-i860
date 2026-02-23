#!/bin/bash
#
# Parallel Analysis Monitor - Real-time timestamp tracking for sub-agent analyses
#
# This script monitors the parallel analysis process and logs timestamps for:
# - Agent launch time
# - File creation events
# - Completion time
# - Progress updates
#
# Usage: ./parallel_analysis_monitor.sh
#

set -euo pipefail

# Configuration
DOCS_DIR="docs/functions"
ASM_DIR="disassembly/annotated"
LOG_FILE="logs/parallel_analysis_$(date +%Y%m%d_%H%M%S).log"
PROGRESS_FILE="logs/parallel_progress.txt"

# Create logs directory
mkdir -p logs

# Initialize log
echo "=== Parallel Analysis Monitor Started ===" | tee "$LOG_FILE"
echo "Timestamp: $(date '+%Y-%m-%d %H:%M:%S.%3N')" | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

# Function to log with timestamp
log_event() {
    local event="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S.%3N')
    echo "[$timestamp] $event" | tee -a "$LOG_FILE"
}

# Function to monitor file creation
monitor_file_creation() {
    local pattern="$1"
    local description="$2"

    log_event "Monitoring for: $description (pattern: $pattern)"

    # Use fswatch if available, otherwise fall back to polling
    if command -v fswatch &> /dev/null; then
        fswatch -1 -r "$pattern" 2>/dev/null | while read -r file; do
            log_event "CREATED: $file"
        done &
    else
        # Polling fallback
        while true; do
            for file in $pattern; do
                if [[ -f "$file" ]] && [[ ! -f "$file.monitored" ]]; then
                    log_event "CREATED: $file"
                    touch "$file.monitored"
                fi
            done
            sleep 0.5
        done &
    fi
}

# Function to track agent completion
track_completion() {
    local function_addr="$1"
    local start_time="$2"

    # Wait for documentation file
    while [[ ! -f "$DOCS_DIR/${function_addr}_"*.md ]]; do
        sleep 0.5
    done

    local doc_time=$(date '+%s.%3N')
    log_event "MILESTONE: ${function_addr} - Documentation created"

    # Wait for assembly file
    while [[ ! -f "$ASM_DIR/${function_addr}_"*.asm ]]; do
        sleep 0.5
    done

    local asm_time=$(date '+%s.%3N')
    log_event "MILESTONE: ${function_addr} - Assembly annotated"

    local end_time=$(date '+%s.%3N')
    local duration=$(echo "$end_time - $start_time" | bc)

    log_event "COMPLETED: ${function_addr} in ${duration}s"

    # Update progress file
    echo "${function_addr},${duration}" >> "$PROGRESS_FILE"
}

# Main monitoring loop
main() {
    log_event "Starting file system monitoring..."

    # Monitor documentation directory
    monitor_file_creation "$DOCS_DIR/*.md" "Documentation files"

    # Monitor assembly directory
    monitor_file_creation "$ASM_DIR/*.asm" "Assembly files"

    log_event "Monitoring active. Press Ctrl+C to stop."

    # Keep script running
    wait
}

# Cleanup on exit
cleanup() {
    log_event "Monitoring stopped"
    # Kill background jobs
    jobs -p | xargs -r kill 2>/dev/null || true
}

trap cleanup EXIT INT TERM

main "$@"
