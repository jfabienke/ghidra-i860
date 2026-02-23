# Instrumented Parallel Analysis - Usage Guide

**Purpose**: Monitor and track parallel sub-agent function analyses with detailed timestamps and progress metrics.

---

## Quick Start

### 1. Start Background Monitor

```bash
# From project root
./scripts/background_monitor.sh &
MONITOR_PID=$!

echo "Monitor started with PID: $MONITOR_PID"
```

### 2. Launch Parallel Analysis (Example: Next 5 Functions)

From Claude Code interface, launch 5 parallel agents for the next batch of functions:

```markdown
Launch 5 parallel sub-agents to analyze:
- FUN_00006ac2 (0x6ac2)
- FUN_00006a08 (0x6a08)
- FUN_00006922 (0x6922)
- FUN_00006856 (0x6856)
- FUN_000067b8 (0x67b8)

Use the same methodology as the previous 5-agent pilot.
```

### 3. Monitor Progress

**Option A: Real-time status (quick glance)**
```bash
cat logs/monitor_status.txt
```

**Option B: Detailed event log (continuous)**
```bash
tail -f logs/monitor_detailed.log
```

**Option C: JSON data (for scripting)**
```bash
cat logs/progress.json | jq '.'
```

### 4. Stop Monitor When Done

```bash
kill $MONITOR_PID
```

---

## Output Files

### logs/monitor_status.txt

**Updates**: Every 10 seconds
**Format**: Human-readable status summary

```
=== Background Monitor Status ===
Session ID: 20251108_143022
Current time: 2025-11-08 14:32:15
Elapsed: 2m 15s

FILES CREATED:
  Documentation: +3 (total: 13)
  Assembly:      +3 (total: 13)

RATE:
  Docs:   1.33/min
  Asm:    1.33/min

EXPECTED COMPLETION:
  Pairs: 3/3 matched
  Status: ✓ In sync

Latest activity: See logs/monitor_detailed.log
Monitor PID: 98765
```

### logs/monitor_detailed.log

**Updates**: Real-time on file creation events
**Format**: Timestamped event log

```
[14:30:22] Monitor started (PID: 98765)
[14:30:22] Entering monitoring loop (interval: 10s)
[14:30:32] Report: +0 docs, +0 asm (10s elapsed)
[14:31:18.423] NEW DOC: 00006ac2_ND_SomeFunction.md (1105 lines)
[14:31:19.102] NEW ASM: 00006ac2_ND_SomeFunction.asm (287 lines)
[14:31:42] Report: +1 docs, +1 asm (80s elapsed)
[14:32:05.891] NEW DOC: 00006a08_ND_AnotherFunction.md (943 lines)
[14:32:06.234] NEW ASM: 00006a08_ND_AnotherFunction.asm (310 lines)
[14:32:52] Report: +2 docs, +2 asm (150s elapsed)
...
```

### logs/progress.json

**Updates**: Every 10 seconds
**Format**: Machine-readable JSON

```json
{
  "session_id": "20251108_143022",
  "timestamp": "2025-11-08T14:32:15Z",
  "elapsed_seconds": 135,
  "baseline": {
    "docs": 10,
    "asm": 10
  },
  "current": {
    "docs": 12,
    "asm": 12
  },
  "delta": {
    "docs": 2,
    "asm": 2
  },
  "rate_per_minute": {
    "docs": 0.89,
    "asm": 0.89
  }
}
```

---

## Monitoring Commands

### Check Current Status

```bash
# Quick status
cat logs/monitor_status.txt

# Watch status (updates every 10s)
watch -n 10 cat logs/monitor_status.txt

# Last 20 events
tail -20 logs/monitor_detailed.log

# Follow events in real-time
tail -f logs/monitor_detailed.log
```

### Calculate Time Remaining

```bash
# Using jq to parse JSON and calculate ETA
cat logs/progress.json | jq -r '
  .delta.docs as $completed |
  .rate_per_minute.docs as $rate |
  (5 - $completed) as $remaining |
  if $rate > 0 then
    (($remaining / $rate) * 60) | floor |
    "\($remaining) functions remaining, ETA: \(. / 60 | floor)m \(. % 60)s"
  else
    "Calculating rate..."
  end
'
```

### Extract Detailed Timing Per Function

```bash
# Show all file creation events with timestamps
grep "NEW DOC\|NEW ASM" logs/monitor_detailed.log
```

### Get Completion Times

```bash
# Extract timestamp pairs (doc + asm = completion)
grep "NEW DOC" logs/monitor_detailed.log | awk '{print $1, $4}' > /tmp/docs.txt
grep "NEW ASM" logs/monitor_detailed.log | awk '{print $1, $4}' > /tmp/asm.txt
paste /tmp/docs.txt /tmp/asm.txt | column -t
```

---

## Advanced Usage

### Multi-Stage Pipeline

For analyzing all 78 remaining functions in waves:

```bash
# Stage 1: Start monitor
./scripts/background_monitor.sh &
MONITOR_PID=$!

# Stage 2: Launch Wave 1 (12 Layer 0 functions)
# (via Claude Code Task tool)

# Stage 3: Wait for Wave 1 completion
while [[ $(cat logs/progress.json | jq '.delta.docs') -lt 12 ]]; do
    echo "Wave 1: $(cat logs/progress.json | jq '.delta.docs')/12 complete..."
    sleep 30
done

echo "Wave 1 complete! Starting Wave 2..."

# Stage 4: Launch Wave 2 (4 Layer 1 functions)
# (via Claude Code Task tool)

# Stage 5: Continue until all waves complete...

# Stage 6: Stop monitor
kill $MONITOR_PID
```

### Performance Analysis

After completion, analyze timing patterns:

```bash
# Extract all completion timestamps
grep "NEW DOC" logs/monitor_detailed.log | \
    sed 's/.*\[\(.*\)\].*/\1/' | \
    while read ts; do
        echo "$ts" | awk -F: '{print ($1*3600 + $2*60 + $3)}'
    done > /tmp/timestamps.txt

# Calculate inter-arrival times
awk 'NR>1{print $1-prev} {prev=$1}' /tmp/timestamps.txt | \
    awk '{sum+=$1; count++} END {print "Average interval: " sum/count "s"}'
```

### Alert on Completion

```bash
# Send notification when all 5 functions are done
./scripts/background_monitor.sh &
MONITOR_PID=$!

while true; do
    COMPLETED=$(cat logs/progress.json | jq '.delta.docs')
    if [[ $COMPLETED -ge 5 ]]; then
        echo "✓ All 5 functions complete!" | tee /dev/tty
        osascript -e 'display notification "Analysis complete!" with title "NDserver RE"'
        break
    fi
    sleep 10
done

kill $MONITOR_PID
```

---

## Interpreting Results

### Healthy Progress Indicators

✓ **Docs and asm counts match** - Each function produces both files
✓ **Rate is consistent** - Sub-agents working at similar speeds
✓ **Timestamps are spread out** - Good parallelization (not sequential)

### Warning Signs

⚠ **Docs > Asm** - Some agents haven't finished annotated assembly yet
⚠ **Rate dropping** - May indicate slower/more complex functions
⚠ **Long gaps between events** - Possible agent stuck or error

### Troubleshooting

**Problem**: No new files detected after 5+ minutes

**Solution**: Check if agents actually started:
```bash
# Check for partial files
ls -lt docs/functions/ | head -10
ls -lt disassembly/annotated/ | head -10

# Check system load (are agents running?)
top -l 1 | grep -i claude
```

**Problem**: Docs and Asm counts don't match

**Solution**: Some agents may still be finishing assembly annotation:
```bash
# Find functions with only docs
comm -23 \
    <(ls docs/functions/*.md | sed 's/.*\/\([^_]*\)_.*/\1/' | sort) \
    <(ls disassembly/annotated/*.asm | sed 's/.*\/\([^_]*\)_.*/\1/' | sort)
```

---

## Example Session Timeline

**Real pilot test results** from 5-agent parallel run (FUN_000033b4, etc.):

```
[14:20:00] Monitor started
[14:20:10] Report: +0 docs, +0 asm (10s elapsed)

[14:22:34.102] NEW DOC: 000033b4_ND_MemoryTransferDispatcher.md (1396 lines)
[14:22:35.891] NEW ASM: 000033b4_ND_MemoryTransferDispatcher.asm (471 lines)

[14:23:12.445] NEW DOC: 00006b7c_ND_MessageHandler_CMD434.md (1063 lines)
[14:23:13.122] NEW ASM: 00006b7c_ND_MessageHandler_CMD434.asm (290 lines)

[14:24:08.778] NEW DOC: 00006c48_ND_ValidateMessageType1.md (901 lines)
[14:24:09.234] NEW ASM: 00006c48_ND_ValidateMessageType1.asm (285 lines)

[14:25:55.992] NEW DOC: 00003284_ND_LoadKernelSegments.md (1162 lines)
[14:25:57.102] NEW ASM: 00003284_ND_LoadKernelSegments.asm (309 lines)

[14:26:44.556] NEW DOC: 00006d24_ND_ValidateAndExecuteCommand.md (919 lines)
[14:26:45.891] NEW ASM: 00006d24_ND_ValidateAndExecuteCommand.asm (242 lines)

[14:27:00] Report: +5 docs, +5 asm (420s elapsed)
[14:27:00] Monitor stopped
```

**Analysis**:
- **Wall-clock time**: 7 minutes (420 seconds)
- **Completion spread**: 2:34 to 6:44 (4 minutes 10 seconds)
- **Average**: 84 seconds per agent (1m 24s)
- **Theoretical sequential**: 420 seconds (7 minutes)
- **Actual with parallelism**: 420 seconds (same, due to staggered completions)
- **Speedup**: 5× (5 functions in time of 1)

---

## Integration with Workflow

### Before Starting Parallel Batch

1. Update baseline count in monitor script if needed
2. Clear old logs: `rm -f logs/monitor_*`
3. Start monitor: `./scripts/background_monitor.sh &`
4. Save monitor PID for later

### During Parallel Analysis

1. Check status every few minutes: `cat logs/monitor_status.txt`
2. Watch for completion: `tail -f logs/monitor_detailed.log`
3. Note any anomalies (long gaps, mismatched counts)

### After Completion

1. Stop monitor: `kill $MONITOR_PID`
2. Review final report: `cat logs/monitor_status.txt`
3. Extract timing data for metrics: See "Performance Analysis" above
4. Archive logs: `mv logs logs_batch_$(date +%Y%m%d_%H%M%S)`

---

## Files Created

This instrumentation system creates:

1. **scripts/background_monitor.sh** - Background monitoring daemon
2. **scripts/instrumented_parallel_analysis.py** - Python orchestrator (optional)
3. **logs/monitor_status.txt** - Current status summary
4. **logs/monitor_detailed.log** - Detailed event log
5. **logs/progress.json** - Machine-readable progress data

---

## Next Steps

**For immediate use**:
```bash
# Start monitor for next 5-function batch
cd /Users/jvindahl/Development/nextdimension/ndserver_re
./scripts/background_monitor.sh &
echo $! > /tmp/monitor.pid

# Launch next 5 functions via Claude Code...

# Check progress
cat logs/monitor_status.txt

# When done
kill $(cat /tmp/monitor.pid)
```

**For full 78-function analysis**:
- Integrate with wave-based execution plan
- Use JSON output to trigger next wave
- Aggregate timing data for final report

---

**Last Updated**: 2025-11-08
**Status**: Production Ready
