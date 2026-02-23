# NeXTdimension Timing Architecture - Visual Documentation

**Document Date**: November 15, 2025
**Firmware Version**: 0.95-beta
**Purpose**: Visual reference for timing hierarchy and interrupt flow
**Canonical Mode**: ND_HW_PROFILE (VBL-only @ 68Hz) for real hardware

**See Also**: `TIMING_REALITY_FINAL.md` for definitive architectural verdict

---

## 1. Overall Timing Hierarchy

```
┌────────────────────────────────────────────────────────────────────┐
│                    NEXTDIMENSION TIMING ARCHITECTURE               │
├────────────────────────────────────────────────────────────────────┤
│                                                                    │
│  LEVEL 1: HARDWARE TIMING SOURCES                                 │
│  ════════════════════════════════════                             │
│                                                                    │
│  REAL HARDWARE (ND_HW_PROFILE - CANONICAL):                      │
│  ┌──────────────────────────┐      ┌─────────────────────────┐   │
│  │   VBL via CSR0           │      │  i860 Internal Timer    │   │
│  │   ─────────────          │      │  ──────────────────     │   │
│  │  Address: 0xFF800000     │      │  Status: DOES NOT EXIST │   │
│  │  Frequency: 68.7 Hz      │      │  Confirmed from manual  │   │
│  │  Period: 14.56 ms        │      │  No control registers   │   │
│  │  Jitter: <10 μs (CRT)    │      │  All timing external    │   │
│  │  Evidence: ✅ 30K+ access│      │                         │   │
│  │  Status: ✅ PROVEN       │      │                         │   │
│  └──────────────────────────┘      └─────────────────────────┘   │
│                                                                    │
│  EMULATOR (ND_EMU_PROFILE - TESTING ONLY):                       │
│  ┌──────────────────────────┐      ┌─────────────────────────┐   │
│  │   VBL via CSR0           │      │  MMIO Timer             │   │
│  │   ─────────────          │      │  ──────────────         │   │
│  │  Emulated @ 68.7 Hz      │      │  Address: 0x020000C0    │   │
│  │                          │      │  Frequency: 1 MHz       │   │
│  │                          │      │  Emulator-only feature  │   │
│  │                          │      │  Evidence: ❌ 0 hw access│   │
│  │                          │      │  Status: EMULATOR-ONLY  │   │
│  └──────────────────────────┘      └─────────────────────────┘   │
│           │                                    │                  │
│           └──────────────┬─────────────────────┘                  │
│                          ↓                                        │
│  LEVEL 2: INTERRUPT SYSTEM                                        │
│  ══════════════════════════                                       │
│                                                                    │
│  ┌──────────────────────────────────────────────────────┐         │
│  │         i860 External Interrupt Handler              │         │
│  │         ──────────────────────────────              │         │
│  │                                                      │         │
│  │  1. Interrupt fired (hardware)                      │         │
│  │     ↓                                                │         │
│  │  2. CPU jumps to vector 0x08                        │         │
│  │     ↓                                                │         │
│  │  3. Assembly handler: external_interrupt_handler    │         │
│  │     - Save minimal context (r1, r2)                 │         │
│  │     - Execute ldint (i860 INTA cycle)               │         │
│  │     - Get vector number from bus                    │         │
│  │     ↓                                                │         │
│  │  4. Call rust_interrupt_dispatcher_with_vector(vec) │         │
│  │     ↓                                                │         │
│  │  5. Dispatch based on vector:                       │         │
│  │     ├─ VBL_VECTOR (0x??): handle_vbl_interrupt()    │         │
│  │     ├─ TIMER_VECTOR (0x??): handle_timer_interrupt()│         │
│  │     └─ Other: log warning                           │         │
│  │     ↓                                                │         │
│  │  6. Restore context, return from interrupt          │         │
│  │                                                      │         │
│  └──────────────────────────────────────────────────────┘         │
│           │                              │                        │
│           ↓                              ↓                        │
│  ┌──────────────────────┐    ┌──────────────────────┐            │
│  │ handle_vbl_interrupt │    │ handle_timer_interrupt│           │
│  │ ──────────────────── │    │ ───────────────────── │           │
│  │                      │    │                       │           │
│  │ 1. Clear MMIO bit    │    │ 1. Clear MMIO bit    │           │
│  │ 2. Clear CSR0 bit    │    │ 2. Call embassy_time │           │
│  │ 3. VBLANK_WAKER      │    │    ::tick()          │           │
│  │    .signal(())       │    │                      │           │
│  │                      │    │ (Advances Embassy    │           │
│  │ (Wakes tasks waiting │    │  internal counter by │           │
│  │  for VBL)            │    │  1 microsecond)      │           │
│  │                      │    │                      │           │
│  └──────────────────────┘    └──────────────────────┘            │
│           │                              │                        │
│           └──────────────┬───────────────┘                        │
│                          ↓                                        │
│  LEVEL 3: EMBASSY ASYNC RUNTIME                                   │
│  ═══════════════════════════════                                  │
│                                                                    │
│  ┌──────────────────────────────────────────────────────┐         │
│  │            Embassy Executor & Time Driver            │         │
│  │            ────────────────────────────────          │         │
│  │                                                      │         │
│  │  Components:                                         │         │
│  │  ├─ Timer Queue (heap of (deadline, waker) pairs)   │         │
│  │  ├─ Task List (ready queue)                         │         │
│  │  ├─ Current Time (AtomicU64, incremented by tick()) │         │
│  │  └─ Scheduler (round-robin over ready tasks)        │         │
│  │                                                      │         │
│  │  On embassy_time::tick():                           │         │
│  │  1. Increment current_time                          │         │
│  │  2. Check timer queue for expired timers            │         │
│  │  3. Wake tasks whose deadline <= current_time       │         │
│  │  4. Add woken tasks to ready queue                  │         │
│  │                                                      │         │
│  │  On Timer::after(duration).await:                   │         │
│  │  1. Calculate deadline = now + duration             │         │
│  │  2. Insert (deadline, task.waker) into timer queue  │         │
│  │  3. Return Poll::Pending (yield)                    │         │
│  │  4. Task suspended until deadline reached           │         │
│  │                                                      │         │
│  │  Scheduler Loop:                                     │         │
│  │  loop {                                              │         │
│  │      for task in ready_queue {                      │         │
│  │          task.poll(cx);  // Run until .await        │         │
│  │      }                                               │         │
│  │      if ready_queue.empty() { CPU idle; }           │         │
│  │  }                                                   │         │
│  │                                                      │         │
│  └──────────────────────────────────────────────────────┘         │
│                          ↓                                        │
│  LEVEL 4: APPLICATION TASKS                                       │
│  ═══════════════════════                                          │
│                                                                    │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐   │
│  │   VBL Task      │  │  Mailbox Task   │  │  Render Task    │   │
│  │   ────────      │  │  ─────────────  │  │  ───────────    │   │
│  │                 │  │                 │  │                 │   │
│  │ loop {          │  │ loop {          │  │ loop {          │   │
│  │   wait_for_vbl  │  │   if cmd_ready  │  │   render_frame  │   │
│  │   ().await;     │  │   {             │  │   ();           │   │
│  │                 │  │     handle_cmd  │  │   wait_for_vbl  │   │
│  │   swap_buffers  │  │     ().await;   │  │   ().await;     │   │
│  │   ();           │  │   }             │  │   flip_buffers  │   │
│  │                 │  │   Timer::after  │  │   ();           │   │
│  │   update_fps(); │  │   (10μs).await; │  │ }               │   │
│  │ }               │  │ }               │  │                 │   │
│  │                 │  │                 │  │                 │   │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘   │
│                                                                    │
└────────────────────────────────────────────────────────────────────┘
```

---

## 2. Interrupt Flow Diagram

```
┌──────────────────────────────────────────────────────────────────────┐
│                      INTERRUPT PROCESSING FLOW                       │
└──────────────────────────────────────────────────────────────────────┘

HARDWARE LAYER
════════════════════════════════════════════════════════════════════════

  CRT Scanout                MMIO Timer (if exists)
  ───────────                ──────────────────────
      │                              │
      │ Reaches VBL                  │ Count = 0
      ↓                              ↓
  ┌────────────┐                ┌────────────┐
  │ CSR0[7] ← 1│                │ INT_STATUS │
  │ (VBL_INT)  │                │ [9] ← 1    │
  └────────────┘                └────────────┘
      │                              │
      └──────────────┬───────────────┘
                     │
                     │ i860 External Interrupt Line
                     ↓

CPU INTERRUPT MECHANISM
════════════════════════════════════════════════════════════════════════

            ┌───────────────────┐
            │ i860 CPU detects  │
            │ external IRQ line │
            └───────────────────┘
                     │
                     │ 1. CPU saves PC
                     │ 2. CPU jumps to vector table
                     ↓
            ┌───────────────────┐
            │ Vector Table      │
            │ Entry 0x08:       │
            │   br external_irq │
            └───────────────────┘
                     │
                     ↓

ASSEMBLY HANDLER
════════════════════════════════════════════════════════════════════════

  #[naked]
  extern "C" fn external_interrupt_handler()
  ──────────────────────────────────────────
         │
         ├─ subs %sp, %sp, 64        │ Allocate stack frame
         ├─ st.l %r1, 0(%sp)         │ Save r1
         ├─ st.l %r2, 4(%sp)         │ Save r2
         │
         ├─ lock                     │ Begin atomic section
         ├─ ldint.l 0(%r0), %r16     │ ◄── CRITICAL: i860 INTA cycle
         ├─ unlock                   │     Reads vector from bus
         │                           │     Acknowledges interrupt
         │ (Vector now in %r16)      │
         │
         ├─ or %r16, %r0, %r2        │ Move vector to arg register
         ├─ call rust_handler        │ Call Rust code
         │
         ├─ ld.l 0(%sp), %r1         │ Restore r1
         ├─ ld.l 4(%sp), %r2         │ Restore r2
         ├─ adds %sp, %sp, 64        │ Deallocate stack
         └─ bri %r31                 │ Return from interrupt
                     │
                     ↓

RUST DISPATCHER
════════════════════════════════════════════════════════════════════════

  pub extern "C" fn rust_interrupt_dispatcher_with_vector(vector: u32)
  ───────────────────────────────────────────────────────────────────
         │
         ├─ match vector {
         │    VBL_VECTOR   => handle_vbl_interrupt(),
         │    TIMER_VECTOR => handle_timer_interrupt(),
         │    _            => warn!("Unknown vector"),
         │  }
         │
         ↓

INTERRUPT HANDLERS
════════════════════════════════════════════════════════════════════════

┌────────────────────────────┐         ┌────────────────────────────┐
│ handle_vbl_interrupt()     │         │ handle_timer_interrupt()   │
├────────────────────────────┤         ├────────────────────────────┤
│                            │         │                            │
│ 1. Read INT_STATUS         │         │ 1. Clear INT_STATUS[9]     │
│ 2. if (status & VBL):      │         │                            │
│    ├─ Clear INT_STATUS[0]  │         │ 2. embassy_time::tick()    │
│    ├─ Clear CSR0[7]        │         │    ├─ current_time++       │
│    └─ VBLANK_WAKER.signal()│         │    ├─ Check timer queue    │
│                            │         │    └─ Wake expired tasks   │
│ (ISR takes ~50 cycles)     │         │                            │
│                            │         │ (ISR takes ~20 cycles)     │
└────────────────────────────┘         └────────────────────────────┘
         │                                       │
         └───────────────┬───────────────────────┘
                         │
                         ↓ Tasks woken, marked ready

EMBASSY SCHEDULER
════════════════════════════════════════════════════════════════════════

         Woken tasks added to ready queue
                         │
                         ↓
              ┌────────────────────┐
              │ Embassy Scheduler  │
              │ polls ready tasks  │
              └────────────────────┘
                         │
         ┌───────────────┼───────────────┐
         ↓               ↓               ↓
    Task A resumes  Task B resumes  Task C resumes
    after .await    after .await    after .await
```

---

## 3. Mode Comparison: Ideal vs. Degraded

```
┌──────────────────────────────────────────────────────────────────────┐
│               TIMING MODE COMPARISON                                 │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  MODE 1: IDEAL (MMIO Controller Present)                            │
│  ═══════════════════════════════════════                            │
│                                                                      │
│  Hardware:                                                           │
│  ├─ VBL Interrupt  @ 68.7 Hz   (14.56 ms period)                    │
│  └─ Timer Interrupt @ 1 MHz    (1 μs period)                        │
│                                                                      │
│  Embassy Configuration:                                              │
│    tick-hz-1_000_000  (1 MHz = 1 μs ticks)                          │
│                                                                      │
│  Timeline (1ms window):                                              │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │ Time (μs)   Event                                              │ │
│  ├────────────────────────────────────────────────────────────────┤ │
│  │ 0           embassy_time::tick() from timer ISR                │ │
│  │ 1           embassy_time::tick()                               │ │
│  │ 2           embassy_time::tick()                               │ │
│  │ ...         (1000 ticks per millisecond)                       │ │
│  │ 998         embassy_time::tick()                               │ │
│  │ 999         embassy_time::tick()                               │ │
│  │ 1000        embassy_time::tick()                               │ │
│  └────────────────────────────────────────────────────────────────┘ │
│                                                                      │
│  Task Behavior:                                                      │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │ Timer::after(Duration::from_micros(10)).await;                 │ │
│  │                                                                │ │
│  │ ├─ Now:       1000 μs                                          │ │
│  │ ├─ Deadline:  1010 μs                                          │ │
│  │ ├─ Insert into timer queue                                     │ │
│  │ ├─ Task suspends                                               │ │
│  │ │                                                              │ │
│  │ ├─ [10 timer ticks pass]                                       │ │
│  │ │                                                              │ │
│  │ └─ At 1010 μs: Task woken, resumes                            │ │
│  │                                                                │ │
│  │ Actual delay: 10±1 μs  ✅ ACCURATE                             │ │
│  └────────────────────────────────────────────────────────────────┘ │
│                                                                      │
│  Characteristics:                                                    │
│  ├─ Tick resolution:     1 μs                                       │
│  ├─ Max timeout error:   ±1 μs                                      │
│  ├─ Task switch latency: ~1 μs                                      │
│  └─ CPU efficiency:      High (idle between ticks)                  │
│                                                                      │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  MODE 2: DEGRADED (VBL Only, No Timer)                              │
│  ══════════════════════════════════════                             │
│                                                                      │
│  Hardware:                                                           │
│  ├─ VBL Interrupt  @ 68.7 Hz   (14.56 ms period)                    │
│  └─ Timer Interrupt: ❌ NOT AVAILABLE                               │
│                                                                      │
│  Embassy Configuration:                                              │
│    tick-hz-1_000_000  (configured for 1 MHz)                        │
│    BUT: embassy_time::tick() only called at VBL (68 Hz)             │
│                                                                      │
│  Timeline (20ms window):                                             │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │ Time (ms)   Event                                              │ │
│  ├────────────────────────────────────────────────────────────────┤ │
│  │ 0.0         VBL interrupt → handle_vbl_interrupt()             │ │
│  │             (embassy_time::tick() NOT called automatically!)   │ │
│  │ ...         [No ticks for 14.56 ms]                            │ │
│  │ 14.56       VBL interrupt → handle_vbl_interrupt()             │ │
│  │             (Could manually call tick(), but inaccurate)       │ │
│  │                                                                │ │
│  │ PROBLEM: Embassy time frozen between VBLs!                     │ │
│  └────────────────────────────────────────────────────────────────┘ │
│                                                                      │
│  Task Behavior:                                                      │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │ Timer::after(Duration::from_micros(10)).await;                 │ │
│  │                                                                │ │
│  │ ├─ Now:       1000 μs (last VBL time)                          │ │
│  │ ├─ Deadline:  1010 μs                                          │ │
│  │ ├─ Insert into timer queue                                     │ │
│  │ ├─ Task suspends                                               │ │
│  │ │                                                              │ │
│  │ ├─ [NO TICKS! Time frozen!]                                    │ │
│  │ ├─ [... 14,560 μs pass ...]                                    │ │
│  │ │                                                              │ │
│  │ └─ Next VBL: If we manually tick, all tasks wake in burst     │ │
│  │                                                                │ │
│  │ Actual delay: 0-14,700 μs  ❌ HIGHLY INACCURATE                │ │
│  └────────────────────────────────────────────────────────────────┘ │
│                                                                      │
│  Workaround (Manual Ticking):                                        │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │ #[embassy_executor::task]                                      │ │
│  │ async fn vbl_ticker() {                                        │ │
│  │     loop {                                                     │ │
│  │         wait_for_vblank().await;  // Every 14.56ms            │ │
│  │                                                                │ │
│  │         // Manually advance Embassy time                       │ │
│  │         unsafe {                                               │ │
│  │             for _ in 0..14_560 {                               │ │
│  │                 embassy_time::tick();  // Pretend 14.56ms = μs│ │
│  │             }                                                  │ │
│  │         }                                                      │ │
│  │     }                                                          │ │
│  │ }                                                              │ │
│  │                                                                │ │
│  │ PROBLEM: Inaccurate (assumes exactly 14.56ms), batched wakeups│ │
│  └────────────────────────────────────────────────────────────────┘ │
│                                                                      │
│  Characteristics:                                                    │
│  ├─ Tick resolution:     14,560 μs (14.56 ms)                       │
│  ├─ Max timeout error:   ±14,560 μs                                 │
│  ├─ Task switch latency: ~14,560 μs                                 │
│  └─ CPU efficiency:      Poor (bursts every VBL)                    │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 4. Hardware Detection Flowchart

```
┌────────────────────────────────────────────────────────────────────┐
│                  HARDWARE DETECTION FLOW                           │
└────────────────────────────────────────────────────────────────────┘

                        START
                          │
                          ↓
             ┌────────────────────────────┐
             │  interrupts::init() called │
             └────────────────────────────┘
                          │
                          ↓
             ┌────────────────────────────┐
             │ Call test_mmio_controller()│
             └────────────────────────────┘
                          │
                          ↓
       ┌──────────────────────────────────────────┐
       │ Read INT_STATUS @ 0x020000C0             │
       │                                          │
       │ ptr::read_volatile(INT_STATUS)           │
       └──────────────────────────────────────────┘
                          │
                          ↓
               ┌──────────────────┐
               │ Value = 0xFFFFFFFF?  │
               │ (Floating bus)    │
               └──────────────────┘
                    │        │
               YES  │        │  NO
                    │        │
                    ↓        ↓
           ┌────────────────────────┐
           │ Return false           │   Continue
           │ (No MMIO)              │
           └────────────────────────┘
                    │                      │
                    │                      ↓
                    │         ┌────────────────────────────┐
                    │         │ Write test pattern:        │
                    │         │ write_volatile(0xA5A5A5A5) │
                    │         └────────────────────────────┘
                    │                      │
                    │                      ↓
                    │         ┌────────────────────────────┐
                    │         │ Read back:                 │
                    │         │ readback = read_volatile() │
                    │         └────────────────────────────┘
                    │                      │
                    │                      ↓
                    │            ┌────────────────────┐
                    │            │ readback == pattern?│
                    │            └────────────────────┘
                    │                   │        │
                    │              YES  │        │  NO
                    │                   │        │
                    │                   ↓        ↓
                    │       ┌─────────────────────────┐
                    │       │ Return true             │   Return false
                    │       │ (MMIO exists)           │   (Not writeable)
                    │       └─────────────────────────┘
                    │                   │                   │
                    │                   │                   │
                    └───────────────────┴───────────────────┘
                                        │
                                        ↓
                    ┌───────────────────────────────────────┐
                    │ if mmio_exists {                      │
                    │   ✅ FULL MODE                        │
                    │   ├─ info!("MMIO detected")           │
                    │   ├─ Enable VBL + Timer interrupts    │
                    │   └─ configure_timer_1mhz()           │
                    │ } else {                              │
                    │   ⚠️  DEGRADED MODE                   │
                    │   ├─ warn!("MMIO not found")          │
                    │   └─ VBL-only via CSR0                │
                    │ }                                     │
                    └───────────────────────────────────────┘
                                        │
                                        ↓
                    ┌───────────────────────────────────────┐
                    │ ALWAYS:                               │
                    │ enable_vblank_interrupt_csr0()        │
                    │                                       │
                    │ (VBL proven to work, always enable)   │
                    └───────────────────────────────────────┘
                                        │
                                        ↓
                    ┌───────────────────────────────────────┐
                    │ install_interrupt_vector(0x08)        │
                    │                                       │
                    │ (Assembly handler ready)              │
                    └───────────────────────────────────────┘
                                        │
                                        ↓
                                      DONE
```

---

## 5. Task Execution Timeline

```
┌────────────────────────────────────────────────────────────────────────┐
│            MULTI-TASK EXECUTION WITH COOPERATIVE SCHEDULING            │
└────────────────────────────────────────────────────────────────────────┘

Assumptions:
- MMIO timer exists (1 MHz ticks)
- Three tasks: VBL task, Mailbox task, Render task

Time (μs)  │ VBL Task           │ Mailbox Task        │ Render Task
───────────┼────────────────────┼─────────────────────┼───────────────────
0          │ wait_for_vbl()     │ Check mailbox       │ render_frame()
           │ (suspended)        │ No command          │ (executing...)
           │                    │ Timer::after(10μs)  │
           │                    │ (suspended)         │
───────────┼────────────────────┼─────────────────────┼───────────────────
10         │ (sleeping)         │ [Timer expired]     │ (still rendering)
           │                    │ Check mailbox       │
           │                    │ No command          │
           │                    │ Timer::after(10μs)  │
           │                    │ (suspended)         │
───────────┼────────────────────┼─────────────────────┼───────────────────
20         │ (sleeping)         │ [Timer expired]     │ (still rendering)
           │                    │ Check mailbox       │
           │                    │ Command ready! ✅   │
           │                    │ handle_cmd().await  │
           │                    │ (processing...)     │
───────────┼────────────────────┼─────────────────────┼───────────────────
...        │ (sleeping)         │ (processing cmd)    │ (still rendering)
───────────┼────────────────────┼─────────────────────┼───────────────────
12,000     │ (sleeping)         │ Command done        │ Render complete!
           │                    │ Timer::after(10μs)  │ wait_for_vbl()
           │                    │ (suspended)         │ (suspended)
───────────┼────────────────────┼─────────────────────┼───────────────────
12,010     │ (sleeping)         │ [Timer expired]     │ (sleeping)
           │                    │ Check mailbox       │
           │                    │ No command          │
           │                    │ Timer::after(10μs)  │
───────────┼────────────────────┼─────────────────────┼───────────────────
14,560     │ ──────── VBL INTERRUPT FIRES ────────
           │ handle_vbl_irq()
           │ VBLANK_WAKER.signal()
           │ ↓
           │ [VBL task woken]   │                    │ [Render task woken]
           │ swap_buffers()     │                    │ flip_buffers()
           │ update_fps()       │                    │ render_frame()
           │ wait_for_vbl()     │                    │ (executing...)
           │ (suspended)        │                    │
───────────┼────────────────────┼─────────────────────┼───────────────────
14,570     │ (sleeping)         │ [Timer expired]     │ (still rendering)
           │                    │ Check mailbox       │
           │                    │ Timer::after(10μs)  │
───────────┼────────────────────┼─────────────────────┼───────────────────
...        │                    │                     │
───────────┴────────────────────┴─────────────────────┴───────────────────

Legend:
  (suspended)    = Task waiting on .await, not in ready queue
  [Timer expired]= Embassy woke task due to Timer::after() deadline
  [VBL task woken]= Embassy woke task due to VBLANK_WAKER.signal()
  (executing...) = Task actively running, consuming CPU
  (sleeping)     = Task suspended, not consuming CPU

Key Observations:
1. Tasks cooperatively share CPU
2. Mailbox checks every 10μs (fast polling with yield)
3. VBL wakes multiple tasks simultaneously
4. No preemption - tasks yield voluntarily at .await points
5. CPU can idle when all tasks suspended
```

---

## 6. Comparison Matrix

```
┌────────────────────────────────────────────────────────────────────────┐
│                     FEATURE COMPARISON MATRIX                          │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│ Feature                │ With MMIO Timer │ VBL Only │ Original ROM    │
│ ───────────────────────┼─────────────────┼──────────┼─────────────────┤
│ VBL Sync               │ ✅ 68 Hz         │ ✅ 68 Hz  │ ✅ Polling      │
│ Timer Interrupt        │ ✅ 1 MHz         │ ❌ None   │ ❌ None         │
│ Embassy Tick Rate      │ 1,000,000 Hz    │ 68 Hz (!)│ N/A             │
│ Max Timing Error       │ ±1 μs           │ ±14.7 ms │ <1 μs (loop)    │
│ Mailbox Poll Rate      │ 100,000/s       │ 68/s     │ ~4 million/s    │
│ Mailbox Latency        │ ~10 μs          │ ~14.7 ms │ <1 μs           │
│ CPU Utilization        │ ~5% (idle gaps) │ ~15% (!) │ ~100% (busy)    │
│ Task Switch Overhead   │ Minimal         │ Batched  │ None (no tasks) │
│ Async/Await Support    │ ✅ Full          │ ⚠️ Limited│ ❌ No           │
│ Multiple Concurrent    │ ✅ Many tasks    │ ✅ Limited│ ❌ Single thread│
│ Power Efficiency       │ ✅ Excellent     │ ⚠️ Medium │ ❌ Poor         │
│ Code Complexity        │ Medium          │ Medium   │ Simple          │
│ Evidence Status        │ ❓ Unverified   │ ✅ Proven │ ✅ Proven       │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘

Rating Scale:
✅ = Fully working, proven
⚠️ = Working but degraded/limited
❌ = Not available / not working
❓ = Unknown / needs testing
```

---

## 7. References

**Documentation**:
- `EMBASSY_TIMER_IMPLEMENTATION.md` - Detailed timing analysis
- `MMIO_INTERRUPT_CONTROLLER_STATUS.md` - MMIO hardware status
- `../TIMER_INTERRUPT_REALITY_CHECK.md` - Original investigation
- `../VBL_TIMING_68HZ.md` - VBL frequency verification

**Source Code**:
- `src/hal/interrupts.rs` - Interrupt handling implementation
- `src/hal/mod.rs` - Hardware register definitions
- `src/main.rs` - Embassy executor and tasks
- `src/video/controller.rs` - VBL synchronization

**Hardware**:
- CSR0 @ 0xFF800000 (PROVEN - 30,000+ accesses)
- MMIO @ 0x020000C0 (UNVERIFIED - 0 accesses)
- Previous emulator: `src/dimension/nd_nbic.c`

---

**Document Status**: Visual Reference Guide
**Last Updated**: November 15, 2025
**Purpose**: Quick reference for timing architecture
**Audience**: Firmware developers, testers, documentation readers
