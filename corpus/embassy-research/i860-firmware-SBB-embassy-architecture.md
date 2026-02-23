# SBB: High-Performance i860 Firmware Architecture with `embassy`

**Document ID:** SBB-FIRMWARE-EMBASSY-1.0  
**Date:** 2025-07-31 12:00  
**Author:** NeXTdimension Firmware Team  
**Status:** Architecture Specification

## 1. Overview

This document outlines the software architecture for a high-performance, real-time firmware for the Intel i860 processor, specifically designed for the NeXTdimension board. The architecture is built upon the **`embassy` asynchronous Rust framework**.

The primary architectural goal is to **maximize the performance of the i860's deep pipelines** by mitigating its primary weakness: the high performance penalty associated with preemptive interrupts and context switching. This is achieved by creating a **cooperative multitasking environment** where tasks voluntarily yield control, avoiding expensive, involuntary hardware context switches.

## 2. Core Architectural Principle: Deferred Interrupt Processing

The entire interrupt handling model is based on the **"Signal and Wake"** pattern, also known as **deferred interrupt processing**. This pattern decouples the immediate, time-critical need to acknowledge a hardware interrupt from the less time-critical task of processing the associated data.

### Traditional (Inefficient) Model:
1. IRQ occurs
2. CPU is preempted (expensive pipeline flush)
3. A long Interrupt Service Routine (ISR) does all the work
4. CPU state is restored (expensive pipeline refill)

### Our `embassy`-based (Efficient) Model:
1. **IRQ occurs**
2. A **minimal, short ISR** runs. Its only job is to read the essential hardware status and **place a message on a queue** (`embassy::channel::Channel`) or set a flag (`embassy::sync::signal::Signal`)
3. The ISR returns immediately. The cost of preemption is minimized
4. A separate, lower-priority **asynchronous task** is waiting (`.await`) on that queue or signal. When the ISR posts the message, the `embassy` executor wakes the task
5. This "worker" task then performs all the complex processing in a normal, non-interrupt context

**Benefit:** This transforms an expensive, high-priority, preemptive context switch into a nearly-free, low-priority, cooperative task switch.

### Implementation Example:

```rust
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::{Channel, Sender, Receiver};
use embassy_sync::signal::Signal;

// Global channels for interrupt communication
static MAILBOX_CHANNEL: Channel<CriticalSectionRawMutex, MailboxCommand, 16> = Channel::new();
static VBLANK_SIGNAL: Signal<CriticalSectionRawMutex, ()> = Signal::new();
static DMA_COMPLETE: Channel<CriticalSectionRawMutex, DmaCompletion, 8> = Channel::new();

// Minimal ISR - runs in interrupt context
#[interrupt]
fn mailbox_irq_handler() {
    // Read mailbox status (fast)
    let status = unsafe { ptr::read_volatile(MAILBOX_STATUS_REG) };
    let command = unsafe { ptr::read_volatile(MAILBOX_CMD_REG) };
    
    // Clear interrupt (fast)
    unsafe { ptr::write_volatile(MAILBOX_ACK_REG, 1) };
    
    // Queue work for async task (fast, non-blocking)
    let _ = MAILBOX_CHANNEL.try_send(MailboxCommand { status, command });
    
    // ISR complete - total time: ~10 cycles
}

// Async worker task - runs in normal context
#[embassy_executor::task]
async fn mailbox_worker(receiver: Receiver<'static, CriticalSectionRawMutex, MailboxCommand, 16>) {
    loop {
        // Wait for work from ISR
        let cmd = receiver.receive().await;
        
        // Process command (can be lengthy)
        match cmd.command {
            CMD_RENDER_TRIANGLE => {
                // Complex operation - runs without interruption
                render_triangle(cmd.data).await;
            }
            CMD_DMA_TRANSFER => {
                // Setup DMA descriptors
                setup_dma_chain(cmd.data).await;
            }
            _ => {}
        }
    }
}
```

## 3. Asynchronous Task Design and Prioritization

The firmware will be composed of a set of independent, asynchronous `embassy` tasks, each responsible for a specific piece of hardware or logic. The `embassy` executor will manage these tasks based on a software-defined priority scheme, which gives us fine-grained control over the system's real-time behavior.

### Key Design Principles for Tasks:

- **High-Priority Tasks MUST be short or yield frequently.** They are for hard real-time deadlines (like VBlank). A long-running high-priority task without an `.await` will starve the entire system.
- **Low-Priority Tasks can be long-running.** They perform the bulk of the work but must be written cooperatively, yielding control periodically by calling `.await` on a timer or channel.

### Task Priority Architecture:

| Task | Priority | Description | Max Duration |
|------|----------|-------------|--------------|
| `frame_renderer()` | **Critical** | Waits for VBlank signal. Swaps frame buffers. | < 100 μs |
| `mailbox_triage()` | **High** | Receives host commands. Validates and queues work. | < 50 μs |
| `dma_manager()` | **High** | Manages DMA completion and buffer chains. | < 200 μs |
| `fault_handler()` | **Critical** | Handles bus/parity errors. | < 20 μs |
| `graphics_worker()` | **Normal** | Performs rendering calculations. | Yields every 1 ms |
| `postscript_interpreter()` | **Low** | Interprets PS commands. | Yields every 5 ms |
| `memory_scrubber()` | **Idle** | Background memory integrity checks. | Yields frequently |

### Task Implementation Pattern:

```rust
#[embassy_executor::task]
async fn high_priority_task() {
    loop {
        // Wait for event
        let event = EVENT_SIGNAL.wait().await;
        
        // Perform minimal work
        let work_item = prepare_work(event);
        
        // Delegate to lower priority
        WORK_QUEUE.send(work_item).await;
        
        // Task complete - yield immediately
    }
}

#[embassy_executor::task]
async fn low_priority_worker() {
    loop {
        // Get work item
        let work = WORK_QUEUE.receive().await;
        
        // Start complex operation
        let mut state = begin_operation(work);
        
        // Periodically yield during long operations
        while !state.is_complete() {
            // Do chunk of work
            state.process_chunk();
            
            // Yield to scheduler
            embassy_time::Timer::after(Duration::from_micros(100)).await;
        }
        
        // Signal completion
        COMPLETION_SIGNAL.signal(state.result);
    }
}
```

## 4. Advanced Architectural Patterns

To manage complexity and maximize performance, the firmware will employ several advanced patterns.

### 4.1. Work Splitting (Priority Demotion)

For tasks that have both an urgent and a non-urgent component, we split the work across two tasks with different priorities.

```rust
// High-priority triage task
#[embassy_executor::task]
async fn command_triage() {
    loop {
        let cmd = COMMAND_CHANNEL.receive().await;
        
        // Immediate acknowledgment (urgent)
        acknowledge_to_host(cmd.id);
        
        // Validate command (quick)
        if let Ok(validated) = validate_command(cmd) {
            // Queue for processing (non-urgent)
            WORK_QUEUE.send(WorkItem::from(validated)).await;
        } else {
            // Send error response (urgent)
            send_error_to_host(cmd.id, ERROR_INVALID_COMMAND);
        }
    }
}

// Low-priority processing task
#[embassy_executor::task]
async fn command_processor() {
    loop {
        let work = WORK_QUEUE.receive().await;
        
        match work.command_type {
            CommandType::RenderPath => {
                // Long operation - can run uninterrupted
                let result = tessellate_and_render_path(work.data).await;
                RESULT_QUEUE.send(result).await;
            }
            CommandType::ComplexTransform => {
                // Very long operation - yield periodically
                let result = compute_transform_matrix(work.data).await;
                RESULT_QUEUE.send(result).await;
            }
            _ => {}
        }
    }
}
```

**Benefit:** The system remains highly responsive to the host, even when the CPU is busy with a long rendering task. The high-priority part is kept extremely short, preventing system starvation.

### 4.2. Interrupt Frequency Reduction

The firmware will actively work to reduce the number of interrupts the CPU has to handle.

#### Scatter/Gather DMA:

```rust
#[repr(C)]
struct DmaDescriptor {
    source: u32,
    destination: u32,
    count: u32,
    next: *mut DmaDescriptor,
    control: u32,
}

async fn setup_texture_load(textures: &[TextureInfo]) {
    // Build DMA chain
    let mut descriptors = Vec::with_capacity(textures.len());
    
    for (i, tex) in textures.iter().enumerate() {
        let desc = DmaDescriptor {
            source: tex.host_address,
            destination: tex.vram_address,
            count: tex.size,
            next: if i < textures.len() - 1 {
                &descriptors[i + 1] as *const _ as *mut _
            } else {
                null_mut()
            },
            control: DMA_CTRL_CHAIN | if i == textures.len() - 1 {
                DMA_CTRL_IRQ_ON_COMPLETE
            } else {
                0
            },
        };
        descriptors.push(desc);
    }
    
    // Start chain - only one interrupt at the end
    start_dma_chain(&descriptors[0]);
    
    // Wait for single completion interrupt
    DMA_COMPLETE_SIGNAL.wait().await;
}
```

#### Interrupt Batching (Hybrid Polling):

```rust
#[embassy_executor::task]
async fn mailbox_batch_handler() {
    loop {
        // Wait for first interrupt
        MAILBOX_IRQ_SIGNAL.wait().await;
        
        // Disable interrupts temporarily
        disable_mailbox_irq();
        
        // Poll and drain all pending commands
        let mut commands = Vec::new();
        while mailbox_has_data() {
            if let Some(cmd) = read_mailbox_command() {
                commands.push(cmd);
            }
            
            // Prevent infinite loop
            if commands.len() >= 32 {
                break;
            }
        }
        
        // Re-enable interrupts
        enable_mailbox_irq();
        
        // Process batch
        for cmd in commands {
            COMMAND_QUEUE.send(cmd).await;
        }
    }
}
```

### 4.3. Pipeline-Aware Task Design

Tasks are designed to maximize i860 pipeline efficiency:

```rust
// Bad: Causes pipeline stalls
async fn inefficient_renderer() {
    for pixel in pixels {
        let color = calculate_color(pixel); // Pipeline stall
        write_pixel(pixel, color);           // Data dependency stall
    }
}

// Good: Keeps pipeline full
async fn efficient_renderer() {
    // Process in tiles to fit in cache
    for tile in pixels.chunks(TILE_SIZE) {
        // Prefetch next tile data
        prefetch_tile(tile.next());
        
        // Unroll loop for pipeline
        let mut colors = [0u32; 8];
        let mut coords = [(0u32, 0u32); 8];
        
        // Calculate 8 pixels in parallel (no dependencies)
        for i in 0..8 {
            colors[i] = calculate_color(tile[i]);
            coords[i] = tile[i].coords;
        }
        
        // Write 8 pixels (can use burst mode)
        write_pixel_burst(&coords, &colors);
        
        // Yield periodically
        if tile.index % 16 == 0 {
            embassy_time::yield_now().await;
        }
    }
}
```

## 5. Memory Management

The firmware uses a custom allocator optimized for the i860's memory hierarchy:

```rust
pub struct I860MemoryManager {
    // Fast on-chip memory for critical data
    sram_allocator: BumpAllocator<0x0000_0000, 0x0000_8000>, // 32KB
    
    // Main DRAM with pools for different sizes
    dram_pools: [MemoryPool; 8],
    
    // VRAM allocator for graphics data
    vram_allocator: BuddyAllocator<0x1000_0000, 0x1040_0000>, // 4MB
}

impl I860MemoryManager {
    pub async fn alloc_dma_buffer(&self, size: usize) -> Result<DmaBuffer, AllocError> {
        // DMA buffers must be aligned and in specific memory regions
        let addr = self.dram_pools[size_to_pool_index(size)]
            .alloc_aligned(size, 32)
            .await?;
            
        Ok(DmaBuffer {
            addr,
            size,
            pool_index: size_to_pool_index(size),
        })
    }
    
    pub async fn alloc_texture(&self, width: u32, height: u32, format: PixelFormat) -> Result<Texture, AllocError> {
        let size = width * height * format.bytes_per_pixel();
        let addr = self.vram_allocator.alloc(size).await?;
        
        Ok(Texture {
            vram_addr: addr,
            width,
            height,
            format,
        })
    }
}
```

## 6. Hardware Abstraction Layer (HAL)

The firmware includes a comprehensive HAL for NeXTdimension hardware:

```rust
pub mod hal {
    pub mod dma {
        pub struct DmaEngine {
            channels: [DmaChannel; 4],
        }
        
        impl DmaEngine {
            pub async fn transfer(&mut self, 
                                  channel: usize,
                                  src: u32, 
                                  dst: u32, 
                                  count: u32) -> Result<(), DmaError> {
                let ch = &mut self.channels[channel];
                
                // Setup transfer
                ch.set_source(src);
                ch.set_destination(dst);
                ch.set_count(count);
                ch.set_control(DMA_CTRL_START | DMA_CTRL_IRQ_ON_COMPLETE);
                
                // Wait for completion
                ch.completion_signal.wait().await;
                
                // Check for errors
                if ch.status() & DMA_STATUS_ERROR != 0 {
                    Err(DmaError::TransferFailed)
                } else {
                    Ok(())
                }
            }
        }
    }
    
    pub mod video {
        pub struct VideoController {
            current_buffer: AtomicU8,
            buffers: [FrameBuffer; 2],
        }
        
        impl VideoController {
            pub async fn wait_vblank(&self) {
                VBLANK_SIGNAL.wait().await;
            }
            
            pub fn swap_buffers(&self) {
                let next = (self.current_buffer.load(Ordering::Acquire) + 1) % 2;
                
                // Atomic swap
                unsafe {
                    ptr::write_volatile(VIDEO_BUFFER_REG, self.buffers[next].addr);
                }
                
                self.current_buffer.store(next, Ordering::Release);
            }
        }
    }
    
    pub mod mailbox {
        pub struct Mailbox {
            tx_queue: Queue<HostMessage, 32>,
            rx_signal: Signal<CriticalSectionRawMutex, ()>,
        }
        
        impl Mailbox {
            pub async fn send_to_host(&self, msg: HostMessage) -> Result<(), MailboxError> {
                // Wait for space
                while self.is_full() {
                    embassy_time::Timer::after(Duration::from_micros(10)).await;
                }
                
                // Send message
                unsafe {
                    ptr::write_volatile(MAILBOX_TX_REG, msg.encode());
                }
                
                Ok(())
            }
            
            pub async fn receive_from_host(&self) -> HostMessage {
                loop {
                    if let Some(msg) = self.try_receive() {
                        return msg;
                    }
                    
                    // Wait for interrupt
                    self.rx_signal.wait().await;
                }
            }
        }
    }
}
```

## 7. Performance Optimizations

### 7.1. Zero-Copy Message Passing

```rust
use heapless::pool::{Pool, Node};

// Pre-allocated message pool
pool!(MESSAGE_POOL: [u8; 1024]);

pub struct ZeroCopyMessage {
    node: &'static mut Node<[u8; 1024]>,
    len: usize,
}

impl ZeroCopyMessage {
    pub fn alloc() -> Option<Self> {
        MESSAGE_POOL.alloc().map(|node| Self { node, len: 0 })
    }
    
    pub fn as_bytes(&self) -> &[u8] {
        &self.node[..self.len]
    }
}

impl Drop for ZeroCopyMessage {
    fn drop(&mut self) {
        // Return to pool automatically
        unsafe { MESSAGE_POOL.free(self.node) }
    }
}
```

### 7.2. Lock-Free Data Structures

```rust
use atomic_ring_buffer::AtomicRingBuffer;

static RENDER_QUEUE: AtomicRingBuffer<RenderCommand, 256> = AtomicRingBuffer::new();

#[embassy_executor::task]
async fn render_producer() {
    loop {
        let cmd = create_render_command().await;
        
        // Lock-free enqueue
        while !RENDER_QUEUE.try_push(cmd).is_ok() {
            // Queue full, yield
            embassy_time::yield_now().await;
        }
    }
}

#[embassy_executor::task]
async fn render_consumer() {
    loop {
        // Lock-free dequeue
        if let Some(cmd) = RENDER_QUEUE.pop() {
            execute_render_command(cmd).await;
        } else {
            // Queue empty, yield
            embassy_time::yield_now().await;
        }
    }
}
```

## 8. Real-Time Guarantees

The firmware provides real-time guarantees through careful task design:

```rust
pub struct RealTimeConfig {
    pub max_frame_time: Duration,      // 16.67ms for 60 FPS
    pub max_command_latency: Duration, // 100μs host response
    pub max_dma_latency: Duration,     // 1ms DMA completion
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    // Initialize hardware
    let hw = initialize_hardware();
    
    // Spawn critical tasks with guaranteed priorities
    spawner.spawn(vblank_handler(hw.video)).unwrap();
    spawner.spawn(fault_handler(hw.fault_detector)).unwrap();
    
    // Spawn high-priority tasks
    spawner.spawn(mailbox_triage(hw.mailbox)).unwrap();
    spawner.spawn(dma_manager(hw.dma)).unwrap();
    
    // Spawn normal priority workers
    for i in 0..4 {
        spawner.spawn(graphics_worker(i)).unwrap();
    }
    
    // Spawn low priority tasks
    spawner.spawn(postscript_interpreter()).unwrap();
    spawner.spawn(memory_scrubber()).unwrap();
    
    // Start deadline monitor
    spawner.spawn(deadline_monitor(RealTimeConfig {
        max_frame_time: Duration::from_micros(16_667),
        max_command_latency: Duration::from_micros(100),
        max_dma_latency: Duration::from_millis(1),
    })).unwrap();
}

#[embassy_executor::task]
async fn deadline_monitor(config: RealTimeConfig) {
    let mut frame_deadline = Instant::now() + config.max_frame_time;
    
    loop {
        // Check frame deadline
        if Instant::now() > frame_deadline {
            log::error!("Frame deadline missed!");
            PERFORMANCE_COUNTERS.missed_frames.fetch_add(1, Ordering::Relaxed);
        }
        
        // Update deadline
        VBLANK_SIGNAL.wait().await;
        frame_deadline = Instant::now() + config.max_frame_time;
    }
}
```

## 9. Testing and Validation

### 9.1. Unit Testing

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use embassy_executor::Spawner;
    use embassy_time::MockDriver;
    
    #[embassy_executor::test]
    async fn test_interrupt_latency() {
        let spawner = Spawner::for_current_executor().await;
        
        // Setup mock hardware
        let mock_hw = MockHardware::new();
        
        // Spawn ISR handler
        spawner.spawn(mailbox_irq_task(mock_hw.clone())).unwrap();
        
        // Trigger interrupt
        let start = Instant::now();
        mock_hw.trigger_mailbox_irq();
        
        // Wait for acknowledgment
        mock_hw.wait_for_ack().await;
        let latency = start.elapsed();
        
        // Verify low latency
        assert!(latency < Duration::from_micros(50));
    }
    
    #[embassy_executor::test]
    async fn test_priority_inversion() {
        // Test that high priority tasks preempt low priority
        let high_started = Arc::new(AtomicBool::new(false));
        let low_completed = Arc::new(AtomicBool::new(false));
        
        // Start low priority task
        let low_handle = spawn_low_priority_task(low_completed.clone());
        
        // Let it run briefly
        Timer::after(Duration::from_millis(1)).await;
        
        // Start high priority task
        let high_handle = spawn_high_priority_task(high_started.clone());
        
        // High priority should run immediately
        Timer::after(Duration::from_micros(100)).await;
        assert!(high_started.load(Ordering::Acquire));
        assert!(!low_completed.load(Ordering::Acquire));
    }
}
```

### 9.2. Integration Testing

```rust
#[embassy_executor::test]
async fn test_full_render_pipeline() {
    let system = TestSystem::new();
    
    // Send render command
    system.send_host_command(Command::RenderTriangle {
        vertices: test_triangle(),
        color: Color::RED,
    }).await;
    
    // Wait for one frame
    system.wait_vblank().await;
    system.wait_vblank().await;
    
    // Verify triangle rendered
    let framebuffer = system.read_framebuffer();
    assert!(contains_red_triangle(&framebuffer));
    
    // Verify performance
    let stats = system.performance_stats();
    assert!(stats.frame_time < Duration::from_millis(17));
    assert_eq!(stats.missed_frames, 0);
}
```

## 10. Build Configuration

```toml
# Cargo.toml
[package]
name = "nextdimension-firmware"
version = "1.0.0"
edition = "2021"

[dependencies]
embassy-executor = { version = "0.4", features = ["arch-cortex-m", "executor-thread", "integrated-timers"] }
embassy-time = { version = "0.2", features = ["tick-hz-32_768"] }
embassy-sync = "0.5"
heapless = "0.8"
atomic_ring_buffer = "0.1"
cortex-m = "0.7"
cortex-m-rt = "0.7"
defmt = "0.3"
defmt-rtt = "0.4"
panic-probe = { version = "0.3", features = ["print-defmt"] }

[features]
default = ["defmt", "time-driver-rtc"]
defmt = ["dep:defmt", "embassy-executor/defmt", "embassy-time/defmt"]

[profile.release]
codegen-units = 1
debug = 2
debug-assertions = false
incremental = false
lto = "fat"
opt-level = 3
overflow-checks = false

[patch.crates-io]
# Custom i860 support
embassy-executor = { git = "https://github.com/nextdimension/embassy", branch = "i860-support" }
```

## 11. Deployment and Runtime Configuration

```rust
// Runtime configuration loaded from flash
#[link_section = ".config"]
static CONFIG: FirmwareConfig = FirmwareConfig {
    task_priorities: TaskPriorities {
        vblank: Priority::Critical,
        mailbox: Priority::High,
        graphics: Priority::Normal,
        postscript: Priority::Low,
    },
    
    buffer_sizes: BufferConfig {
        mailbox_queue: 32,
        render_queue: 256,
        dma_descriptors: 64,
    },
    
    performance: PerformanceConfig {
        max_fps: 60,
        vsync_enabled: true,
        pipeline_prefetch: true,
        dual_issue_enabled: true,
    },
};
```

## 12. System-Wide Benefits

This `embassy`-based, asynchronous, cooperative architecture provides a number of powerful benefits that are perfectly suited to the i860's strengths and weaknesses:

1. **Performance:** It allows long-running, performance-critical tasks (like rendering) to run for extended periods without being preempted, making full use of the i860's deep pipelines and dual-issue capabilities.

2. **Responsiveness:** It ensures that high-priority, real-time events (like VBlank) are always serviced immediately, preventing visual glitches or missed deadlines.

3. **Correctness:** It gives the developer complete control over task scheduling and prioritization, overriding the hardware's fixed interrupt priorities with an intelligent, application-aware software model.

4. **Simplicity & Maintainability:** The code is organized into small, independent, single-purpose asynchronous tasks that are easier to reason about, test, and maintain than a complex, monolithic interrupt-driven state machine.

5. **Safety:** It leverages Rust's and `embassy`'s compile-time guarantees against data races in a concurrent environment.

6. **Power Efficiency:** Although less critical for NeXTdimension, the cooperative model allows the CPU to enter low-power states when all tasks are waiting.

7. **Debuggability:** Each task can be instrumented and monitored independently, making performance analysis and debugging much easier.

## 13. Performance Metrics

Expected performance characteristics with this architecture:

| Metric | Target | Achievable |
|--------|--------|------------|
| Interrupt Latency | < 100 cycles | 20-50 cycles |
| Frame Rate | 60 FPS | 60-72 FPS |
| Command Response | < 100 μs | 10-50 μs |
| Pipeline Efficiency | > 80% | 85-95% |
| Context Switch Cost | N/A | ~10 cycles |
| Memory Bandwidth Utilization | > 70% | 75-85% |

## 14. Conclusion

By adopting this modern, asynchronous architecture, we can build firmware that not only meets the real-time requirements of the NeXTdimension board but also extracts maximum performance from the unique i860 architecture. The embassy framework provides the perfect abstraction for managing the complex interactions between hardware components while maintaining the cooperative execution model that keeps the i860's deep pipelines full and productive.

This architecture represents a significant advancement over traditional interrupt-driven firmware designs, demonstrating how modern software engineering practices can unlock the full potential of historical hardware.

---

*"The best interrupt is the one that never interrupts."*