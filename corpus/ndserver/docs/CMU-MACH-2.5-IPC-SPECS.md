I'll search for specific CMU Mach 2.5 IPC specification details for you.Based on the documentation and source code I found, here's a summary of the CMU Mach 2.5 IPC specification:

## CMU Mach 2.5 IPC Specification Summary

### Core IPC Primitives

**Ports** - Finite-length message queues providing protected, unidirectional communication channels. Each port has exactly one receiver but can have multiple senders. Ports are capability-based objects referenced through port rights.

**Port Rights** - Three fundamental types:
- **Receive rights**: Exactly one per port, grant message reception capability, automatically imply send rights, cause port destruction when deallocated
- **Send rights**: Can exist in multiple tasks, permit message sending, survive port destruction with notifications, can be duplicated and transferred
- **Ownership rights**: Indicate port ownership (being phased out in favor of backup port mechanism in 2.5)

### Message Structure

**msg_header_t** - Fixed message header (Mach 2.5 format):
```c
typedef struct {
    unsigned int msg_unused : 24,
                 msg_simple : 8;
    msg_size_t   msg_size;
    integer_t    msg_type;
    port_t       msg_local_port;    // Reply port
    port_t       msg_remote_port;   // Destination port
    integer_t    msg_id;
} msg_header_t;
```

Fields:
- `msg_simple`: Flag indicating simple (inline data only) vs complex messages
- `msg_size`: Total message size in bytes (max 8192 bytes)
- `msg_type`: Message priority/type (MSG_TYPE_NORMAL or MSG_TYPE_EMERGENCY)
- `msg_remote_port`: Destination port (must have send/send-once right)
- `msg_local_port`: Reply port (conventional)
- `msg_id`: Operation/function identifier (not used by kernel)

**msg_type_t** - Type descriptor for message data:
```c
typedef struct {
    unsigned int msg_type_name : 8,        // Data type
                 msg_type_size : 8,        // Bits per item
                 msg_type_number : 12,     // Item count
                 msg_type_inline : 1,      // Inline vs pointer
                 msg_type_longform : 1,    // Use long form
                 msg_type_deallocate : 1,  // Deallocate flag
                 msg_type_unused : 1;
} msg_type_t;
```

**msg_type_long_t** - Extended descriptor for large values

### Primary System Calls

**msg_send()** - Asynchronous message transmission
- Copies message to destination port's queue
- Returns immediately (doesn't wait for receipt)
- Can specify timeout options

**msg_receive()** - Blocking message reception
- Retrieves message from port or port set
- Blocks if queue empty (subject to timeout)
- Can receive from port sets (multiplexing)

**msg_rpc()** - Combined send/receive for RPC
- Optimized single call for request/reply pattern
- Reduces system call overhead
- Atomic send-then-receive operation

**Port Management Calls** (new in 2.5):
- `port_allocate()` - Create new port with receive right
- `port_deallocate()` - Remove port right
- `port_set_allocate()` - Create port set
- `port_set_add()` / `port_set_remove()` - Manage port set members
- `port_insert_send()` / `port_extract_send()` - Transfer send rights
- `port_insert_receive()` / `port_extract_receive()` - Transfer receive rights
- `port_set_backup()` - Set backup port for receive right deallocation
- `port_names()`, `port_type()`, `port_rename()` - Query/modify ports

### Message Data Types

Predefined types include:
- MSG_TYPE_INTEGER_16, MSG_TYPE_INTEGER_32
- MSG_TYPE_PORT (renamed to distinguish send/receive)
- MSG_TYPE_PORT_OWNERSHIP (obsolete in 2.5)
- MSG_TYPE_PORT_RECEIVE (obsolete in 2.5)
- MSG_TYPE_UNSTRUCTURED for raw data

### Key Mach 2.5 Enhancements

**Backup Port Mechanism** - Replaces ownership rights. When receive rights are deallocated, if a backup port exists, the rights are sent to it in a notification rather than destroying the port.

**Port Sets** - Enable receiving from multiple ports through single call, supporting server multiplexing across client connections.

**Notifications** - Port destroyed notifications now use PORT_NULL in msg_remote_port field (changed from 2.0 which sent task kernel port).

**Kernel Special Ports** - Support for TASK_KERNEL_PORT and THREAD_KERNEL_PORT with task_get/set_special_port functions.

### Memory Management

**Copy-on-Write** - Large message data transferred via VM page remapping, deferring actual copying until modification occurs.

**Out-of-line Memory** - Data specified by pointer rather than inline, uses VM-based transfer for efficiency, indicated by msg_type_inline=0.

### Port Namespace

Each task maintains a 32-bit integer namespace mapping port names to port rights. Names are task-local with no system-wide meaning. The kernel maintains translation tables (ipc_entry structures) mapping names to actual port capabilities.

### MIG Support

Mach 2.5 includes full MIG (Mach Interface Generator) support, compiling .defs specifications into client/server stubs for type-safe RPC programming.

This specification formed the foundation for NeXTSTEP 3.3 and OPENSTEP 4.2, providing the IPC substrate that evolved into modern Darwin/XNU's Mach 3.0-based implementation.
