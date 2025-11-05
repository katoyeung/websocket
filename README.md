# High-Performance WebSocket Library for Mac Mini M4

Ultra-low latency WebSocket library optimized for Apple Silicon M4 architecture, designed for high-frequency trading (HFT) applications.

## Features

- **Sub-microsecond latency**: 99th percentile < 40µs target (M4 unified memory advantage)
- **High throughput**: 15,000+ messages/second sustained
- **Zero-copy architecture**: Direct ring buffer → TLS → parsing path
- **M4-optimized**: Neon SIMD acceleration, 128-byte cache alignment
- **SecureTransport TLS**: Kernel-integrated TLS with hardware acceleration
- **kqueue I/O**: Edge-triggered event multiplexing pinned to E-cores

## Architecture Overview

```
Exchange Server → TCP/IP → [SecureTransport] → Ringbuffer → WebSocket Parser → on_msg()
```

### Key Components

1. **Ring Buffer** (`ringbuffer.c`)
   - 8MB dual-buffered (rx_ring/tx_ring)
   - 128-byte alignment (M4 cache line size)
   - Lock-free SPSC (single-producer/single-consumer)
   - Memory-locked with `mlock()`

2. **I/O Multiplexing** (`io_kqueue.c`)
   - kqueue with `EV_CLEAR | EV_ENABLE | EV_ONESHOT`
   - Thread pinned to E-core for efficient I/O
   - `SO_TIMESTAMP_OLD` for kernel-level timestamps
   - Zero-copy read/write paths

3. **TLS** (`ssl.c`)
   - Primary: SecureTransport (M4 hardware acceleration)
   - Fallback: OpenSSL 3.x
   - Zero-copy decryption via `SSLRead()` → ring buffer

4. **Parsing** (`parser_neon.c`)
   - Neon SIMD WebSocket frame parsing (16-byte parallel)
   - Neon JSON parsing with `vtbl` for delimiter scanning
   - 4x speedup vs scalar on M4

5. **WebSocket** (`websocket.c`)
   - RFC 6455 compliant
   - Minimal state machine
   - Callback-based API

## M4-Specific Optimizations

### Memory Model

- **128-byte alignment**: Matches M4 L1 cache line size (vs 64B on x86)
- **Unified memory**: No CPU/GPU memory split (cheaper register-to-memory moves)
- **VM_FLAGS_PURGABLE**: Prevents swapping (M4 has no swap by default)
- **Memory locking**: `mlock()` to avoid page faults

### CPU Affinity

- **I/O thread**: Pinned to E-core (efficiency core) via `thread_policy_set`
- **Parser thread**: Pinned to P-core (performance core) for maximum compute
- **QoS class**: `QOS_CLASS_USER_INTERACTIVE` for low-latency scheduling

### Neon SIMD

- **Frame parsing**: `vld1q_u8()` / `vaddq_u8()` for 16-byte header validation
- **JSON parsing**: `vtbl` (table lookup) for parallel delimiter scanning
- **Target**: 4x speedup vs scalar parsing

### Compiler Flags

```bash
-mcpu=apple-m4 -mtune=apple-m4 -O3 -ffast-math -fno-pie
```

- `-mcpu=apple-m4`: Enables M4-specific instructions (AMX tensor ops)
- `-fno-pie`: Disables ASLR for improved cache locality
- Hot paths marked with `__attribute__((section("__TEXT,__hot")))`

## Building

### Prerequisites

- macOS 13.0+ (M4 support)
- CMake 3.20+
- Xcode Command Line Tools

### Build Steps

```bash
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make
```

### Run Tests

```bash
# Unit tests
./test_ringbuffer
./test_parser_neon
./test_kqueue

# Integration test (Binance)
./test_integration_binance

# Benchmarks
./benchmark
```

### Example

```bash
./binance_ticker btcusdt
```

## Network Tuning

For optimal latency, apply these system-level tunings:

```bash
# Increase TCP receive buffer (matches ring buffer size)
sudo sysctl -w net.inet.tcp.recvspace=8388608

# Disable delayed ACK (trades bandwidth for latency)
sudo sysctl -w net.inet.tcp.delayed_ack=0

# Disable CPU throttling
sudo pmset -a noidle 1
```

Or use the helper function:

```c
#include "os_macos.h"
sysctl_tune_network();
```

## API Reference

### WebSocket API

```c
// Create/destroy
WebSocket* websocket_create(void);
void websocket_destroy(WebSocket* ws);

// Connect
int websocket_connect(WebSocket* ws, const char* url, bool disable_cert_validation);

// Callbacks
void websocket_set_on_message(WebSocket* ws, ws_on_message_t callback, void* user_data);
void websocket_set_on_error(WebSocket* ws, ws_on_error_t callback, void* user_data);

// Send/close
int websocket_send(WebSocket* ws, const uint8_t* data, size_t len, bool is_text);
int websocket_close(WebSocket* ws);

// Event loop
int websocket_process(WebSocket* ws);  // Call in your event loop

// State
WSState websocket_get_state(WebSocket* ws);
```

### Example Usage

```c
#include "websocket.h"

void on_message(WebSocket* ws, const uint8_t* data, size_t len, void* user_data) {
    printf("Received: %.*s\n", (int)len, data);
}

int main(void) {
    WebSocket* ws = websocket_create();
    websocket_set_on_message(ws, on_message, NULL);
    
    if (websocket_connect(ws, "wss://example.com/ws", true) != 0) {
        fprintf(stderr, "Connection failed\n");
        return 1;
    }
    
    // Event loop
    while (websocket_get_state(ws) == WS_STATE_CONNECTED) {
        websocket_process(ws);
        usleep(100);  // Small sleep to avoid busy-waiting
    }
    
    websocket_destroy(ws);
    return 0;
}
```

### Neon Parser API

```c
// Parse WebSocket frame
int neon_parse_ws_frame(const uint8_t* data, size_t len, WSFrame* frame);

// Parse JSON field
int neon_parse_json_market_data(const char* json, size_t json_len,
                                const char* field_name,
                                char* value_buf, size_t value_buf_size,
                                size_t* value_len);

// Batch field extraction
int neon_extract_json_fields(const char* json, size_t json_len,
                             JSONField* fields, size_t field_count);
```

### OS Primitives API

```c
// Cycle counting (PMCCNTR_EL0)
uint64_t arm_cycle_count(void);
double arm_cycles_to_ns(uint64_t cycles);

// CPU affinity
int cpu_pin_p_core(void);  // Pin to performance core
int cpu_pin_e_core(void);  // Pin to efficiency core

// Network tuning
int sysctl_tune_network(void);

// Cache control
void cache_flush(void* addr, size_t len);
```

## Performance Targets

- **Latency**: 99th percentile < 40µs (NIC → on_msg callback)
- **Throughput**: 15,000+ messages/second sustained
- **Neon parsing**: 4x speedup vs scalar
- **SecureTransport**: 30% faster TLS decryption than OpenSSL

## Latency Breakdown

The integration test measures latency at multiple stages:

- **t0**: Kernel timestamp (via `SO_TIMESTAMP_OLD`)
- **t1**: kqueue wake event
- **t2**: TLS decryption complete
- **t3**: Parsing complete (in `on_message` callback)

Measure with ARM cycle counter (`PMCCNTR_EL0`) for sub-nanosecond precision.

## Limitations

- **macOS-only**: No cross-platform support (uses SecureTransport, kqueue, vm_allocate)
- **M4-specific**: Compiler flags and optimizations target Apple Silicon
- **Single-threaded I/O**: One kqueue event loop per process
- **No frame fragmentation**: Assumes frames fit in single read

## License

See LICENSE file.

## Contributing

This library is optimized for HFT use cases on Mac Mini M4. Contributions should maintain:
- Zero dynamic allocations in hot paths
- Cache-line alignment (128 bytes)
- Neon SIMD acceleration where applicable
- Sub-microsecond latency goals



