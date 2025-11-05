#ifndef IO_KQUEUE_H
#define IO_KQUEUE_H

#include <stdint.h>
#include <sys/types.h>
#include <sys/event.h>
#include <sys/socket.h>
#include "ringbuffer.h"

#define IO_MAX_SOCKETS 64

typedef struct {
    int fd;
    RingBuffer* rx_ring;  // Receive ring buffer (zero-copy target)
    RingBuffer* tx_ring;  // Transmit ring buffer
    void* user_data;      // User context
    // NIC timestamp tracking
    uint64_t last_nic_timestamp_ns;  // Kernel timestamp when packet arrived (nanoseconds)
    uint64_t last_nic_timestamp_ticks; // Same timestamp in CPU cycles
} IOSocket;

typedef struct {
    int kq;                           // kqueue file descriptor
    IOSocket sockets[IO_MAX_SOCKETS]; // Socket registry
    int socket_count;                 // Active socket count
    int e_core_pinned;                 // Whether thread is pinned to E-core
    
#ifdef __APPLE__
    // GCD queues for optimized CPU scheduling (M4 optimization)
    void* io_queue;                    // Dispatch queue for I/O operations (E-core)
    void* net_queue;                   // Dispatch queue for network receive (P-core 0)
    void* ssl_queue;                   // Dispatch queue for SSL encryption (P-core 1)
    void* parse_queue;                 // Dispatch queue for parsing (P-core 2)
#endif
} IOContext;

// Initialize kqueue I/O context
// Pins calling thread to E-core for efficient I/O handling
// Returns 0 on success, -1 on error
int io_init(IOContext* ctx);

// Cleanup I/O context
void io_cleanup(IOContext* ctx);

// Add socket to kqueue monitoring
// Sets socket to non-blocking, enables SO_TIMESTAMP_OLD
// Returns socket index on success, -1 on error
int io_add_socket(IOContext* ctx, int fd, RingBuffer* rx_ring, RingBuffer* tx_ring, void* user_data);

// Remove socket from monitoring
// Returns 0 on success, -1 on error
int io_remove_socket(IOContext* ctx, int fd);

// Poll for I/O events
// timeout_us: timeout in microseconds (0 for non-blocking, default 10µs for HFT)
// Returns number of events ready, -1 on error
int io_poll(IOContext* ctx, struct kevent* events, int max_events, int timeout_us);

// Read data from socket directly into ring buffer (zero-copy)
// Captures NIC timestamp via SO_TIMESTAMP_OLD if available
// Returns bytes read, -1 on error, 0 on EAGAIN
ssize_t io_read(IOContext* ctx, int socket_index);

// Write data from ring buffer to socket
// Returns bytes written, -1 on error, 0 on EAGAIN
ssize_t io_write(IOContext* ctx, int socket_index);

// Get last captured NIC timestamp for a socket
// Returns timestamp in nanoseconds (0 if not available)
uint64_t io_get_last_nic_timestamp_ns(IOContext* ctx, int socket_index);

// Get last captured NIC timestamp in CPU cycles
uint64_t io_get_last_nic_timestamp_ticks(IOContext* ctx, int socket_index);

#ifdef __APPLE__
// M4 OPTIMIZATION: Get GCD queues for optimized CPU scheduling
// Returns GCD queue pointer (dispatch_queue_t) or NULL if not available
void* io_get_io_queue(IOContext* ctx);      // I/O operations queue (E-core)
void* io_get_net_queue(IOContext* ctx);      // Network receive queue (P-core 0)
void* io_get_ssl_queue(IOContext* ctx);     // SSL encryption queue (P-core 1)
void* io_get_parse_queue(IOContext* ctx);    // Parsing queue (P-core 2)
#endif

#endif // IO_KQUEUE_H

