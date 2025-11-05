#ifndef SSL_H
#define SSL_H

#include "ringbuffer.h"
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

// SecureTransport is the primary implementation
// OpenSSL 3.x is fallback if SecureTransport unavailable

typedef enum {
    SSL_BACKEND_SECURETRANSPORT = 0,
    SSL_BACKEND_OPENSSL = 1
} SSLBackend;

typedef struct SSLContext SSLContext;

// Initialize SSL context
// Uses SecureTransport by default, falls back to OpenSSL if needed
// Returns 0 on success, -1 on error
int ssl_init(SSLContext** ctx, bool disable_cert_validation);

// Cleanup SSL context
void ssl_cleanup(SSLContext* ctx);

// Connect SSL socket (performs TLS handshake)
// hostname: Server hostname for SNI (Server Name Indication)
// Returns 0 on success, -1 on error
int ssl_connect(SSLContext* ctx, int fd, const char* hostname);

// Read decrypted data directly into ring buffer (zero-copy)
// Returns bytes read, -1 on error, 0 on would-block
ssize_t ssl_read(SSLContext* ctx, RingBuffer* rb);

// Write data from ring buffer to SSL socket
// Returns bytes written, -1 on error, 0 on would-block
ssize_t ssl_write(SSLContext* ctx, RingBuffer* rb);

// Get which backend is being used
SSLBackend ssl_get_backend(SSLContext* ctx);

// Get last NIC timestamp (for latency measurement)
// Returns timestamp in nanoseconds, or 0 if not available
uint64_t ssl_get_last_nic_timestamp_ns(SSLContext* ctx);

// Get last NIC timestamp (for latency measurement)
// Returns timestamp in CPU cycles, or 0 if not available
uint64_t ssl_get_last_nic_timestamp_ticks(SSLContext* ctx);

// Check if SSL handshake is complete
// Returns true if handshake is finished, false otherwise
bool ssl_is_handshake_complete(SSLContext* ctx);

// Set user data for diagnostic tracking
void ssl_set_user_data(SSLContext* ctx, void* user_data);

// Get diagnostic counters
uint64_t ssl_get_bytes_read(SSLContext* ctx);
uint64_t ssl_get_read_calls(SSLContext* ctx);

#endif // SSL_H

