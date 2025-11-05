#ifndef NETWORK_FRAMEWORK_H
#define NETWORK_FRAMEWORK_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <sys/types.h>

// Network.framework integration for user-space kernel bypass (M4 optimization)
// This provides a C-compatible interface to Network.framework APIs

// Network connection handle (opaque)
typedef struct NetworkConnection NetworkConnection;

// Callback for received data (zero-copy)
// data: Pointer to data (dispatch_data_t internally, zero-copy)
// len: Length of data
// user_data: User-provided context
typedef void (*network_receive_callback_t)(const void* data, size_t len, void* user_data);

// Create a Network.framework connection (user-space kernel bypass)
// host: Hostname (e.g., "api.binance.com")
// port: Port number or service name (e.g., "443" or "https")
// Returns connection handle on success, NULL on error
NetworkConnection* network_connection_create(const char* host, const char* port);

// Configure connection for kernel bypass (M4 optimization)
// conn: Connection handle
// disable_kernel_tcp: If true, bypasses kernel TCP stack (user-space only)
// Returns 0 on success, -1 on error
int network_connection_configure(NetworkConnection* conn, bool disable_kernel_tcp);

// Set receive callback for zero-copy data delivery
// conn: Connection handle
// callback: Function to call when data is received
// user_data: User context passed to callback
// Returns 0 on success, -1 on error
int network_connection_set_receive_callback(NetworkConnection* conn, 
                                             network_receive_callback_t callback, 
                                             void* user_data);

// Start connection
// conn: Connection handle
// Returns 0 on success, -1 on error
int network_connection_start(NetworkConnection* conn);

// Send data
// conn: Connection handle
// data: Data to send
// len: Length of data
// Returns bytes sent on success, -1 on error
ssize_t network_connection_send(NetworkConnection* conn, const void* data, size_t len);

// Get file descriptor (for compatibility with existing code)
// Note: Network.framework may not provide a traditional FD
// Returns FD on success, -1 if not available
int network_connection_get_fd(NetworkConnection* conn);

// Close connection
// conn: Connection handle
void network_connection_close(NetworkConnection* conn);

// Cleanup connection
// conn: Connection handle (must be NULL after this call)
void network_connection_destroy(NetworkConnection* conn);

// Check if Network.framework is available at runtime
// Returns true if available, false otherwise
bool network_framework_available(void);

#endif // NETWORK_FRAMEWORK_H

