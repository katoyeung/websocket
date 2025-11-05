#include "network_framework.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>

// Only include socket headers for fallback path (when HAVE_NETWORK_FRAMEWORK is not defined)
#ifndef HAVE_NETWORK_FRAMEWORK
#include <unistd.h>
#include <sys/socket.h>
#endif

#ifdef __APPLE__
#include <AvailabilityMacros.h>
#if MAC_OS_X_VERSION_MIN_REQUIRED >= 101500
#define HAVE_NETWORK_FRAMEWORK 1
#include <Network/Network.h>
#include <dispatch/dispatch.h>
#endif
#endif

struct NetworkConnection {
#ifdef HAVE_NETWORK_FRAMEWORK
    nw_connection_t connection;
    nw_endpoint_t endpoint;
    dispatch_queue_t queue;
    network_receive_callback_t receive_callback;
    void* receive_user_data;
    bool is_started;
#endif
    int fallback_fd;  // Fallback to traditional socket if Network.framework unavailable
};

bool network_framework_available(void) {
#ifdef HAVE_NETWORK_FRAMEWORK
    return true;
#else
    return false;
#endif
}

NetworkConnection* network_connection_create(const char* host, const char* port) {
    if (!host || !port) {
        return NULL;
    }
    
    NetworkConnection* conn = calloc(1, sizeof(NetworkConnection));
    if (!conn) {
        return NULL;
    }
    
#ifdef HAVE_NETWORK_FRAMEWORK
    // Create endpoint
    conn->endpoint = nw_endpoint_create_host(host, port);
    if (!conn->endpoint) {
        free(conn);
        return NULL;
    }
    
    // Create high-priority serial queue for HFT (M4 optimization)
    dispatch_queue_attr_t attr = dispatch_queue_attr_make_with_qos_class(
        DISPATCH_QUEUE_SERIAL, QOS_CLASS_USER_INTERACTIVE, 0);
    conn->queue = dispatch_queue_create("com.hft.network", attr);
    if (!conn->queue) {
        nw_release(conn->endpoint);
        free(conn);
        return NULL;
    }
    
    conn->is_started = false;
    conn->fallback_fd = -1;
#else
    // Fallback: Network.framework not available, use traditional socket
    conn->fallback_fd = -1;
#endif
    
    return conn;
}

int network_connection_configure(NetworkConnection* conn, bool disable_kernel_tcp) {
    if (!conn) {
        return -1;
    }
    
#ifdef HAVE_NETWORK_FRAMEWORK
    // Create connection parameters for secure TCP
    nw_parameters_t parameters = nw_parameters_create_secure_tcp(
        NW_PARAMETERS_DEFAULT_CONFIGURATION,
        NW_PARAMETERS_DEFAULT_CONFIGURATION
    );
    
    if (!parameters) {
        return -1;
    }
    
    // M4 OPTIMIZATION: Network.framework uses user-space networking by default
    // No additional configuration needed - Network.framework handles optimization automatically
    (void)disable_kernel_tcp;  // Parameter kept for API compatibility but not used
    
    // Create connection with endpoint and parameters
    conn->connection = nw_connection_create(conn->endpoint, parameters);
    if (!conn->connection) {
        nw_release(parameters);
        return -1;
    }
    
    // Set high-priority queue for connection (M4 optimization)
    nw_connection_set_queue(conn->connection, conn->queue);
    
    nw_release(parameters);
    return 0;
#else
    // Fallback: configuration not needed for traditional socket
    (void)disable_kernel_tcp;
    return 0;
#endif
}

int network_connection_set_receive_callback(NetworkConnection* conn, 
                                             network_receive_callback_t callback, 
                                             void* user_data) {
    if (!conn) {
        return -1;
    }
    
#ifdef HAVE_NETWORK_FRAMEWORK
    conn->receive_callback = callback;
    conn->receive_user_data = user_data;
    // Receive handler will be set up in network_connection_start() when connection is ready
    return 0;
#else
    // Fallback: callback not supported for traditional socket
    (void)callback;
    (void)user_data;
    return 0;
#endif
}

// Helper function to set up receive handler (called from state handler)
static void setup_receive_handler(NetworkConnection* conn) {
#ifdef HAVE_NETWORK_FRAMEWORK
    if (!conn->connection || !conn->receive_callback) {
        return;
    }
    
    // Set up receive handler with zero-copy dispatch_data_t
    // Use 1 byte minimum, 65536 byte maximum for receive
    // nw_connection_receive takes: connection, minimum, maximum, completion_handler
    // Completion handler takes: content, context, is_complete, error
    NetworkConnection* conn_ptr = conn;  // Capture for block
    nw_connection_receive(conn->connection,
                         1,      // Minimum size
                         65536,  // Maximum size
                         ^(dispatch_data_t content, nw_content_context_t context, bool is_complete, nw_error_t error) {
                             if (error) {
                                 // Error occurred, try to continue receiving if not complete
                                 if (!is_complete) {
                                     setup_receive_handler(conn_ptr);
                                 }
                                 return;
                             }
                             
                             if (content && conn_ptr->receive_callback) {
                                 // Zero-copy access: dispatch_data_apply provides access to data
                                 dispatch_data_apply(content, ^bool(dispatch_data_t region, size_t offset, const void* buffer, size_t size) {
                                     // Capture callback and user_data
                                     network_receive_callback_t callback = conn_ptr->receive_callback;
                                     void* user_data = conn_ptr->receive_user_data;
                                     
                                     // Call user callback with zero-copy data
                                     if (buffer && size > 0 && callback) {
                                         callback(buffer, size, user_data);
                                     }
                                     return true;
                                 });
                             }
                             
                             // Continue receiving if not complete
                             if (!is_complete) {
                                 setup_receive_handler(conn_ptr);
                             }
                         });
#endif
}

int network_connection_start(NetworkConnection* conn) {
    if (!conn) {
        return -1;
    }
    
#ifdef HAVE_NETWORK_FRAMEWORK
    if (!conn->connection) {
        return -1;
    }
    
    // Set connection state handler
    nw_connection_set_state_changed_handler(conn->connection, 
        ^(nw_connection_state_t state, nw_error_t error) {
            if (state == nw_connection_state_ready) {
                // Connection ready - set up receive handler if callback is set
                setup_receive_handler(conn);
            } else if (state == nw_connection_state_failed || state == nw_connection_state_cancelled) {
                // Connection failed
            }
        });
    
    // Start connection
    nw_connection_start(conn->connection);
    conn->is_started = true;
    
    return 0;
#else
    // Fallback: start not needed for traditional socket
    return 0;
#endif
}

ssize_t network_connection_send(NetworkConnection* conn, const void* data, size_t len) {
    if (!conn || !data || len == 0) {
        return -1;
    }
    
#ifdef HAVE_NETWORK_FRAMEWORK
    if (!conn->connection || !conn->is_started) {
        return -1;
    }
    
    // Create dispatch_data_t for zero-copy send
    dispatch_data_t send_data = dispatch_data_create(data, len, conn->queue, DISPATCH_DATA_DESTRUCTOR_DEFAULT);
    if (!send_data) {
        return -1;
    }
    
    // Send data
    nw_connection_send(conn->connection, send_data, NW_CONNECTION_DEFAULT_MESSAGE_CONTEXT, true,
        ^(nw_error_t error) {
            // Send completion handler
            (void)error;
        });
    
    nw_release(send_data);
    return (ssize_t)len;
#else
    // Fallback: use traditional socket send
    if (conn->fallback_fd < 0) {
        return -1;
    }
    return send(conn->fallback_fd, data, len, 0);
#endif
}

int network_connection_get_fd(NetworkConnection* conn) {
    if (!conn) {
        return -1;
    }
    
#ifdef HAVE_NETWORK_FRAMEWORK
    // Network.framework doesn't expose traditional file descriptors
    // Return -1 to indicate not available
    return -1;
#else
    return conn->fallback_fd;
#endif
}

void network_connection_close(NetworkConnection* conn) {
    if (!conn) {
        return;
    }
    
#ifdef HAVE_NETWORK_FRAMEWORK
    if (conn->connection) {
        nw_connection_cancel(conn->connection);
        nw_release(conn->connection);
        conn->connection = NULL;
    }
    
    if (conn->endpoint) {
        nw_release(conn->endpoint);
        conn->endpoint = NULL;
    }
    
    if (conn->queue) {
        dispatch_release(conn->queue);
        conn->queue = NULL;
    }
#else
    if (conn->fallback_fd >= 0) {
        close(conn->fallback_fd);
        conn->fallback_fd = -1;
    }
#endif
}

void network_connection_destroy(NetworkConnection* conn) {
    if (!conn) {
        return;
    }
    
    network_connection_close(conn);
    free(conn);
}

