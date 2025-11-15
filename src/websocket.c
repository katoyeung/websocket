#include "websocket.h"
#include "internal.h"
#include "ringbuffer.h"
#include "io_kqueue.h"
#include "ssl.h"
#include "parser_neon.h"
#include "os_macos.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <ctype.h>
#include <sys/socket.h>
#include <sys/event.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <time.h>
#include <mach/mach_time.h>

// Forward declarations
static int websocket_send_pong(WebSocket* ws, const uint8_t* payload, size_t payload_len);
static void update_latency_sample(WebSocket* ws, uint64_t latency_ns);
static void check_health(WebSocket* ws);
static void report_metrics_if_needed(WebSocket* ws);
static void check_heartbeat(WebSocket* ws);

// PHASE 2: Observability - Logging macro helper
#define WS_LOG(ws, level, fmt, ...) \
    do { \
        if ((ws) && (ws)->log_callback) { \
            char log_buf[512]; \
            snprintf(log_buf, sizeof(log_buf), fmt, ##__VA_ARGS__); \
            (ws)->log_callback((ws), (level), log_buf, (ws)->log_user_data); \
        } \
    } while(0)

// Helper to get current time in nanoseconds
static uint64_t get_time_ns(void) {
    static mach_timebase_info_data_t timebase = {0, 0};
    static bool timebase_inited = false;
    if (!timebase_inited) {
        mach_timebase_info(&timebase);
        timebase_inited = true;
    }
    uint64_t ticks = mach_absolute_time();
    return (ticks * timebase.numer) / timebase.denom;
}

// Precomputed HTTP upgrade headers (const to avoid ARC overhead if objc interop needed)
const char* const ws_http_upgrade_template = 
    "GET %s HTTP/1.1\r\n"
    "Host: %s\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    "Sec-WebSocket-Key: %s\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    "\r\n";

struct WebSocket {
    WSState state;
    int fd;
    SSLContext* ssl_ctx;
    IOContext* io_ctx;
    
    // Ring buffers
    RingBuffer rx_ring;
    RingBuffer tx_ring;
    
    // Callbacks
    ws_on_message_t on_message;
    ws_on_error_t on_error;
    void* callback_user_data;
    void* user_data;
    
    // Connection state
    char* url;
    char host[256];    // Fixed-size buffer for hostname (supports 255-char domains)
    char path[1024];   // Fixed-size buffer for path + query parameters
    int port;
    bool use_ssl;
    bool cert_validation_disabled;
    
    // Handshake state
    char sec_websocket_key[25];  // Base64-encoded 16-byte key + null terminator
    
    // I/O socket index
    int socket_index;
    
    // Frame pool for zero-allocation parsing (HFT optimization)
    WSFrame frame_pool[16];  // Pre-allocate 16 frames (covers 99% of scenarios)
    int frame_pool_idx;      // Index for round-robin reuse
    
    // Error tracking
    uint32_t frame_parse_errors;  // Count of frame parse errors
    
    // Diagnostic counters for throughput investigation
    uint64_t ssl_bytes_read_total;      // Total bytes read from SSL
    uint64_t ssl_read_calls;            // Number of SSL read calls
    uint64_t frames_parsed_total;       // Total frames successfully parsed
    uint64_t frames_processed_total;    // Total frames processed (including errors)
    
    // PHASE 2: Observability - Metrics tracking
    WebSocketMetrics metrics;
    uint64_t metrics_last_report_ns;  // Last time metrics were reported
    uint64_t connection_start_ns;     // Connection start time (nanoseconds)
    
    // Latency tracking (for percentile calculation)
    uint64_t* latency_samples;        // Array of latency samples
    size_t latency_sample_count;       // Current number of samples
    size_t latency_sample_capacity;    // Maximum samples (for rolling window)
    size_t latency_sample_idx;        // Current index in rolling window
    
    // PHASE 2: Observability - Callbacks
    ws_on_metrics_t on_metrics;
    void* metrics_user_data;
    ws_on_health_t on_health;
    void* health_user_data;
    ws_log_callback_t log_callback;
    void* log_user_data;
    
    // PHASE 2: Observability - Health state
    WSHealthStatus current_health;
    uint64_t last_health_check_ns;
    
    // PHASE 3: Error Recovery - Reconnection state
    WSReconnectConfig reconnect_config;
    WSReconnectState reconnect_state;
    uint64_t last_reconnect_attempt_ns;
    
    // PHASE 3: Error Recovery - Heartbeat state
    WSHeartbeatConfig heartbeat_config;
    uint64_t last_ping_sent_ns;
    uint64_t last_pong_received_ns;
    
    // SSL polling optimization - track when we last got data for adaptive polling
    uint64_t last_ssl_data_time_ns;
};

// Generate WebSocket key for handshake
static void generate_websocket_key(char* key_out) {
    uint8_t random_bytes[16];
    
    // Generate random bytes
    FILE* urandom = fopen("/dev/urandom", "r");
    if (urandom) {
        fread(random_bytes, 1, 16, urandom);
        fclose(urandom);
    } else {
        // Fallback: use simple PRNG
        for (int i = 0; i < 16; i++) {
            random_bytes[i] = (uint8_t)(rand() & 0xFF);
        }
    }
    
    // Base64 encode using EVP
    EVP_ENCODE_CTX* ctx = EVP_ENCODE_CTX_new();
    if (!ctx) {
        return;
    }
    
    unsigned char encoded[32];
    int out_len = 0;
    
    EVP_EncodeInit(ctx);
    EVP_EncodeUpdate(ctx, encoded, &out_len, random_bytes, 16);
    int final_len = 0;
    EVP_EncodeFinal(ctx, encoded + out_len, &final_len);
    
    size_t total_len = out_len + final_len;
    if (total_len > 0 && total_len < 25) {
        // Remove newline if present
        if (encoded[total_len - 1] == '\n') {
            total_len--;
        }
        memcpy(key_out, encoded, total_len);
        key_out[total_len] = '\0';
    }
    
    EVP_ENCODE_CTX_free(ctx);
}

// Parse URL into components (using pre-allocated buffers to avoid dynamic allocation)
static int parse_url(const char* url, char* host_buf, size_t host_len,
                     char* path_buf, size_t path_len,
                     int* port_out, bool* use_ssl_out) {
    if (!url || !host_buf || !path_buf || !port_out || !use_ssl_out) {
        return -1;
    }
    
    *use_ssl_out = false;
    
    // Check protocol
    if (strncmp(url, "wss://", 6) == 0) {
        *use_ssl_out = true;
        url += 6;
    } else if (strncmp(url, "ws://", 5) == 0) {
        url += 5;
    } else {
        return -1;  // Invalid protocol
    }
    
    // Find host end: look for port colon first, then path slash
    const char* host_start = url;
    const char* colon = strchr(host_start, ':');
    const char* slash = strchr(host_start, '/');
    const char* question = strchr(host_start, '?');
    
    // Host ends at first of: port colon, path slash, query param, or end of string
    const char* host_end = host_start + strlen(host_start);
    if (slash && slash < host_end) host_end = slash;
    if (question && question < host_end) host_end = question;
    
    // Extract hostname (without port)
    size_t actual_host_len;
    if (colon && colon < host_end) {
        // Port is present, extract hostname up to colon
        actual_host_len = colon - host_start;
        if (actual_host_len >= host_len) {
            return -1;  // Buffer overflow
        }
        memcpy(host_buf, host_start, actual_host_len);
        host_buf[actual_host_len] = '\0';
        
        // Parse port (between colon and host_end)
        const char* port_start = colon + 1;
        size_t port_len = (host_end < port_start + 20) ? (host_end - port_start) : 20;
        char port_buf[21] = {0};
        if (port_len > 0) {
            memcpy(port_buf, port_start, port_len > 20 ? 20 : port_len);
            *port_out = atoi(port_buf);
        } else {
            *port_out = *use_ssl_out ? 443 : 80;
        }
    } else {
        // No port, extract hostname up to host_end
        actual_host_len = host_end - host_start;
        if (actual_host_len >= host_len) {
            return -1;  // Buffer overflow
        }
        memcpy(host_buf, host_start, actual_host_len);
        host_buf[actual_host_len] = '\0';
        
        // Default port
        *port_out = *use_ssl_out ? 443 : 80;
    }
    
    // Parse path (include everything after host, including query strings)
    if (*host_end == '/' || *host_end == '?') {
        size_t path_str_len = strlen(host_end);
        if (path_str_len >= path_len) {
            return -1;  // Buffer overflow
        }
        memcpy(path_buf, host_end, path_str_len);
        path_buf[path_str_len] = '\0';
    } else {
        if (path_len < 2) {
            return -1;
        }
        path_buf[0] = '/';
        path_buf[1] = '\0';
    }
    
    return 0;
}

// Perform TCP connect
static int tcp_connect(const char* host, int port) {
    struct addrinfo hints, *result, *rp;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);
    
    int gai_err = getaddrinfo(host, port_str, &hints, &result);
    if (gai_err != 0) {
        return -1;
    }
    
    int fd = -1;
    const int connect_timeout_sec = 10;  // 10 second timeout
    
    for (rp = result; rp != NULL; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd == -1) {
            continue;
        }
        
        // Set socket to non-blocking for timeout support
        int flags = fcntl(fd, F_GETFL, 0);
        if (flags == -1 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
            close(fd);
            fd = -1;
            continue;
        }
        
        // CRITICAL: Enable SO_TIMESTAMP BEFORE connect() for NIC timestamp capture
        // This must be done before connection so kernel timestamps all received packets
        int timestamp_on = 1;
        #ifdef SO_TIMESTAMPNS
        if (setsockopt(fd, SOL_SOCKET, SO_TIMESTAMPNS, &timestamp_on, sizeof(timestamp_on)) < 0) {
            // Fallback to SO_TIMESTAMP if SO_TIMESTAMPNS not available
            setsockopt(fd, SOL_SOCKET, SO_TIMESTAMP, &timestamp_on, sizeof(timestamp_on));
        }
        #else
        setsockopt(fd, SOL_SOCKET, SO_TIMESTAMP, &timestamp_on, sizeof(timestamp_on));
        #endif
        
        // Attempt connection (non-blocking)
        int connect_result = connect(fd, rp->ai_addr, rp->ai_addrlen);
        if (connect_result == 0) {
            // Connected immediately - keep non-blocking (I/O code expects non-blocking)
            break;  // Success
        }
        
        if (errno == EINPROGRESS) {
            // Connection in progress - wait for completion with timeout
            fd_set write_fds;
            FD_ZERO(&write_fds);
            FD_SET(fd, &write_fds);
            
            struct timeval timeout;
            timeout.tv_sec = connect_timeout_sec;
            timeout.tv_usec = 0;
            
            int select_result = select(fd + 1, NULL, &write_fds, NULL, &timeout);
            if (select_result > 0 && FD_ISSET(fd, &write_fds)) {
                // Check if connection succeeded
                int socket_error = 0;
                socklen_t len = sizeof(socket_error);
                if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &socket_error, &len) == 0 && socket_error == 0) {
                    // Connection successful - keep non-blocking (I/O code expects non-blocking)
                    break;  // Success
                }
            }
            // Connection failed or timed out
            close(fd);
            fd = -1;
            continue;
        }
        
        // Other error - try next address
        close(fd);
        fd = -1;
    }
    
    
    freeaddrinfo(result);
    return fd;
}

// Send HTTP upgrade request
static int send_handshake(WebSocket* ws) {
    char handshake[WS_HTTP_UPGRADE_HEADER_SIZE];
    
    // Generate WebSocket key
    generate_websocket_key(ws->sec_websocket_key);
    
    // Build handshake
    snprintf(handshake, sizeof(handshake), ws_http_upgrade_template,
             ws->path, ws->host, ws->sec_websocket_key);
    
    size_t handshake_len = strlen(handshake);
    
    // Write to tx_ring and send
    size_t written = ringbuffer_write(&ws->tx_ring, handshake, handshake_len);
    if (written != handshake_len) {
        return -1;
    }
    
    if (ws->use_ssl) {
        ssl_write(ws->ssl_ctx, &ws->tx_ring);
    } else {
        io_write(ws->io_ctx, ws->socket_index);
    }
    
    return 0;
}

// Parse HTTP response and verify handshake (single-pass FSM for HFT optimization)
// CRITICAL FIX: Use case-insensitive header matching and improved header parsing
static int parse_handshake_response(WebSocket* ws) {
    // Use read_inline to peek without consuming (in case we need more data)
    char* response_ptr;
    size_t response_len;
    ringbuffer_read_inline(&ws->rx_ring, &response_ptr, &response_len);
    
    if (response_len == 0 || !response_ptr) {
        return 1;  // Need more data
    }
    
    // Need at least "HTTP/1.1 101" to have valid response
    if (response_len < 12) {
        return 1;  // Need more data - too short
    }
    
    // Find HTTP response start (handle potential binary data before HTTP)
    const char* http_start = NULL;
    for (size_t i = 0; i < response_len && i < 100; i++) {  // Limit search to first 100 bytes
        if (response_len - i >= 12) {
            if (strncmp((char*)response_ptr + i, "HTTP/1.1", 8) == 0 ||
                strncmp((char*)response_ptr + i, "HTTP/1.0", 8) == 0) {
                http_start = (char*)response_ptr + i;
                break;
            }
        }
    }
    
    if (!http_start) {
        // No HTTP found - might be SSL handshake data or incomplete
        // Check if we have enough data that we should have seen HTTP by now
        if (response_len > 200) {
            return -1;  // Have substantial data but no HTTP - invalid
        }
        return 1;  // Need more data
    }
    
    // Now parse from http_start
    // Make a null-terminated copy for string functions
    size_t http_offset = http_start - (char*)response_ptr;
    size_t remaining = response_len - http_offset;
    char response[WS_MAX_HEADER_SIZE];
    size_t copy_len = (remaining < sizeof(response) - 1) ? remaining : sizeof(response) - 1;
    memcpy(response, http_start, copy_len);
    response[copy_len] = '\0';
    
    // Check for HTTP 101 status
    bool http_valid = false;
    bool upgrade_valid = false;
    bool connection_valid = false;
    
    // Look for "HTTP/1.1 101" or "HTTP/1.0 101"
    if (copy_len >= 12) {
        if (strncmp(response, "HTTP/1.1 101", 12) == 0 ||
            strncmp(response, "HTTP/1.0 101", 12) == 0) {
            http_valid = true;
        }
    }
    
    if (!http_valid) {
        // HTTP status not 101 - handshake failed
        return -1;
    }
    
    // Case-insensitive search for headers
    char* response_lower = malloc(copy_len + 1);
    if (!response_lower) return -1;
    for (size_t i = 0; i < copy_len; i++) {
        response_lower[i] = (char)tolower((unsigned char)response[i]);
    }
    response_lower[copy_len] = '\0';
    
    // Look for "upgrade: websocket" (case-insensitive)
    if (strstr(response_lower, "upgrade: websocket") != NULL ||
        strstr(response_lower, "upgrade:websocket") != NULL) {
        upgrade_valid = true;
    }
    
    // Look for "connection: upgrade" (case-insensitive)
    if (strstr(response_lower, "connection: upgrade") != NULL ||
        strstr(response_lower, "connection:upgrade") != NULL) {
        connection_valid = true;
    }
    
    free(response_lower);
    
    // If all valid, consume the response from ringbuffer
    if (http_valid && upgrade_valid && connection_valid) {
        // Consume at least the HTTP response (up to first blank line + some)
        // Find end of headers (double CRLF)
        const char* header_end = strstr((char*)http_start, "\r\n\r\n");
        if (header_end) {
            size_t header_len = (header_end - http_start) + 4;  // Include \r\n\r\n
            // Consume from http_start to end of headers
            size_t consumed = ringbuffer_read(&ws->rx_ring, NULL, http_offset);  // Skip data before HTTP
            if (consumed == http_offset) {
                // Now consume the HTTP response headers
                char dummy[4096];
                ringbuffer_read(&ws->rx_ring, dummy, 
                    (header_len < sizeof(dummy)) ? header_len : sizeof(dummy));
            }
        } else {
            // No \r\n\r\n found yet - but we validated, so consume what we checked
            // Actually, if we validated, the headers should be complete
            // For safety, don't consume if we can't find header end
        }
        return 0;  // Success
    }
    
    // Need more data to complete parsing
    return 1;
}

// Get frame from pool (lock-free for single-threaded context)
static inline WSFrame* get_frame_from_pool(WebSocket* ws) {
    ws->frame_pool_idx = (ws->frame_pool_idx + 1) % 16;
    WSFrame* frame = &ws->frame_pool[ws->frame_pool_idx];
    // Only reset fields that change per frame (skip payload pointer)
    memset(frame, 0, offsetof(WSFrame, payload));
    frame->payload = NULL;
    return frame;
}

// Process received WebSocket frames (fixed: better bounds checking and error recovery)
static void process_frames(WebSocket* ws) {
    // Read available data from rx_ring (safety check length)
    char* data;
    size_t len;
    ringbuffer_read_inline(&ws->rx_ring, &data, &len);
    
    if (len == 0 || !data) {  // Avoid null pointer access
        return;
    }
    
    // Parse frames
    size_t offset = 0;
    size_t total_consumed = 0;
    int parse_attempts = 0;
    const int max_parse_attempts = 1000;  // Fixed limit to prevent infinite loops
    
    while (offset < len && parse_attempts < max_parse_attempts) {
        parse_attempts++;
        WSFrame* frame = get_frame_from_pool(ws);  // Use pooled frame instead of stack allocation
        int result = neon_parse_ws_frame((const uint8_t*)(data + offset), len - offset, frame);
        
        if (result == 1) {
            // Need more data - keep what we have in buffer
            break;
        }
        
        if (result != 0) {
            // Parse error - skip one byte and try again (to recover from corruption)
            ws->frame_parse_errors++;
            ws->metrics.errors_total++;  // PHASE 2: Track error count
            ws->frames_processed_total++;  // Track processed (including errors)
            WS_LOG(ws, WS_LOG_WARN, "Frame parse error at offset %zu", offset);
            offset++;
            continue;
        }
        
        // Validate frame size (avoid illegal length)
        size_t frame_size = frame->header_size + frame->payload_len;
        if (frame_size == 0 || frame_size > len - offset) {
            // Invalid frame size - skip one byte and try again
            ws->frame_parse_errors++;
            ws->frames_processed_total++;  // Track processed (including errors)
            offset++;
            continue;
        }
        
        // Frame successfully parsed - increment counters
        ws->frames_parsed_total++;
        ws->frames_processed_total++;
        
        // Assign payload pointer to point to payload in ringbuffer
        frame->payload = (uint8_t*)(data + offset + frame->header_size);
        
        // Process frame
        if (frame->opcode == WS_OPCODE_TEXT || frame->opcode == WS_OPCODE_BINARY) {
            // Server-to-client frames should NOT be masked per RFC 6455
            // But handle both cases for robustness
            uint8_t* payload = (uint8_t*)frame->payload;
            if (frame->mask) {
                // Unmask if present (shouldn't happen for server frames)
                for (size_t i = 0; i < frame->payload_len; i++) {
                    payload[i] ^= ((uint8_t*)(&frame->masking_key))[i % 4];
                }
            }
            
            // PHASE 2: Update metrics for received message
            ws->metrics.messages_received++;
            ws->metrics.bytes_received += frame->payload_len;
            
            // Calculate latency if NIC timestamp is available
            uint64_t nic_timestamp_ns = websocket_get_last_nic_timestamp_ns(ws);
            if (nic_timestamp_ns > 0) {
                uint64_t now_ns = get_time_ns();
                uint64_t latency_ns = (now_ns > nic_timestamp_ns) ? (now_ns - nic_timestamp_ns) : 0;
                update_latency_sample(ws, latency_ns);
            }
            
            // Call callback directly with payload pointer
            if (ws->on_message) {
                ws->on_message(ws, payload, frame->payload_len, ws->callback_user_data);
            }
        } else if (frame->opcode == WS_OPCODE_PING) {
            // CRITICAL: Binance sends ping every 20 seconds
            // MUST respond with pong within 1 minute or connection will be closed
            // RFC 6455: Pong frame must contain the same payload as the ping frame
            uint8_t* ping_payload = (uint8_t*)frame->payload;
            size_t ping_len = frame->payload_len;
            
            // Unmask ping payload if masked (shouldn't happen for server frames)
            if (frame->mask && ping_payload) {
                for (size_t i = 0; i < ping_len; i++) {
                    ping_payload[i] ^= ((uint8_t*)(&frame->masking_key))[i % 4];
                }
            }
            
            // Send pong frame with same payload (RFC 6455 requirement)
            // Pong frames must be masked from client to server
            int pong_result = websocket_send_pong(ws, ping_payload, ping_len);
            if (pong_result != 0) {
                // Failed to send pong - this may cause disconnection
                WS_LOG(ws, WS_LOG_ERROR, "Failed to send PONG frame in response to PING (error=%d)", pong_result);
            }
        } else if (frame->opcode == WS_OPCODE_PONG) {
            // PHASE 3: Record pong receipt for heartbeat monitoring
            ws->last_pong_received_ns = get_time_ns();
            // Pong response received - no action needed, just acknowledge
            // Binance documentation says unsolicited pongs are allowed
        } else if (frame->opcode == WS_OPCODE_CLOSE) {
            ws->state = WS_STATE_CLOSING;
        }
        
        offset += frame_size;
        total_consumed += frame_size;
    }
    
    // Optimize: Use ringbuffer_advance_read to advance pointer, avoiding manual calculation
    if (total_consumed > 0) {
        // Manually advance read pointer using atomic operations (SPSC optimization)
        size_t rp = __atomic_load_n(&ws->rx_ring.read_ptr, __ATOMIC_RELAXED);
        size_t new_rp = (rp + total_consumed) % ws->rx_ring.size;
        __atomic_store_n(&ws->rx_ring.read_ptr, new_rp, __ATOMIC_RELEASE);
    }
}

WebSocket* websocket_create(void) {
    WebSocket* ws = calloc(1, sizeof(WebSocket));
    if (!ws) {
        return NULL;
    }
    
    ws->state = WS_STATE_CLOSED;  // Initial state changed to closed to avoid confusion
    ws->fd = -1;
    ws->socket_index = -1;
    ws->ssl_ctx = NULL;
    ws->io_ctx = NULL;
    ws->frame_pool_idx = 0;  // Initialize frame pool index
    ws->frame_parse_errors = 0;  // Initialize error counter
    
    // PHASE 2: Initialize observability fields
    memset(&ws->metrics, 0, sizeof(WebSocketMetrics));
    ws->metrics_last_report_ns = 0;
    ws->connection_start_ns = 0;
    ws->latency_samples = NULL;
    ws->latency_sample_count = 0;
    ws->latency_sample_capacity = 1000;  // Store up to 1000 latency samples
    ws->latency_sample_idx = 0;
    ws->on_metrics = NULL;
    ws->metrics_user_data = NULL;
    ws->on_health = NULL;
    ws->health_user_data = NULL;
    ws->log_callback = NULL;
    ws->log_user_data = NULL;
    ws->current_health = WS_HEALTH_OK;
    ws->last_health_check_ns = 0;
    
    // PHASE 3: Initialize error recovery
    memset(&ws->reconnect_config, 0, sizeof(WSReconnectConfig));
    ws->reconnect_config.initial_backoff_ms = 100;
    ws->reconnect_config.max_backoff_ms = 30000;
    ws->reconnect_config.backoff_multiplier = 2.0;
    ws->reconnect_config.reset_backoff_on_success = true;
    memset(&ws->reconnect_state, 0, sizeof(WSReconnectState));
    ws->last_reconnect_attempt_ns = 0;
    ws->reconnect_state.next_backoff_ms = ws->reconnect_config.initial_backoff_ms;
    
    // PHASE 3: Initialize heartbeat
    memset(&ws->heartbeat_config, 0, sizeof(WSHeartbeatConfig));
    ws->last_ping_sent_ns = 0;
    ws->last_pong_received_ns = 0;
    
    // Allocate latency samples array
    ws->latency_samples = calloc(ws->latency_sample_capacity, sizeof(uint64_t));
    if (!ws->latency_samples) {
        // If allocation fails, disable latency tracking but continue
        ws->latency_sample_capacity = 0;
    }
    
    return ws;
}

void websocket_destroy(WebSocket* ws) {
    if (!ws) {
        return;
    }
    
    // PRIORITY 1 FIX: Ensure clean shutdown sequence
    // Close connection if still active (SSL cleanup will handle final shutdown)
    if (ws->state == WS_STATE_CONNECTED || ws->state == WS_STATE_CONNECTING) {
        websocket_close(ws);
        // Don't wait for graceful shutdown here - SSL cleanup will handle it
        // Waiting can cause crashes if websocket_process accesses partially-destroyed state
    }
    
    // Explicit cleanup order matters - SSL first, then I/O, then buffers
    if (ws->ssl_ctx) {
        ssl_cleanup(ws->ssl_ctx);
        ws->ssl_ctx = NULL;
    }
    
    if (ws->io_ctx) {
        io_cleanup(ws->io_ctx);
        free(ws->io_ctx);
        ws->io_ctx = NULL;
    }
    
    ringbuffer_cleanup(&ws->rx_ring);
    ringbuffer_cleanup(&ws->tx_ring);
    
    // PRIORITY 2: Cleanup observability resources
    if (ws->latency_samples) {
        free(ws->latency_samples);
        ws->latency_samples = NULL;
        ws->latency_sample_count = 0;
        ws->latency_sample_capacity = 0;
    }
    
    if (ws->url) {
        free(ws->url);
        ws->url = NULL;
    }
    
    // host and path are now stack buffers, no need to free
    free(ws);
    
    // Note: Memory reclamation happens automatically - no delay needed here
    // The VM_DEALLOCATE in ssl_cleanup() handles force memory release
}

void websocket_set_on_message(WebSocket* ws, ws_on_message_t callback, void* user_data) {
    if (ws) {
        ws->on_message = callback;
        ws->callback_user_data = user_data;
    }
}

void websocket_set_on_error(WebSocket* ws, ws_on_error_t callback, void* user_data) {
    if (ws) {
        ws->on_error = callback;
        ws->callback_user_data = user_data;
    }
}

int websocket_connect(WebSocket* ws, const char* url, bool disable_cert_validation) {
    if (!ws || !url) {
        return -1;
    }
    
    // CRITICAL FIX: Clean up existing resources ONLY if reconnecting
    // On first connect (WS_STATE_CLOSED), skip cleanup to avoid breaking connection
    if (ws->state == WS_STATE_CONNECTED || ws->state == WS_STATE_CONNECTING) {
        // Close existing connection first (this will clean up SSL, I/O, and close socket)
        websocket_close(ws);
        // websocket_close() sets state to CLOSED, but doesn't clean up ring buffers
        // So we need to clean them up here to prevent memory leak on reconnection
        if (ws->rx_ring.buf) {
            ringbuffer_cleanup(&ws->rx_ring);
        }
        if (ws->tx_ring.buf) {
            ringbuffer_cleanup(&ws->tx_ring);
        }
        // Clean up I/O context and SSL context from previous connection
        if (ws->io_ctx) {
            io_cleanup(ws->io_ctx);
            free(ws->io_ctx);
            ws->io_ctx = NULL;
        }
        if (ws->ssl_ctx) {
            ssl_cleanup(ws->ssl_ctx);
            ws->ssl_ctx = NULL;
        }
        if (ws->fd >= 0) {
            close(ws->fd);
            ws->fd = -1;
        }
        if (ws->url) {
            free(ws->url);
            ws->url = NULL;
        }
        // Reset socket_index to prevent stale references
        ws->socket_index = -1;
    }
    
    ws->url = strdup(url);
    ws->cert_validation_disabled = disable_cert_validation;
    
    // Parse URL (using pre-allocated buffers)
    if (parse_url(url, ws->host, sizeof(ws->host), ws->path, sizeof(ws->path), &ws->port, &ws->use_ssl) != 0) {
        free(ws->url);
        ws->url = NULL;
        return -1;
    }
    
    // Initialize ring buffers
    if (ringbuffer_init(&ws->rx_ring) != 0 || ringbuffer_init(&ws->tx_ring) != 0) {
        goto cleanup;
    }
    
    // Initialize I/O context
    ws->io_ctx = malloc(sizeof(IOContext));
    if (!ws->io_ctx || io_init(ws->io_ctx) != 0) {
        goto cleanup;
    }
    
    // Connect TCP
    ws->fd = tcp_connect(ws->host, ws->port);
    if (ws->fd < 0) {
        goto cleanup;
    }
    
    // SO_TIMESTAMP is now enabled in tcp_connect() BEFORE connect()
    // This ensures kernel timestamps all received packets from the start
    // Verify it's still enabled (should be, but check for safety)
    int timestamp_value = 0;
    socklen_t optlen = sizeof(timestamp_value);
    #ifdef SO_TIMESTAMPNS
    if (getsockopt(ws->fd, SOL_SOCKET, SO_TIMESTAMPNS, &timestamp_value, &optlen) < 0 || timestamp_value == 0) {
        // Not enabled, try to enable it
        timestamp_value = 1;
        if (setsockopt(ws->fd, SOL_SOCKET, SO_TIMESTAMPNS, &timestamp_value, sizeof(timestamp_value)) < 0) {
            // Fallback to SO_TIMESTAMP
            setsockopt(ws->fd, SOL_SOCKET, SO_TIMESTAMP, &timestamp_value, sizeof(timestamp_value));
        }
    }
    #else
    if (getsockopt(ws->fd, SOL_SOCKET, SO_TIMESTAMP, &timestamp_value, &optlen) < 0 || timestamp_value == 0) {
        timestamp_value = 1;
        setsockopt(ws->fd, SOL_SOCKET, SO_TIMESTAMP, &timestamp_value, sizeof(timestamp_value));
    }
    #endif
    
    // Initialize SSL if needed
    if (ws->use_ssl) {
        if (ssl_init(&ws->ssl_ctx, disable_cert_validation) != 0) {
            goto cleanup;
        }

        if (ssl_connect(ws->ssl_ctx, ws->fd, ws->host) != 0) {
            ssl_cleanup(ws->ssl_ctx);
            ws->ssl_ctx = NULL;
            goto cleanup;
        }

        // Set user_data in SSL context for diagnostic tracking
        ssl_set_user_data(ws->ssl_ctx, ws);
    }
    
    // Add socket to I/O context
    ws->socket_index = io_add_socket(ws->io_ctx, ws->fd, &ws->rx_ring, &ws->tx_ring, ws);
    if (ws->socket_index < 0) {
        if (ws->use_ssl) {
            ssl_cleanup(ws->ssl_ctx);
            ws->ssl_ctx = NULL;
        }
        goto cleanup;
    }
    
    // Send handshake
    if (send_handshake(ws) != 0) {
        goto cleanup;
    }
    
    ws->state = WS_STATE_CONNECTING;
    return 0;

cleanup:
    // Clean up resources on error
    if (ws->fd >= 0) {
        close(ws->fd);
        ws->fd = -1;
    }
    if (ws->ssl_ctx) {
        ssl_cleanup(ws->ssl_ctx);
        ws->ssl_ctx = NULL;
    }
    if (ws->io_ctx) {
        io_cleanup(ws->io_ctx);
        free(ws->io_ctx);
        ws->io_ctx = NULL;
    }
    if (ws->url) {
        free(ws->url);
        ws->url = NULL;
    }
    ringbuffer_cleanup(&ws->rx_ring);
    ringbuffer_cleanup(&ws->tx_ring);
    return -1;
}

// Send pong frame (internal helper for ping response)
// CRITICAL: RFC 6455 requires client-to-server frames to be MASKED
static int websocket_send_pong(WebSocket* ws, const uint8_t* payload, size_t payload_len) {
    if (!ws || ws->state != WS_STATE_CONNECTED) {
        return -1;
    }
    
    // Generate random masking key (required for client-to-server frames)
    uint32_t masking_key;
    // Use /dev/urandom for portability (arc4random_buf may not be available)
    FILE* urandom = fopen("/dev/urandom", "r");
    if (urandom) {
        fread(&masking_key, 1, sizeof(masking_key), urandom);
        fclose(urandom);
    } else {
        // Fallback (less secure but better than nothing)
        masking_key = (uint32_t)rand() ^ ((uint32_t)rand() << 16);
    }
    
    // Build WebSocket pong frame with masking
    uint8_t frame_header[14];
    size_t header_size = 2;
    
    frame_header[0] = 0x80 | WS_OPCODE_PONG;  // FIN + PONG opcode
    frame_header[1] = 0x80;  // MASK bit set (required for client-to-server)
    
    if (payload_len < 126) {
        frame_header[1] |= payload_len;
        frame_header[2] = ((uint8_t*)&masking_key)[0];
        frame_header[3] = ((uint8_t*)&masking_key)[1];
        frame_header[4] = ((uint8_t*)&masking_key)[2];
        frame_header[5] = ((uint8_t*)&masking_key)[3];
        header_size = 6;
    } else if (payload_len < 65536) {
        frame_header[1] |= 126;
        uint16_t len16 = htons((uint16_t)payload_len);
        memcpy(frame_header + 2, &len16, 2);
        frame_header[4] = ((uint8_t*)&masking_key)[0];
        frame_header[5] = ((uint8_t*)&masking_key)[1];
        frame_header[6] = ((uint8_t*)&masking_key)[2];
        frame_header[7] = ((uint8_t*)&masking_key)[3];
        header_size = 8;
    } else {
        frame_header[1] |= 127;
        uint64_t len64 = __builtin_bswap64(payload_len);
        memcpy(frame_header + 2, &len64, 8);
        frame_header[10] = ((uint8_t*)&masking_key)[0];
        frame_header[11] = ((uint8_t*)&masking_key)[1];
        frame_header[12] = ((uint8_t*)&masking_key)[2];
        frame_header[13] = ((uint8_t*)&masking_key)[3];
        header_size = 14;
    }
    
    // Write frame header to tx_ring
    size_t written = ringbuffer_write(&ws->tx_ring, frame_header, header_size);
    if (written != header_size) {
        return -1;
    }
    
    // Mask and write payload (RFC 6455: mask payload with rotating key)
    if (payload && payload_len > 0) {
        uint8_t* masked_payload = malloc(payload_len);
        if (!masked_payload) {
            return -1;
        }
        for (size_t i = 0; i < payload_len; i++) {
            masked_payload[i] = payload[i] ^ ((uint8_t*)&masking_key)[i % 4];
        }
        written = ringbuffer_write(&ws->tx_ring, masked_payload, payload_len);
        free(masked_payload);
        if (written != payload_len) {
            return -1;
        }
    }
    
    // Send via SSL or direct I/O
    if (ws->use_ssl) {
        ssl_write(ws->ssl_ctx, &ws->tx_ring);
    } else {
        io_write(ws->io_ctx, ws->socket_index);
    }
    
    return 0;
}

int websocket_send(WebSocket* ws, const uint8_t* data, size_t len, bool is_text) {
    if (!ws || !data || len == 0 || ws->state != WS_STATE_CONNECTED) {
        return -1;
    }
    
    // CRITICAL: RFC 6455 requires client-to-server frames to be MASKED
    // Generate random masking key (required for client-to-server frames)
    uint32_t masking_key;
    FILE* urandom = fopen("/dev/urandom", "r");
    if (urandom) {
        fread(&masking_key, 1, sizeof(masking_key), urandom);
        fclose(urandom);
    } else {
        // Fallback (less secure but better than nothing)
        masking_key = (uint32_t)rand() ^ ((uint32_t)rand() << 16);
    }
    
    // Mask the payload
    uint8_t* masked_payload = (uint8_t*)malloc(len);
    if (!masked_payload) {
        return -1;
    }
    for (size_t i = 0; i < len; ++i) {
        masked_payload[i] = data[i] ^ ((uint8_t*)&masking_key)[i % 4];
    }
    
    // Build WebSocket frame with masking
    uint8_t frame_header[14];
    size_t header_size = 2;
    
    frame_header[0] = 0x80 | (is_text ? WS_OPCODE_TEXT : WS_OPCODE_BINARY);
    frame_header[1] = 0x80;  // MASK bit set (required for client-to-server)
    
    if (len < 126) {
        frame_header[1] |= len;
        frame_header[2] = ((uint8_t*)&masking_key)[0];
        frame_header[3] = ((uint8_t*)&masking_key)[1];
        frame_header[4] = ((uint8_t*)&masking_key)[2];
        frame_header[5] = ((uint8_t*)&masking_key)[3];
        header_size = 6;
    } else if (len < 65536) {
        frame_header[1] |= 126;
        uint16_t len16 = htons((uint16_t)len);
        memcpy(frame_header + 2, &len16, 2);
        frame_header[4] = ((uint8_t*)&masking_key)[0];
        frame_header[5] = ((uint8_t*)&masking_key)[1];
        frame_header[6] = ((uint8_t*)&masking_key)[2];
        frame_header[7] = ((uint8_t*)&masking_key)[3];
        header_size = 8;
    } else {
        frame_header[1] |= 127;
        uint64_t len64 = __builtin_bswap64(len);
        memcpy(frame_header + 2, &len64, 8);
        frame_header[10] = ((uint8_t*)&masking_key)[0];
        frame_header[11] = ((uint8_t*)&masking_key)[1];
        frame_header[12] = ((uint8_t*)&masking_key)[2];
        frame_header[13] = ((uint8_t*)&masking_key)[3];
        header_size = 14;
    }
    
    // Write frame header to tx_ring
    size_t written = ringbuffer_write(&ws->tx_ring, frame_header, header_size);
    if (written != header_size) {
        free(masked_payload);
        return -1;
    }
    
    // Write masked payload to tx_ring
    written = ringbuffer_write(&ws->tx_ring, masked_payload, len);
    free(masked_payload);
    if (written != len) {
        return -1;
    }
    
    // PHASE 2: Update metrics for sent message
    ws->metrics.messages_sent++;
    ws->metrics.bytes_sent += len;
    
    // Send via SSL or direct I/O
    if (ws->use_ssl) {
        ssl_write(ws->ssl_ctx, &ws->tx_ring);
    } else {
        io_write(ws->io_ctx, ws->socket_index);
    }
    
    return 0;
}

int websocket_close(WebSocket* ws) {
    if (!ws || ws->state == WS_STATE_CLOSED) {
        return 0;
    }
    
    if (ws->fd >= 0) {
        if (ws->socket_index >= 0) {
            io_remove_socket(ws->io_ctx, ws->fd);
        }
        // CRITICAL: Shutdown socket properly for clean SSL/TLS closure
        shutdown(ws->fd, SHUT_RDWR);
        close(ws->fd);
        ws->fd = -1;
    }
    
    ws->state = WS_STATE_CLOSED;
    return 0;
}

int websocket_process(WebSocket* ws) {
    if (!ws) {
        return -1;
    }
    
    struct kevent events[IO_MAX_SOCKETS];
    // CRITICAL: Use 0 timeout for maximum responsiveness - kqueue returns immediately
    // When kqueue reports readable, we drain ultra-aggressively (50k+ SSL reads)
    // Between events, we always read to catch SecureTransport's buffered data
    // Zero timeout ensures we never block and can process immediately
    int timeout_us = ws->use_ssl ? 0 : 10;  // 0 for SSL (non-blocking), 10μs for non-SSL
    int event_count = io_poll(ws->io_ctx, events, IO_MAX_SOCKETS, timeout_us);
    
    if (event_count < 0) {
        WS_LOG(ws, WS_LOG_ERROR, "websocket_process: io_poll() returned error: %d", event_count);
        return -1;
    }
    
    for (int i = 0; i < event_count; i++) {
        int socket_idx = (int)(intptr_t)events[i].udata;
        
        // Check for connection closure (EOF or error)
        if (events[i].flags & EV_EOF || events[i].flags & EV_ERROR) {
            // Connection closed or error
            WS_LOG(ws, WS_LOG_WARN, "websocket_process: Connection closed/error: flags=0x%x", events[i].flags);
            if (ws->state == WS_STATE_CONNECTED || ws->state == WS_STATE_CONNECTING) {
                ws->state = WS_STATE_CLOSED;
                // Connection closed - callback will handle reconnect if needed
                if (ws->on_error) {
                    ws->on_error(ws, -1, "Connection closed by peer", ws->callback_user_data);
                }
            }
            continue;
        }
        
        if (events[i].filter == EVFILT_READ) {
            // Read data
            // For non-SSL, io_read() captures NIC timestamp
            // For SSL, SecureTransport reads internally, so timestamp capture is limited
            if (ws->use_ssl) {
                // CRITICAL: When kqueue reports socket is readable, drain SSL ULTRA-aggressively
                // SecureTransport buffers data internally, so we need to read many times
                // Strategy: Read continuously until we get no data for multiple attempts
                
                // CRITICAL: Process frames BEFORE draining to free ring buffer space
                // This ensures we have maximum space available for SSL reads
                process_frames(ws);
                
                int ssl_drain_attempts = 0;
                const int max_ssl_drain = 50000;  // Ultra-aggressive: 50,000 drain attempts
                int consecutive_would_block = 0;
                const int max_consecutive_would_block = 500;  // Stop after 500 consecutive would-blocks
                bool made_progress = false;
                
                // CRITICAL: Process frames once before starting drain to free initial space
                process_frames(ws);
                
                // CRITICAL: kqueue already told us socket is readable (EVFILT_READ event)
                // Trust kqueue and drain aggressively - SecureTransport may have buffered data
                while (ssl_drain_attempts < max_ssl_drain && ws->state == WS_STATE_CONNECTED) {
                    ssl_drain_attempts++;
                    ssize_t ssl_result = ssl_read(ws->ssl_ctx, &ws->rx_ring);
                    
                    // Update diagnostic counters
                    if (ws->ssl_ctx) {
                        ws->ssl_bytes_read_total = ssl_get_bytes_read(ws->ssl_ctx);
                        ws->ssl_read_calls = ssl_get_read_calls(ws->ssl_ctx);
                    }
                    
                    if (ssl_result > 0) {
                        // Got data - reset would-block counter and process frames immediately
                        made_progress = true;
                        consecutive_would_block = 0;  // Reset counter
                        
                        // Process frames immediately to free buffer space
                        process_frames(ws);
                        
                        // Drain all frames aggressively to free maximum buffer space
                        int frame_iterations = 0;
                        while (frame_iterations < 500 && ws->state == WS_STATE_CONNECTED) {
                            size_t before = ws->rx_ring.read_ptr;
                            process_frames(ws);
                            size_t after = ws->rx_ring.read_ptr;
                            if (after == before) {
                                break;
                            }
                            frame_iterations++;
                        }
                        
                        // Continue draining SSL - we're getting data
                        continue;
                    } else if (ssl_result == -2) {
                        // Ring buffer full - process frames to free space
                        made_progress = true;
                        process_frames(ws);
                        
                        // CRITICAL: Drain ALL frames aggressively before continuing SSL reads
                        // This frees maximum buffer space for SecureTransport
                        int frame_iterations = 0;
                        while (frame_iterations < 1000 && ws->state == WS_STATE_CONNECTED) {
                            size_t before = ws->rx_ring.read_ptr;
                            process_frames(ws);
                            size_t after = ws->rx_ring.read_ptr;
                            if (after == before) {
                                break;
                            }
                            frame_iterations++;
                        }
                        
                        // Continue draining after freeing space
                        continue;
                    } else if (ssl_result == 0) {
                        // Would-block - track consecutive would-blocks
                        consecutive_would_block++;
                        
                        // CRITICAL: Continue draining aggressively even after would-block
                        // SecureTransport may buffer data and make it available later
                        // Process frames before continuing to free buffer space
                        process_frames(ws);
                        
                        // Only stop after many consecutive would-blocks
                        // CRITICAL: Continue draining even after would-block if we made progress
                        // SecureTransport may buffer data and make it available later
                        if (consecutive_would_block < max_consecutive_would_block) {
                            // If we made progress, reset counter and keep trying longer
                            if (made_progress) {
                                // Reset counter to allow more attempts after progress
                                if (consecutive_would_block < 200) {
                                    consecutive_would_block = 0;  // Reset, keep trying aggressively
                                }
                            }
                            continue;  // Keep trying - SecureTransport may have more data
                        }
                        
                        // Too many consecutive would-blocks - likely no more data
                        // Process any remaining frames and stop
                        process_frames(ws);
                        break;
                    } else {
                        // Error - stop draining
                        WS_LOG(ws, WS_LOG_ERROR, "websocket_process: SSL read error: %zd", ssl_result);
                        break;
                    }
                }
                
                // CRITICAL: After aggressive draining, process any remaining frames
                // Level-triggered events will fire again if socket is still readable
                // Process frames one more time to catch anything that arrived during draining
                process_frames(ws);
            } else {
                io_read(ws->io_ctx, socket_idx);
            }
            
            // Process handshake if connecting
            if (ws->state == WS_STATE_CONNECTING) {
                // For SSL, complete handshake first before parsing WebSocket handshake
                // CRITICAL: SSL handshake must complete BEFORE we can read HTTP response
                if (ws->use_ssl) {
                    // Drive SSL handshake by reading/writing - loop until complete
                    // SecureTransport handshake is asynchronous and needs multiple I/O cycles
                    int ssl_handshake_iterations = 0;
                    const int max_ssl_iterations = 50;  // Increased from 20 to 50 for more reliable handshake
                    bool ssl_made_progress = false;
                    
                    while (ssl_handshake_iterations < max_ssl_iterations) {
                        ssize_t ssl_write_result = ssl_write(ws->ssl_ctx, &ws->tx_ring);
                        ssize_t ssl_read_result = ssl_read(ws->ssl_ctx, &ws->rx_ring);
                        
                        ssl_handshake_iterations++;
                        
                        // Check if handshake is complete (for OpenSSL)
                        if (ssl_is_handshake_complete(ws->ssl_ctx)) {
                            ssl_made_progress = true;
                            break;  // Handshake complete
                        }
                        
                        // If we got data or wrote data, handshake is progressing
                        if (ssl_read_result > 0 || ssl_write_result > 0) {
                            ssl_made_progress = true;
                            // Continue one more iteration to complete handshake
                            continue;
                        }
                        
                        // If both return 0 (no progress), handshake might be waiting for more I/O
                        // or already complete (for SecureTransport, which doesn't have completion check)
                        if (ssl_read_result == 0 && ssl_write_result == 0) {
                            // No progress this iteration
                            // For SecureTransport, assume handshake can proceed if we've made progress before
                            if (ssl_made_progress || ssl_handshake_iterations >= 10) {
                                break;  // Assume handshake will complete via subsequent I/O
                            }
                            // Wait a bit before next iteration
                            usleep(10000);  // 10ms
                            continue;
                        }
                        
                        // If error, don't fail immediately - might be temporary
                        if (ssl_read_result < 0 || ssl_write_result < 0) {
                            // SSL error - but don't close immediately
                            // SecureTransport may return errors during handshake that are recoverable
                            if (ssl_handshake_iterations >= 20) {
                                // Too many errors - likely real failure
                                break;
                            }
                            // Wait before retry
                            usleep(10000);  // 10ms
                            continue;
                        }
                    }
                }
                
                // Try to parse HTTP handshake if we have data
                // CRITICAL: Must actively drain SSL to get HTTP response into ringbuffer
                // For SSL, we need to keep reading until HTTP response arrives
                // Also ensure handshake request has been sent via SSL
                if (ws->use_ssl) {
                    // First, ensure handshake request is sent via SSL
                    ssl_write(ws->ssl_ctx, &ws->tx_ring);
                    
                    // Aggressively read SSL to get HTTP response
                    // SecureTransport may buffer HTTP response in SSL layer
                    for (int ssl_try = 0; ssl_try < 20; ssl_try++) {
                        ssize_t ssl_result = ssl_read(ws->ssl_ctx, &ws->rx_ring);
                        if (ssl_result <= 0) {
                            // No more data available right now
                            // But still try to parse what we have
                            break;
                        }
                        // Got data - continue reading to get full HTTP response
                    }
                }
                
                char* test_data;
                size_t test_len;
                ringbuffer_read_inline(&ws->rx_ring, &test_data, &test_len);
                
                if (test_len > 0) {
                    int result = parse_handshake_response(ws);
                    if (result == 0) {
                        // Handshake complete!
                        ws->state = WS_STATE_CONNECTED;
                        
                        // PHASE 2: Record connection start time for metrics
                        if (ws->connection_start_ns == 0) {
                            ws->connection_start_ns = get_time_ns();
                            WS_LOG(ws, WS_LOG_INFO, "WebSocket connected to %s:%d", ws->host, ws->port);
                        }
                        
                        // PHASE 3: Reset reconnection state on successful connection
                        if (ws->reconnect_config.reset_backoff_on_success) {
                            ws->reconnect_state.reconnect_attempts = 0;
                            ws->reconnect_state.is_reconnecting = false;
                            ws->reconnect_state.next_backoff_ms = ws->reconnect_config.initial_backoff_ms;
                        }
                        
                        // CRITICAL FIX: Re-register socket with kqueue after connection is established
                        // This ensures kqueue properly detects readable events after SSL handshake completes
                        // SecureTransport may change socket state during handshake, so re-registration ensures
                        // kqueue is properly monitoring the socket for new data
                        if (ws->socket_index >= 0 && ws->io_ctx) {
                            struct kevent ev;
                            EV_SET(&ev, ws->fd, EVFILT_READ, EV_ADD | EV_CLEAR | EV_ENABLE, 0, 0, (void*)(intptr_t)ws->socket_index);
                            if (kevent(ws->io_ctx->kq, &ev, 1, NULL, 0, NULL) == 0) {
                                WS_LOG(ws, WS_LOG_INFO, "Re-registered socket with kqueue after connection");
                            } else {
                                WS_LOG(ws, WS_LOG_WARN, "Failed to re-register socket with kqueue: %s", strerror(errno));
                            }
                        }
                        
                        // Re-register write event if tx_ring has data
                        if (ringbuffer_readable(&ws->tx_ring) > 0) {
                            struct kevent ev;
                            EV_SET(&ev, ws->fd, EVFILT_WRITE, EV_ADD | EV_CLEAR | EV_ENABLE | EV_ONESHOT, 0, 0, (void*)(intptr_t)ws->socket_index);
                            kevent(ws->io_ctx->kq, &ev, 1, NULL, 0, NULL);
                        }
                    } else if (result < 0 && test_len > 200) {
                        // Parse error - invalid handshake response
                        // Only fail if we have substantial data (complete response) that's invalid
                        // Check if it looks like HTTP but wrong format
                        if (strstr((char*)test_data, "HTTP") != NULL) {
                            // Has HTTP but parsing failed - real error
                            if (ws->on_error) {
                                ws->on_error(ws, -1, "Handshake failed: invalid HTTP response", ws->callback_user_data);
                            }
                            websocket_close(ws);
                        }
                        // If no HTTP found yet, might still be SSL handshake data - keep waiting
                    }
                    // result == 1 means "need more data" - this is OK, keep waiting
                }
                // If test_len == 0, no data yet - keep waiting (handshake still in progress)
            } else if (ws->state == WS_STATE_CONNECTED) {
                // Process WebSocket frames
                process_frames(ws);
                
                // Continue processing frames until ring buffer is empty
                // This handles cases where multiple frames arrived in one SSL read
                // EV_ONESHOT only fires once per socket event, so we need to drain the buffer
                size_t frames_processed = 1;
                while (frames_processed > 0) {
                    size_t before = ws->rx_ring.read_ptr;
                    process_frames(ws);
                    size_t after = ws->rx_ring.read_ptr;
                    frames_processed = (after != before) ? 1 : 0;
                }
            }
        }
    }
    
    // CRITICAL: For SSL connections, use hybrid approach
    // 1. Ultra-aggressive draining when kqueue reports readable (EVFILT_READ handler)
    // 2. CONTINUOUS polling between events to catch SecureTransport's buffered data
    // 3. FALLBACK: Use select() to check socket directly when kqueue fails
    // SecureTransport buffers data internally, and kqueue may not detect it immediately
    // SOLUTION: Poll SSL reads continuously with adaptive frequency + select() fallback
    if (ws->state == WS_STATE_CONNECTED && ws->use_ssl) {
        // CRITICAL FIX: For SSL connections, use select() as PRIMARY mechanism, not just fallback
        // kqueue is unreliable for slow connections (like Binance ~1 msg/sec)
        // Okx/Bitget work because they send messages frequently, keeping socket 'active'
        // Binance fails because kqueue misses events when socket appears 'idle'
        // SOLUTION: Check select() EVERY TIME for SSL connections, regardless of kqueue events
        // This ensures we catch data immediately, even for slow connections
        if (ws->fd >= 0) {
            fd_set read_fds;
            struct timeval timeout;
            FD_ZERO(&read_fds);
            FD_SET(ws->fd, &read_fds);
            timeout.tv_sec = 0;
            timeout.tv_usec = 0;  // Non-blocking check
            
            int select_result = select(ws->fd + 1, &read_fds, NULL, NULL, &timeout);
            if (select_result > 0 && FD_ISSET(ws->fd, &read_fds)) {
                // Socket is readable but kqueue didn't detect it - force SSL read
                // Process frames first to free buffer space
                process_frames(ws);
                
                // Force SSL read when select() detects readable
                // CRITICAL: Read aggressively in a tight loop until we get data or socket is empty
                // This is key for slow connections (like Binance) where kqueue misses events
                int select_read_attempts = 0;
                const int max_select_reads = 1000;  // Read up to 1000 times when select() detects data
                bool got_data_via_select = false;
                int consecutive_would_block_select = 0;
                const int max_would_block_select = 50;  // Stop after 50 consecutive would-blocks
                
                while (select_read_attempts < max_select_reads && ws->state == WS_STATE_CONNECTED) {
                    select_read_attempts++;
                    ssize_t ssl_result = ssl_read(ws->ssl_ctx, &ws->rx_ring);
                    
                    // CRITICAL FIX: If select() says readable but SSLRead() returns would-block,
                    // SecureTransport might be processing encrypted data in the background.
                    // Add a tiny delay to give it time to decrypt before trying again.
                    // This is especially important for slow connections like Binance.
                    if (ssl_result == 0 && select_read_attempts > 1) {
                        // Give SecureTransport a moment to process encrypted data
                        // Use usleep for very short delay (microseconds)
                        usleep(10);  // 10 microseconds - very short, just enough to let SecureTransport process
                    }
                    
                    if (ssl_result > 0) {
                        got_data_via_select = true;
                        consecutive_would_block_select = 0;  // Reset counter
                        // Update timestamp for adaptive polling
                        ws->last_ssl_data_time_ns = get_time_ns();
                        
                        // Process frames immediately
                        process_frames(ws);
                        
                        // Drain frames aggressively
                        int frame_iter = 0;
                        while (frame_iter < 500 && ws->state == WS_STATE_CONNECTED) {
                            size_t before = ws->rx_ring.read_ptr;
                            process_frames(ws);
                            size_t after = ws->rx_ring.read_ptr;
                            if (after == before) break;
                            frame_iter++;
                        }
                        
                        // Check select() again - there might be more data
                        FD_ZERO(&read_fds);
                        FD_SET(ws->fd, &read_fds);
                        timeout.tv_sec = 0;
                        timeout.tv_usec = 0;
                        if (select(ws->fd + 1, &read_fds, NULL, NULL, &timeout) > 0 && FD_ISSET(ws->fd, &read_fds)) {
                            // More data available - continue reading
                            continue;
                        }
                        // Socket no longer readable - break (we got what we could)
                        break;
                    } else if (ssl_result == 0) {
                        // Would-block - track consecutive would-blocks
                        consecutive_would_block_select++;
                        
                        // Check select() again - data might have arrived
                        FD_ZERO(&read_fds);
                        FD_SET(ws->fd, &read_fds);
                        timeout.tv_sec = 0;
                        timeout.tv_usec = 0;
                        if (select(ws->fd + 1, &read_fds, NULL, NULL, &timeout) > 0 && FD_ISSET(ws->fd, &read_fds)) {
                            // Socket still readable - continue trying
                            consecutive_would_block_select = 0;  // Reset counter
                            continue;
                        }
                        
                        // Socket no longer readable and SSLRead returns would-block
                        // This means SecureTransport has no data and socket is empty
                        if (consecutive_would_block_select >= max_would_block_select) {
                            // Too many would-blocks - socket is likely empty now
                            break;
                        }
                        // Continue trying a bit more
                        continue;
                    } else {
                        // Error - stop
                        break;
                    }
                }
            }
        }
        
        // Process frames first to free buffer space
        process_frames(ws);
        
        // CRITICAL FIX: Use adaptive polling - poll more aggressively when we're getting data
        // SecureTransport buffers data internally, and kqueue may not fire immediately when
        // new data arrives. We need to poll continuously to catch all data.
        // 
        // Strategy: Track when we last got SSL data and adjust polling frequency accordingly
        uint64_t now_ns = get_time_ns();
        uint64_t time_since_last_data_ns = (ws->last_ssl_data_time_ns > 0) ? 
            (now_ns - ws->last_ssl_data_time_ns) : UINT64_MAX;
        
        // Adaptive limits: poll more aggressively when we're getting data
        // CRITICAL FIX: For slow connections (like Binance ~1 msg/sec), we need to keep
        // polling aggressively even when no data has been received recently.
        // Okx/Bitget work because high message rate keeps polling active.
        // Binance fails because we reduce polling when idle, missing the next message.
        // SOLUTION: Keep aggressive polling even when idle, but with longer would-block tolerance
        int max_no_event_reads;
        int max_consecutive_would_block;
        
        if (time_since_last_data_ns < 100000000ULL) {  // < 100ms since last data
            // Recent data - poll very aggressively
            max_no_event_reads = 10000;  // Read up to 10,000 times
            max_consecutive_would_block = 500;  // Stop after 500 consecutive would-blocks
        } else if (time_since_last_data_ns < 1000000000ULL) {  // < 1s since last data
            // Somewhat recent - poll moderately
            max_no_event_reads = 5000;  // Read up to 5,000 times
            max_consecutive_would_block = 300;  // Stop after 300 consecutive would-blocks
        } else {
            // No data for a while - BUT keep polling aggressively for slow connections
            // This is critical for Binance which sends ~1 msg/sec
            // We need to be actively polling when the next message arrives
            // CRITICAL FIX: Reduce polling when idle to avoid blocking reconnection
            // But still poll enough to catch messages when they arrive
            max_no_event_reads = 1000;  // Reduced from 5000 to avoid blocking (still enough for slow connections)
            max_consecutive_would_block = 50;  // Reduced from 200 to exit faster when no data
        }
        
        int no_event_reads = 0;
        int consecutive_would_block_no_event = 0;
        bool made_progress = false;
        
        // CRITICAL FIX: Add timeout to prevent blocking reconnection
        // If we've been polling for more than 5ms, exit early to allow reconnection check
        uint64_t polling_start_ns = get_time_ns();
        const uint64_t MAX_POLLING_TIME_NS = 5000000ULL;  // 5ms in nanoseconds
        
        while (no_event_reads < max_no_event_reads && ws->state == WS_STATE_CONNECTED) {
            // Check timeout - exit early if we've been polling too long
            uint64_t polling_elapsed_ns = get_time_ns() - polling_start_ns;
            if (polling_elapsed_ns >= MAX_POLLING_TIME_NS) {
                // Timeout - exit early to allow reconnection check
                break;
            }
            no_event_reads++;
            ssize_t ssl_result = ssl_read(ws->ssl_ctx, &ws->rx_ring);
            
            // Update diagnostic counters
            if (ws->ssl_ctx) {
                ws->ssl_bytes_read_total = ssl_get_bytes_read(ws->ssl_ctx);
                ws->ssl_read_calls = ssl_get_read_calls(ws->ssl_ctx);
            }
            
            if (ssl_result > 0) {
                // Got data - update timestamp and reset counters
                ws->last_ssl_data_time_ns = now_ns;
                made_progress = true;
                consecutive_would_block_no_event = 0;
                
                // Process frames immediately to free buffer space
                process_frames(ws);
                
                // Drain frames aggressively to free maximum buffer space
                int frame_iter = 0;
                while (frame_iter < 500 && ws->state == WS_STATE_CONNECTED) {
                    size_t before = ws->rx_ring.read_ptr;
                    process_frames(ws);
                    size_t after = ws->rx_ring.read_ptr;
                    if (after == before) break;
                    frame_iter++;
                }
                
                // Reset read counter to allow more reads (we're getting data!)
                no_event_reads = 0;
                continue;
            } else if (ssl_result == -2) {
                // Ring buffer full - process frames to free space
                made_progress = true;
                consecutive_would_block_no_event = 0;
                process_frames(ws);
                
                // Drain frames aggressively
                int frame_iter = 0;
                while (frame_iter < 1000 && ws->state == WS_STATE_CONNECTED) {
                    size_t before = ws->rx_ring.read_ptr;
                    process_frames(ws);
                    size_t after = ws->rx_ring.read_ptr;
                    if (after == before) break;
                    frame_iter++;
                }
                
                // Reset read counter to allow more reads after freeing space
                no_event_reads = 0;
                continue;
            } else if (ssl_result == 0) {
                // Would-block - track consecutive would-blocks
                consecutive_would_block_no_event++;
                
                // Process frames before continuing
                process_frames(ws);
                
                // CRITICAL FIX: Check select() during polling loop to detect new data
                // This catches messages that arrive while we're in the polling loop
                // This is especially important for slow connections like Binance
                if (ws->fd >= 0 && (consecutive_would_block_no_event % 10 == 0)) {
                    // Check select() every 10 would-blocks to see if new data arrived
                    fd_set read_fds_check;
                    struct timeval timeout_check;
                    FD_ZERO(&read_fds_check);
                    FD_SET(ws->fd, &read_fds_check);
                    timeout_check.tv_sec = 0;
                    timeout_check.tv_usec = 0;
                    
                    if (select(ws->fd + 1, &read_fds_check, NULL, NULL, &timeout_check) > 0 && 
                        FD_ISSET(ws->fd, &read_fds_check)) {
                        // New data available! Reset counters and continue reading
                        consecutive_would_block_no_event = 0;
                        made_progress = true;
                        continue;  // Try reading again
                    }
                }
                
                // Adaptive stopping: if we made progress recently, be more patient
                if (made_progress && consecutive_would_block_no_event < max_consecutive_would_block / 2) {
                    // Reset counter if we made progress - SecureTransport may have more data
                    consecutive_would_block_no_event = 0;
                }
                
                // Only stop after many consecutive would-blocks
                if (consecutive_would_block_no_event >= max_consecutive_would_block) {
                    // Too many consecutive would-blocks - likely no more data right now
                    break;
                }
                // Continue trying - SecureTransport may have more data
                continue;
            } else {
                // Error - stop
                WS_LOG(ws, WS_LOG_WARN, "websocket_process: SSL read error in no-event polling: %zd", ssl_result);
                break;
            }
        }
    } else if (ws->state == WS_STATE_CONNECTED) {
        // For non-SSL, process frames even if no new socket events
        process_frames(ws);
    }
    
    // PHASE 2: Periodic observability checks (health and metrics reporting)
    if (ws->state == WS_STATE_CONNECTED) {
        check_health(ws);
        report_metrics_if_needed(ws);
        check_heartbeat(ws);  // PHASE 3: Check heartbeat
    }
    
    return event_count;
}

WSState websocket_get_state(WebSocket* ws) {
    return ws ? ws->state : WS_STATE_CLOSED;
}

void* websocket_get_user_data(WebSocket* ws) {
    return ws ? ws->user_data : NULL;
}

uint64_t websocket_get_last_nic_timestamp_ns(WebSocket* ws) {
    if (!ws || ws->socket_index < 0) {
        return 0;
    }
    // For SSL connections, get timestamp from SSL context
    if (ws->use_ssl && ws->ssl_ctx) {
        return ssl_get_last_nic_timestamp_ns(ws->ssl_ctx);
    }
    // For non-SSL, get from I/O context
    return io_get_last_nic_timestamp_ns(ws->io_ctx, ws->socket_index);
}

uint64_t websocket_get_last_nic_timestamp_ticks(WebSocket* ws) {
    if (!ws || ws->socket_index < 0) {
        return 0;
    }
    // For SSL connections, get timestamp from SSL context
    if (ws->use_ssl && ws->ssl_ctx) {
        return ssl_get_last_nic_timestamp_ticks(ws->ssl_ctx);
    }
    // For non-SSL, get from I/O context
    return io_get_last_nic_timestamp_ticks(ws->io_ctx, ws->socket_index);
}

// PHASE 2: Observability - Metrics API implementations

// Comparison function for qsort
static int compare_uint64_for_sort(const void* a, const void* b) {
    uint64_t va = *(const uint64_t*)a;
    uint64_t vb = *(const uint64_t*)b;
    if (va < vb) return -1;
    if (va > vb) return 1;
    return 0;
}

// Helper function to calculate percentiles from latency samples
static void calculate_latency_percentiles(WebSocket* ws, double* p50, double* p99) {
    if (!ws || !ws->latency_samples || ws->latency_sample_count == 0) {
        *p50 = 0.0;
        *p99 = 0.0;
        return;
    }
    
    // Create a temporary sorted array for percentile calculation
    size_t count = ws->latency_sample_count;
    uint64_t* sorted = (uint64_t*)malloc(count * sizeof(uint64_t));
    if (!sorted) {
        *p50 = 0.0;
        *p99 = 0.0;
        return;
    }
    
    // Copy and sort
    memcpy(sorted, ws->latency_samples, count * sizeof(uint64_t));
    
    // Use qsort for O(n log n) instead of O(n^2) bubble sort
    // Critical for HFT: latency_sample_count can be up to 1000
    qsort(sorted, count, sizeof(uint64_t), compare_uint64_for_sort);
    
    // Calculate percentiles
    size_t p50_idx = (size_t)(count * 0.50);
    size_t p99_idx = (size_t)(count * 0.99);
    if (p99_idx >= count) p99_idx = count - 1;
    
    *p50 = (double)sorted[p50_idx];
    *p99 = (double)sorted[p99_idx];
    
    free(sorted);
}

// Helper to update latency sample
static void update_latency_sample(WebSocket* ws, uint64_t latency_ns) {
    // CRITICAL FIX: Check all pointers before accessing
    if (!ws || !ws->latency_samples || ws->latency_sample_capacity == 0) {
        return;
    }
    
    // PRIORITY 1 FIX: Use rolling window - overwrite oldest sample
    // This ensures bounded memory usage during high-throughput scenarios
    ws->latency_samples[ws->latency_sample_idx] = latency_ns;
    ws->latency_sample_idx = (ws->latency_sample_idx + 1) % ws->latency_sample_capacity;
    
    if (ws->latency_sample_count < ws->latency_sample_capacity) {
        ws->latency_sample_count++;
    }
    
    // PRIORITY 1 FIX: Periodically reset metrics to prevent unbounded accumulation
    // DISABLED: This was causing crashes - metric reset should be done explicitly via API
    // The rolling window for latency samples is already bounded, so no periodic reset needed
    // Metrics can be reset explicitly via websocket_reset_metrics() when needed
}

void websocket_set_on_metrics(WebSocket* ws, ws_on_metrics_t callback, void* user_data) {
    if (ws) {
        ws->on_metrics = callback;
        ws->metrics_user_data = user_data;
    }
}

// Diagnostic tracking (for throughput investigation)
void websocket_get_diagnostics(WebSocket* ws, uint64_t* ssl_bytes_read, uint64_t* ssl_read_calls,
                                uint64_t* frames_parsed, uint64_t* frames_processed) {
    if (!ws) {
        return;
    }
    
    if (ssl_bytes_read) {
        *ssl_bytes_read = ws->ssl_bytes_read_total;
    }
    if (ssl_read_calls) {
        *ssl_read_calls = ws->ssl_read_calls;
    }
    if (frames_parsed) {
        *frames_parsed = ws->frames_parsed_total;
    }
    if (frames_processed) {
        *frames_processed = ws->frames_processed_total;
    }
}

void websocket_get_metrics(WebSocket* ws, WebSocketMetrics* out_metrics) {
    if (!ws || !out_metrics) {
        return;
    }
    
    // Calculate current metrics
    uint64_t now_ns = get_time_ns();
    
    // Calculate latency percentiles
    calculate_latency_percentiles(ws, &ws->metrics.latency_p50_ns, &ws->metrics.latency_p99_ns);
    
    // Calculate throughput (messages per second)
    if (ws->connection_start_ns > 0 && now_ns > ws->connection_start_ns) {
        double elapsed_sec = ((double)(now_ns - ws->connection_start_ns)) / 1000000000.0;
        if (elapsed_sec > 0) {
            ws->metrics.throughput_msg_per_sec = (double)ws->metrics.messages_received / elapsed_sec;
        }
    }
    
    // Calculate ring buffer utilization
    size_t rx_readable = ringbuffer_readable(&ws->rx_ring);
    double rx_utilization = (double)rx_readable / (double)ws->rx_ring.size;
    size_t tx_readable = ringbuffer_readable(&ws->tx_ring);
    double tx_utilization = (double)tx_readable / (double)ws->tx_ring.size;
    ws->metrics.ringbuffer_utilization = (rx_utilization + tx_utilization) / 2.0;
    
    // Calculate connection uptime
    if (ws->connection_start_ns > 0) {
        ws->metrics.connection_uptime_ns = now_ns - ws->connection_start_ns;
    }
    
    // Copy metrics to output
    memcpy(out_metrics, &ws->metrics, sizeof(WebSocketMetrics));
}

void websocket_reset_metrics(WebSocket* ws) {
    if (!ws) {
        return;
    }
    
    memset(&ws->metrics, 0, sizeof(WebSocketMetrics));
    ws->latency_sample_count = 0;
    ws->latency_sample_idx = 0;
    ws->metrics_last_report_ns = 0;
}

// PHASE 2: Observability - Health check API

WSHealthStatus websocket_get_health(WebSocket* ws) {
    if (!ws) {
        return WS_HEALTH_UNHEALTHY;
    }
    
    // Check connection state
    if (ws->state != WS_STATE_CONNECTED) {
        return WS_HEALTH_UNHEALTHY;
    }
    
    // Check error rate
    uint64_t total_operations = ws->metrics.messages_received + ws->metrics.messages_sent;
    if (total_operations > 0) {
        double error_rate = (double)ws->metrics.errors_total / (double)total_operations;
        if (error_rate > 0.1) {  // >10% error rate
            return WS_HEALTH_UNHEALTHY;
        }
    }
    
    // Check latency
    if (ws->metrics.latency_p99_ns > 100000) {  // P99 > 100µs
        return WS_HEALTH_DEGRADED;
    }
    
    // Check ring buffer saturation
    if (ws->metrics.ringbuffer_utilization > 0.8) {  // >80% utilization
        return WS_HEALTH_DEGRADED;
    }
    
    return WS_HEALTH_OK;
}

void websocket_set_on_health(WebSocket* ws, ws_on_health_t callback, void* user_data) {
    if (ws) {
        ws->on_health = callback;
        ws->health_user_data = user_data;
    }
}

// PHASE 2: Observability - Logging API

void websocket_set_log_callback(WebSocket* ws, ws_log_callback_t callback, void* user_data) {
    if (ws) {
        ws->log_callback = callback;
        ws->log_user_data = user_data;
    }
}

// PHASE 2: Helper function to check and report health changes (called periodically)
static void check_health(WebSocket* ws) {
    if (!ws || !ws->on_health) {
        return;
    }
    
    uint64_t now_ns = get_time_ns();
    // Check health every 1 second
    if (now_ns - ws->last_health_check_ns < 1000000000ULL) {
        return;
    }
    ws->last_health_check_ns = now_ns;
    
    WSHealthStatus new_health = websocket_get_health(ws);
    if (new_health != ws->current_health) {
        const char* reason = "";
        if (new_health == WS_HEALTH_UNHEALTHY) {
            if (ws->state != WS_STATE_CONNECTED) {
                reason = "Connection not connected";
            } else {
                reason = "High error rate";
            }
        } else if (new_health == WS_HEALTH_DEGRADED) {
            reason = "High latency or buffer saturation";
        } else {
            reason = "All systems normal";
        }
        
        ws->current_health = new_health;
        ws->on_health(ws, new_health, reason, ws->health_user_data);
    }
}

// PHASE 2: Helper function to report metrics periodically (called from websocket_process)
static void report_metrics_if_needed(WebSocket* ws) {
    if (!ws || !ws->on_metrics) {
        return;
    }
    
    uint64_t now_ns = get_time_ns();
    // Report metrics every 1 second
    if (now_ns - ws->metrics_last_report_ns < 1000000000ULL) {
        return;
    }
    ws->metrics_last_report_ns = now_ns;
    
    // Update metrics before reporting
    WebSocketMetrics current_metrics;
    websocket_get_metrics(ws, &current_metrics);
    
    // Call callback with current metrics
    ws->on_metrics(ws, &current_metrics, ws->metrics_user_data);
}

// PHASE 3: Error Recovery - Reconnection API implementations

void websocket_set_reconnect_config(WebSocket* ws, const WSReconnectConfig* config) {
    if (!ws || !config) {
        return;
    }
    
    memcpy(&ws->reconnect_config, config, sizeof(WSReconnectConfig));
    
    // Ensure next_backoff_ms is initialized
    if (ws->reconnect_state.reconnect_attempts == 0) {
        ws->reconnect_state.next_backoff_ms = ws->reconnect_config.initial_backoff_ms;
    }
}

void websocket_get_reconnect_state(WebSocket* ws, WSReconnectState* out_state) {
    if (!ws || !out_state) {
        return;
    }
    
    memcpy(out_state, &ws->reconnect_state, sizeof(WSReconnectState));
}

// PHASE 3: Helper to calculate next backoff delay
static uint32_t calculate_backoff(WebSocket* ws) {
    if (ws->reconnect_state.reconnect_attempts == 0) {
        return ws->reconnect_config.initial_backoff_ms;
    }
    
    // Calculate: initial * (multiplier ^ attempts)
    double backoff_ms = (double)ws->reconnect_config.initial_backoff_ms;
    for (uint32_t i = 0; i < ws->reconnect_state.reconnect_attempts; i++) {
        backoff_ms *= ws->reconnect_config.backoff_multiplier;
    }
    
    // Cap at max_backoff_ms
    if (backoff_ms > (double)ws->reconnect_config.max_backoff_ms) {
        backoff_ms = (double)ws->reconnect_config.max_backoff_ms;
    }
    
    return (uint32_t)backoff_ms;
}

// PHASE 3: Helper to trigger reconnection (called from error handler)

// PHASE 3: Error Recovery - Heartbeat API

void websocket_set_heartbeat_config(WebSocket* ws, const WSHeartbeatConfig* config) {
    if (!ws || !config) {
        return;
    }
    
    memcpy(&ws->heartbeat_config, config, sizeof(WSHeartbeatConfig));
    ws->last_ping_sent_ns = 0;
    ws->last_pong_received_ns = 0;
}

// PHASE 3: Helper to send ping and check pong timeout
static void check_heartbeat(WebSocket* ws) {
    if (!ws || !ws->heartbeat_config.enable_heartbeat || ws->state != WS_STATE_CONNECTED) {
        return;
    }
    
    uint64_t now_ns = get_time_ns();
    uint64_t ping_interval_ns = (uint64_t)ws->heartbeat_config.ping_interval_ms * 1000000ULL;
    uint64_t pong_timeout_ns = (uint64_t)ws->heartbeat_config.pong_timeout_ms * 1000000ULL;
    
    // Send ping if interval has elapsed
    if (ws->last_ping_sent_ns == 0 || (now_ns - ws->last_ping_sent_ns) >= ping_interval_ns) {
        // Send empty ping frame (RFC 6455 allows empty ping)
        // CRITICAL: Client-to-server frames MUST be masked (RFC 6455 section 5.3)
        uint32_t masking_key;
        FILE* urandom = fopen("/dev/urandom", "r");
        if (urandom) {
            fread(&masking_key, 1, sizeof(masking_key), urandom);
            fclose(urandom);
        } else {
            masking_key = (uint32_t)rand() ^ ((uint32_t)rand() << 16);
        }
        
        // Build masked ping frame: FIN + PING opcode, MASK bit set, empty payload
        uint8_t ping_frame[6] = {
            0x89,  // FIN + PING opcode
            0x80,  // MASK bit set (required for client-to-server)
            ((uint8_t*)&masking_key)[0],
            ((uint8_t*)&masking_key)[1],
            ((uint8_t*)&masking_key)[2],
            ((uint8_t*)&masking_key)[3]
        };
        size_t written = ringbuffer_write(&ws->tx_ring, ping_frame, 6);
        if (written == 6) {
            if (ws->use_ssl) {
                ssl_write(ws->ssl_ctx, &ws->tx_ring);
            } else {
                io_write(ws->io_ctx, ws->socket_index);
            }
            ws->last_ping_sent_ns = now_ns;
        }
    }
    
    // Check for pong timeout
    if (ws->last_ping_sent_ns > 0 && ws->last_pong_received_ns < ws->last_ping_sent_ns) {
        if ((now_ns - ws->last_ping_sent_ns) >= pong_timeout_ns) {
            WS_LOG(ws, WS_LOG_WARN, "Heartbeat timeout: no pong received within %u ms", 
                   ws->heartbeat_config.pong_timeout_ms);
            if (ws->heartbeat_config.on_heartbeat_timeout) {
                ws->heartbeat_config.on_heartbeat_timeout(ws, ws->heartbeat_config.heartbeat_user_data);
            }
            // Reset ping sent time to allow retry
            ws->last_ping_sent_ns = 0;
        }
    }
}
