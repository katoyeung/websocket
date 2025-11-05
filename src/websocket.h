#ifndef WEBSOCKET_H
#define WEBSOCKET_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

// WebSocket state machine
typedef enum {
    WS_STATE_CONNECTING,
    WS_STATE_CONNECTED,
    WS_STATE_CLOSING,
    WS_STATE_CLOSED
} WSState;

// WebSocket frame opcodes (RFC 6455)
#define WS_OPCODE_CONT  0x0
#define WS_OPCODE_TEXT  0x1
#define WS_OPCODE_BINARY 0x2
#define WS_OPCODE_CLOSE 0x8
#define WS_OPCODE_PING  0x9
#define WS_OPCODE_PONG  0xA

// Forward declarations
typedef struct WebSocket WebSocket;

// Message callback type
// Called when a complete WebSocket message is received
typedef void (*ws_on_message_t)(WebSocket* ws, const uint8_t* data, size_t len, void* user_data);

// Error callback type
typedef void (*ws_on_error_t)(WebSocket* ws, int error_code, const char* error_msg, void* user_data);

// PHASE 2: Observability - Metrics structure
typedef struct {
    uint64_t messages_received;
    uint64_t messages_sent;
    uint64_t errors_total;
    uint64_t bytes_received;
    uint64_t bytes_sent;
    double latency_p50_ns;
    double latency_p99_ns;
    double throughput_msg_per_sec;
    double ringbuffer_utilization;
    uint64_t connection_uptime_ns;
} WebSocketMetrics;

// PHASE 2: Observability - Metrics callback type
typedef void (*ws_on_metrics_t)(WebSocket* ws, const WebSocketMetrics* metrics, void* user_data);

// PHASE 2: Observability - Health status
typedef enum {
    WS_HEALTH_OK,
    WS_HEALTH_DEGRADED,  // High latency, buffer saturation
    WS_HEALTH_UNHEALTHY  // Connection issues, errors
} WSHealthStatus;

// PHASE 2: Observability - Health check callback type
typedef void (*ws_on_health_t)(WebSocket* ws, WSHealthStatus status, const char* reason, void* user_data);

// PHASE 2: Observability - Logging
typedef enum {
    WS_LOG_DEBUG,
    WS_LOG_INFO,
    WS_LOG_WARN,
    WS_LOG_ERROR
} WSLogLevel;

// PHASE 2: Observability - Log callback type
typedef void (*ws_log_callback_t)(WebSocket* ws, WSLogLevel level, const char* message, void* user_data);

// Create WebSocket instance
// Returns NULL on error
WebSocket* websocket_create(void);

// Cleanup WebSocket instance
void websocket_destroy(WebSocket* ws);

// Set message callback
void websocket_set_on_message(WebSocket* ws, ws_on_message_t callback, void* user_data);

// Set error callback
void websocket_set_on_error(WebSocket* ws, ws_on_error_t callback, void* user_data);

// Connect to WebSocket server
// url: e.g., "wss://stream.binance.com:9443/ws/btcusdt@ticker"
// disable_cert_validation: true for HFT optimization (skip cert validation)
// Returns 0 on success, -1 on error
int websocket_connect(WebSocket* ws, const char* url, bool disable_cert_validation);

// Send message (TEXT or BINARY)
// Returns 0 on success, -1 on error
int websocket_send(WebSocket* ws, const uint8_t* data, size_t len, bool is_text);

// Close WebSocket connection
// Returns 0 on success, -1 on error
int websocket_close(WebSocket* ws);

// Process I/O events (call this in your event loop)
// Returns number of events processed, -1 on error
int websocket_process(WebSocket* ws);

// Get current state
WSState websocket_get_state(WebSocket* ws);

// Get user data pointer
void* websocket_get_user_data(WebSocket* ws);

// Get last captured NIC timestamp (kernel-level, from SO_TIMESTAMP_OLD)
// Returns timestamp in nanoseconds (0 if not available)
// Note: For SSL/TLS, timestamps may not be available if SecureTransport reads internally
uint64_t websocket_get_last_nic_timestamp_ns(WebSocket* ws);

// Get last NIC timestamp in CPU cycles
uint64_t websocket_get_last_nic_timestamp_ticks(WebSocket* ws);

// PHASE 2: Observability - Metrics API
void websocket_set_on_metrics(WebSocket* ws, ws_on_metrics_t callback, void* user_data);
void websocket_get_metrics(WebSocket* ws, WebSocketMetrics* out_metrics);
void websocket_reset_metrics(WebSocket* ws);

// PHASE 2: Observability - Health check API
WSHealthStatus websocket_get_health(WebSocket* ws);

// Diagnostic tracking (for throughput investigation)
void websocket_get_diagnostics(WebSocket* ws, uint64_t* ssl_bytes_read, uint64_t* ssl_read_calls, 
                                uint64_t* frames_parsed, uint64_t* frames_processed);
void websocket_set_on_health(WebSocket* ws, ws_on_health_t callback, void* user_data);

// PHASE 2: Observability - Logging API
void websocket_set_log_callback(WebSocket* ws, ws_log_callback_t callback, void* user_data);

// PHASE 3: Error Recovery - Reconnection configuration
typedef struct {
    bool auto_reconnect;
    uint32_t max_retries;           // 0 = unlimited
    uint32_t initial_backoff_ms;    // e.g., 100ms
    uint32_t max_backoff_ms;        // e.g., 30000ms (30s)
    double backoff_multiplier;      // e.g., 2.0
    bool reset_backoff_on_success;
} WSReconnectConfig;

// PHASE 3: Error Recovery - Reconnection state
typedef struct {
    uint32_t reconnect_attempts;
    uint32_t next_backoff_ms;
    bool is_reconnecting;
} WSReconnectState;

// PHASE 3: Error Recovery - Heartbeat configuration
typedef struct {
    bool enable_heartbeat;
    uint32_t ping_interval_ms;      // Send ping every N ms
    uint32_t pong_timeout_ms;       // Expect pong within N ms
    void (*on_heartbeat_timeout)(WebSocket* ws, void* user_data);
    void* heartbeat_user_data;
} WSHeartbeatConfig;

// PHASE 3: Error Recovery - Reconnection API
void websocket_set_reconnect_config(WebSocket* ws, const WSReconnectConfig* config);
void websocket_get_reconnect_state(WebSocket* ws, WSReconnectState* out_state);

// PHASE 3: Error Recovery - Heartbeat API
void websocket_set_heartbeat_config(WebSocket* ws, const WSHeartbeatConfig* config);

#endif // WEBSOCKET_H

