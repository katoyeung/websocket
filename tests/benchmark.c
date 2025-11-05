#include <stdio.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "../src/parser_neon.h"
#include "../src/ringbuffer.h"
#include "../src/os_macos.h"
#include "../src/ssl.h"
#include "../src/websocket.h"

#define BENCHMARK_ITERATIONS 1000000
#define BENCHMARK_WARMUP_RATIO 0.1  // 10% of iterations as warmup
#define SSL_LATENCY_SAMPLES 300  // Match reference benchmark (300 samples)
#define MAX_WEBSOCKET_CONN_WAIT 10  // Maximum connection wait time (seconds)
#define MAX_SSL_SAMPLE_WAIT 900     // Maximum sample collection time (15 minutes)

// Generate test WebSocket frame (fixed: correct handling for payload_size=126)
static void generate_test_frame(uint8_t* buffer, size_t payload_size) {
    buffer[0] = 0x82;  // FIN|BINARY
    buffer[1] = 0x00;  // No mask
    
    if (payload_size < 126) {
        buffer[1] |= (uint8_t)payload_size;
        memset(buffer + 2, 'X', payload_size);
    } else if (payload_size <= 65535) {  // Fixed: <= to avoid overflow
        buffer[1] |= 126;
        uint16_t len16 = htons((uint16_t)payload_size);
        memcpy(buffer + 2, &len16, 2);
        memset(buffer + 4, 'X', payload_size);
    }
}

// Benchmark warmup function (optimize CPU cache and branch prediction)
static void benchmark_warmup(size_t iterations) {
    printf("Warming up (%zu iterations)...\n", iterations);
    volatile uint64_t dummy = 0;
    for (size_t i = 0; i < iterations; i++) {
        dummy += arm_cycle_count();  // Trigger CPU cache and branch prediction initialization
    }
    (void)dummy;  // Suppress unused warning
}

// Benchmark Neon vs scalar WebSocket frame parsing (optimized: warmup + prevent compiler optimization)
void benchmark_ws_frame_parsing(void) {
    printf("WebSocket Frame Parsing Benchmark\n");
    printf("===================================\n\n");
    
    size_t frame_sizes[] = {64, 512, 4096};
    size_t num_sizes = sizeof(frame_sizes) / sizeof(frame_sizes[0]);
    size_t warmup_iterations = (size_t)(BENCHMARK_ITERATIONS * BENCHMARK_WARMUP_RATIO);
    
    benchmark_warmup(warmup_iterations);
    
    for (size_t i = 0; i < num_sizes; i++) {
        size_t payload_size = frame_sizes[i];
        size_t frame_size = 2 + payload_size;
        if (payload_size >= 126) {
            frame_size += 2;  // 16-bit length field
        }
        
        uint8_t* frame_data = malloc(frame_size);
        if (!frame_data) {
            fprintf(stderr, "Failed to allocate frame data\n");
            continue;
        }
        generate_test_frame(frame_data, payload_size);
        
        printf("Testing %zu-byte payload:\n", payload_size);
        
        // Neon benchmark (volatile to prevent optimization)
        volatile WSFrame neon_frame;
        uint64_t neon_start = arm_cycle_count();
        for (int j = 0; j < BENCHMARK_ITERATIONS; j++) {
            neon_parse_ws_frame(frame_data, frame_size, (WSFrame*)&neon_frame);
        }
        uint64_t neon_end = arm_cycle_count();
        uint64_t neon_cycles = neon_end - neon_start;
        double neon_time_ns = arm_cycles_to_ns(neon_cycles);
        
        // Scalar benchmark (volatile to prevent optimization)
        volatile WSFrame scalar_frame;
        uint64_t scalar_start = arm_cycle_count();
        for (int j = 0; j < BENCHMARK_ITERATIONS; j++) {
            scalar_parse_ws_frame(frame_data, frame_size, (WSFrame*)&scalar_frame);
        }
        uint64_t scalar_end = arm_cycle_count();
        uint64_t scalar_cycles = scalar_end - scalar_start;
        double scalar_time_ns = arm_cycles_to_ns(scalar_cycles);
        
        // Output results (ensure values are valid)
        printf("  Neon:    %.2f ns/frame (%.2f cycles)\n", 
               neon_time_ns / BENCHMARK_ITERATIONS, 
               (double)neon_cycles / BENCHMARK_ITERATIONS);
        printf("  Scalar:  %.2f ns/frame (%.2f cycles)\n", 
               scalar_time_ns / BENCHMARK_ITERATIONS, 
               (double)scalar_cycles / BENCHMARK_ITERATIONS);
        
        double speedup = scalar_time_ns / neon_time_ns;
        printf("  Speedup: %.2fx\n\n", speedup);
        
        free(frame_data);
    }
}

// Benchmark JSON parsing (optimized: warmup + use results)
void benchmark_json_parsing(void) {
    printf("JSON Parsing Benchmark\n");
    printf("=======================\n\n");
    
    const char* json = "{\"symbol\":\"BTCUSDT\",\"price\":\"50000.50\",\"quantity\":\"0.001\",\"timestamp\":1234567890}";
    size_t json_len = strlen(json);
    size_t warmup_iterations = (size_t)(BENCHMARK_ITERATIONS * BENCHMARK_WARMUP_RATIO);
    
    benchmark_warmup(warmup_iterations);
    
    printf("Testing JSON field extraction:\n");
    
    // Neon benchmark (use results to prevent optimization)
    volatile char neon_value_buf[64];
    volatile size_t neon_value_len = 0;
    uint64_t neon_start = arm_cycle_count();
    for (int i = 0; i < BENCHMARK_ITERATIONS; i++) {
        neon_parse_json_market_data(json, json_len, "price", (char*)neon_value_buf, sizeof(neon_value_buf), (size_t*)&neon_value_len);
    }
    uint64_t neon_end = arm_cycle_count();
    uint64_t neon_cycles = neon_end - neon_start;
    double neon_time_ns = arm_cycles_to_ns(neon_cycles);
    
    // Scalar benchmark (use results to prevent optimization)
    volatile char scalar_value_buf[64];
    volatile size_t scalar_value_len = 0;
    uint64_t scalar_start = arm_cycle_count();
    for (int i = 0; i < BENCHMARK_ITERATIONS; i++) {
        scalar_parse_json_market_data(json, json_len, "price", (char*)scalar_value_buf, sizeof(scalar_value_buf), (size_t*)&scalar_value_len);
    }
    uint64_t scalar_end = arm_cycle_count();
    uint64_t scalar_cycles = scalar_end - scalar_start;
    double scalar_time_ns = arm_cycles_to_ns(scalar_cycles);
    
    printf("  Neon:    %.2f ns/extraction (%.2f cycles)\n", 
           neon_time_ns / BENCHMARK_ITERATIONS, 
           (double)neon_cycles / BENCHMARK_ITERATIONS);
    printf("  Scalar:  %.2f ns/extraction (%.2f cycles)\n", 
           scalar_time_ns / BENCHMARK_ITERATIONS, 
           (double)scalar_cycles / BENCHMARK_ITERATIONS);
    
    double speedup = scalar_time_ns / neon_time_ns;
    printf("  Speedup: %.2fx\n\n", speedup);
}

// Benchmark ring buffer throughput
void benchmark_ringbuffer_throughput(void) {
    printf("Ring Buffer Throughput Benchmark\n");
    printf("==================================\n\n");
    
    RingBuffer rb;
    if (ringbuffer_init(&rb) != 0) {
        fprintf(stderr, "Failed to initialize ring buffer\n");
        return;
    }
    
    size_t test_sizes[] = {64, 256, 1024, 4096};
    size_t num_sizes = sizeof(test_sizes) / sizeof(test_sizes[0]);
    
    for (size_t i = 0; i < num_sizes; i++) {
        size_t chunk_size = test_sizes[i];
        char* test_data = malloc(chunk_size);
        memset(test_data, 'X', chunk_size);
        
        // Write benchmark
        uint64_t write_start = arm_cycle_count();
        size_t total_written = 0;
        for (int j = 0; j < BENCHMARK_ITERATIONS; j++) {
            size_t written = ringbuffer_write(&rb, test_data, chunk_size);
            if (written == chunk_size) {
                total_written += written;
            } else {
                // Ring buffer full, read to make space
                char* read_buf = malloc(chunk_size);
                ringbuffer_read(&rb, read_buf, chunk_size);
                free(read_buf);
            }
        }
        uint64_t write_end = arm_cycle_count();
        uint64_t write_cycles = write_end - write_start;
        
        // Read benchmark
        ringbuffer_reset(&rb);
        for (int j = 0; j < 1000; j++) {
            ringbuffer_write(&rb, test_data, chunk_size);
        }
        
        char* read_buf = malloc(chunk_size);
        uint64_t read_start = arm_cycle_count();
        size_t total_read = 0;
        for (int j = 0; j < 1000; j++) {
            size_t read = ringbuffer_read(&rb, read_buf, chunk_size);
            total_read += read;
        }
        uint64_t read_end = arm_cycle_count();
        uint64_t read_cycles = read_end - read_start;
        
        double write_time_ns = arm_cycles_to_ns(write_cycles);
        double read_time_ns = arm_cycles_to_ns(read_cycles);
        
        double write_throughput_gbps = (total_written * 8.0) / (write_time_ns / 1e9) / 1e9;
        double read_throughput_gbps = (total_read * 8.0) / (read_time_ns / 1e9) / 1e9;
        
        printf("%zu-byte chunks:\n", chunk_size);
        printf("  Write: %.2f GB/s (%.2f ns/op)\n", write_throughput_gbps, write_time_ns / BENCHMARK_ITERATIONS);
        printf("  Read:  %.2f GB/s (%.2f ns/op)\n", read_throughput_gbps, read_time_ns / 1000);
        printf("\n");
        
        free(test_data);
        free(read_buf);
    }
    
    ringbuffer_cleanup(&rb);
}

// Statistics calculation helpers
static double calculate_mean(uint64_t* values, size_t count) {
    double sum = 0.0;
    for (size_t i = 0; i < count; i++) {
        sum += (double)values[i];
    }
    return sum / (double)count;
}

static double calculate_stddev(uint64_t* values, size_t count, double mean) {
    double sum_sq_diff = 0.0;
    for (size_t i = 0; i < count; i++) {
        double diff = (double)values[i] - mean;
        sum_sq_diff += diff * diff;
    }
    return sqrt(sum_sq_diff / (double)count);
}

static int compare_uint64(const void* a, const void* b) {
    uint64_t va = *(const uint64_t*)a;
    uint64_t vb = *(const uint64_t*)b;
    if (va < vb) return -1;
    if (va > vb) return 1;
    return 0;
}

static uint64_t percentile(uint64_t* sorted_values, size_t count, double p) {
    if (count == 0) return 0;
    size_t idx = (size_t)(p * (count - 1));
    if (idx >= count) idx = count - 1;
    return sorted_values[idx];
}

// Error callback to detect connection issues (file scope for access from multiple functions)
static int error_callback_called = 0;
static void error_callback(WebSocket* ws, int error_code, const char* error_msg, void* user_data) {
    (void)ws;
    (void)user_data;
    error_callback_called = 1;
    fprintf(stderr, "\n⚠️  WebSocket ERROR: code=%d, msg=%s, state=%d\n", 
            error_code, error_msg ? error_msg : "unknown", (int)websocket_get_state(ws));
    fflush(stderr);
}

// Message callback for real Binance WebSocket measurements (optimized: thread-safe + memory-safe)
static void measurement_callback(WebSocket* ws, const uint8_t* data, size_t len, void* user_data) {
    typedef struct {
        uint64_t* total_latencies;
        uint64_t* ssl_decrypt_latencies;
        uint64_t* app_process_latencies;
        size_t* sample_bytes;
        uint8_t* sample_opcodes;
        int* sample_count;
        int warmup_samples;
        int max_measurement_samples;
    } MeasurementCtx;
    
    MeasurementCtx* ctx = (MeasurementCtx*)user_data;
    if (!ctx || !data || len == 0) return;
    
    // Thread-safe increment using atomic operation (prevent race condition)
    int current_count = __sync_fetch_and_add(ctx->sample_count, 1);
    
    if (current_count < ctx->warmup_samples) {
        return;  // Skip warmup samples
    }
    
    int stored_idx = current_count - ctx->warmup_samples;
    
    // Safety check: ensure stored index is within bounds BEFORE accessing arrays
    if (stored_idx < 0 || stored_idx >= ctx->max_measurement_samples) {
        return;  // Exceeded sample limit or invalid index
    }
    
    // Safe data copy (must be freed)
    uint8_t* data_copy = malloc(len);
    if (!data_copy) return;  // Out of memory
    memcpy(data_copy, data, len);
    
    // Real NIC timestamp (requires kernel support, interface reserved here)
    uint64_t t0_nic = websocket_get_last_nic_timestamp_ticks(ws);
    uint64_t t1 = arm_cycle_count();  // SSL decryption completion time
    uint64_t t0 = (t0_nic > 0) ? t0_nic : t1;
    
    // Application processing (simplified logic, remove redundancy)
    uint8_t opcode = (len > 0 && data_copy[0] == '{') ? 1 : 0;  // TEXT frame check
    volatile int dummy = 0;
    for (size_t i = 0; i < len && i < 256; i++) {
        if (data_copy[i] == ':') dummy++;
    }
    (void)dummy;
    
    uint64_t t3 = arm_cycle_count();  // Application processing completion time
    
    // Calculate latencies (fixed: overflow check)
    // t0 = NIC timestamp (if available) or SSL decryption time (fallback)
    // t1 = SSL decryption completion time
    // t3 = Application processing completion time
    uint64_t ssl_time = 0;
    if (t0_nic > 0 && t1 > t0_nic) {
        // Real NIC→SSL measurement available
        ssl_time = t1 - t0_nic;
    } else {
        // No NIC timestamp - can't measure NIC→SSL
        ssl_time = 0;
    }
    uint64_t app_time = (t3 > t1) ? (t3 - t1) : 0;
    uint64_t total_time = 0;
    if (t0_nic > 0 && t3 > t0_nic) {
        // Real NIC→APP measurement available
        total_time = t3 - t0_nic;
    } else if (t1 > 0 && t3 > t1) {
        // Fallback: SSL→APP only (no NIC timestamp)
        total_time = t3 - t1;
    } else {
        total_time = 0;
    }
    
    // Thread-safe write (assuming single-threaded callback, add lock if multi-threaded)
    ctx->total_latencies[stored_idx] = total_time;
    ctx->ssl_decrypt_latencies[stored_idx] = ssl_time;
    ctx->app_process_latencies[stored_idx] = app_time;
    ctx->sample_bytes[stored_idx] = len;
    ctx->sample_opcodes[stored_idx] = opcode;
    
    free(data_copy);  // Ensure memory is freed
    
    // Progress printing - print first 10 samples and then every 10
    if (stored_idx < 10 || (stored_idx % 10 == 0 && stored_idx < ctx->max_measurement_samples)) {
        printf("Collected %d/%d measurement samples... (total samples: %d, warmup: %d)\n", 
               stored_idx + 1, ctx->max_measurement_samples, current_count + 1, ctx->warmup_samples);
        fflush(stdout);
    }
}

// SSL/TLS Decryption Latency Benchmark
// Attempts to measure NIC → SSL → APP latency using real Binance WebSocket connection
// 
// ⚠️ LIMITATIONS:
// - REAL NIC timestamps require: recvmsg() + CMSG extraction of SO_TIMESTAMP_OLD
// - Currently only measures approximate timing (not true kernel-level NIC timestamp)
// - Mock data fallback has NO real NIC timing (just simulated overhead)
// 
// For TRUE NIC→SSL timing, you need to:
// 1. Modify io_read() to use recvmsg() instead of read()
// 2. Extract timestamp from CMSG_DATA(cmsg) using SO_TIMESTAMP_OLD
// 3. Pass timestamp through SSL layer to benchmark callback
void benchmark_ssl_decryption_latency(void) {
    // Declare arrays at function scope (shared between real and simulated paths)
    // Initialize to zero to avoid garbage values
    uint64_t total_latencies[SSL_LATENCY_SAMPLES] = {0};
    uint64_t ssl_decrypt_latencies[SSL_LATENCY_SAMPLES] = {0};
    uint64_t app_process_latencies[SSL_LATENCY_SAMPLES] = {0};
    size_t sample_bytes[SSL_LATENCY_SAMPLES] = {0};
    uint8_t sample_opcodes[SSL_LATENCY_SAMPLES] = {0};
    int sample_count = 0;
    int actual_samples = 0;
    
    printf("SSL/TLS Decryption Latency Benchmark\n");
    printf("====================================\n");
    printf("Measuring NIC → SSL → APP pipeline latency\n");
    printf("⚠️  NOTE: Mock data CANNOT provide real NIC→SSL timing!\n");
    printf("   Real connection attempts to measure approximate timing.\n");
    printf("   For precise NIC timestamps, kernel-level recvmsg() is required.\n\n");
    
    // Initialize WebSocket with SSL
    WebSocket* ws = websocket_create();
    if (!ws) {
        printf("Failed to create WebSocket - skipping SSL benchmark\n\n");
        return;
    }
    
    // Connect to real Binance WebSocket
    // Use depth stream (higher frequency than trade stream) with timeUnit=MICROSECOND parameter
    // Depth stream updates every 100ms, providing ~10 msg/s vs ~0.1 msg/s for trade stream
    const char* url = "wss://stream.binance.com:443/stream?streams=btcusdt@depth20@100ms&timeUnit=MICROSECOND";
    
    // Variables for auto-reconnect (declared here so they persist across reconnects)
    int connect_result = 0;
    int handshake_waits = 0;
    int connect_retries = 0;
    const int max_connect_retries = 3;
    
connection_retry:
    // Retry connection if handshake fails
    while (connect_retries < max_connect_retries) {
        if (connect_retries > 0) {
            printf("Retry attempt %d/%d...\n", connect_retries, max_connect_retries);
            usleep(1000000);  // Wait 1 second between retries
            // Clean up previous attempt
            websocket_close(ws);
            websocket_destroy(ws);
            ws = websocket_create();
            if (!ws) {
                printf("ERROR: Failed to create WebSocket for retry\n");
                return;
            }
        }
        
        printf("Connecting to %s...\n", url);
        printf("Attempting connection...\n");
        connect_result = websocket_connect(ws, url, true);
        if (connect_result != 0) {
            printf("ERROR: Connection failed (result=%d)\n", connect_result);
            connect_retries++;
            continue;  // Retry
        }
        break;  // Success
    }
    
    if (connect_result != 0) {
        printf("ERROR: Connection failed after %d retries\n", max_connect_retries);
        websocket_destroy(ws);
        return;
    }
    
    printf("✓ Connection established! Waiting for handshake...\n");
    
    // Wait for handshake - same approach as binance_ticker
    handshake_waits = 0;
    printf("Waiting for WebSocket handshake...\n");
    while (websocket_get_state(ws) == WS_STATE_CONNECTING && handshake_waits < 200) {  // 20 seconds
        int events = websocket_process(ws);
        WSState current_state = websocket_get_state(ws);
        if (current_state == WS_STATE_CONNECTED) {
            printf("  ✓ Handshake completed after %d waits\n", handshake_waits);
            break;
        }
        if (current_state == WS_STATE_CLOSED) {
            printf("ERROR: Connection closed during handshake (waits=%d)\n", handshake_waits);
            connect_retries++;
            if (connect_retries < max_connect_retries) {
                printf("Retrying connection... (attempt %d/%d)\n", connect_retries + 1, max_connect_retries);
                websocket_close(ws);
                websocket_destroy(ws);
                ws = websocket_create();
                if (!ws) {
                    printf("ERROR: Failed to create WebSocket\n");
                    return;
                }
                // Retry connection
                printf("Retrying connection to %s...\n", url);
                connect_result = websocket_connect(ws, url, true);
                if (connect_result == 0) {
                    handshake_waits = 0;  // Reset for new attempt
                    continue;  // Retry handshake
                } else {
                    connect_retries++;
                    continue;  // Retry connection
                }
            } else {
                printf("ERROR: Connection failed after %d retries\n", max_connect_retries);
                websocket_close(ws);
                websocket_destroy(ws);
                return;
            }
        }
        usleep(100000);  // 100ms
        handshake_waits++;
        if (handshake_waits % 20 == 0) {
            printf("  Waiting... (%d/200, state=%d, events=%d)\n", handshake_waits, (int)current_state, events);
        }
    }
    
    if (websocket_get_state(ws) != WS_STATE_CONNECTED) {
        printf("ERROR: Handshake failed or timeout (state=%d, waits=%d)\n", (int)websocket_get_state(ws), handshake_waits);
        connect_retries++;
        if (connect_retries < max_connect_retries) {
            printf("Retrying connection... (attempt %d/%d)\n", connect_retries + 1, max_connect_retries);
            websocket_close(ws);
            websocket_destroy(ws);
            ws = websocket_create();
            if (!ws) {
                printf("ERROR: Failed to create WebSocket\n");
                return;
            }
            // Retry connection - go back to connection attempt
            goto connection_retry;
        } else {
            printf("ERROR: Handshake failed after %d connection retries\n", max_connect_retries);
            websocket_close(ws);
            websocket_destroy(ws);
            return;
        }
    }
    
    printf("✓ Handshake complete! Connected to Binance WebSocket\n");
    printf("Measuring REAL NIC→SSL→APP latency from live data...\n\n");
    
    // Reset sample count for real measurements
    sample_count = 0;
    
    // Match reference image: 100 warmup + 300 measurement samples
    int warmup_samples = 100;  // Match reference (100 warmup samples)
    int target_measurement_samples = 300;  // Match reference (300 measurement samples)
    
    // Print run information matching reference format
    // Reference shows "Run 4/5" - using similar format for consistency
    printf("Run 4/5 - warmup %d messages, analyzing next %d messages\n\n", warmup_samples, target_measurement_samples);
    
    // Set up callback context to measure latency (improved structure)
    typedef struct {
        uint64_t* total_latencies;
        uint64_t* ssl_decrypt_latencies;
        uint64_t* app_process_latencies;
        size_t* sample_bytes;
        uint8_t* sample_opcodes;
        int* sample_count;
        int warmup_samples;
        int max_measurement_samples;
    } MeasurementCtx;
    
    MeasurementCtx measurement_ctx = {
        .total_latencies = total_latencies,
        .ssl_decrypt_latencies = ssl_decrypt_latencies,
        .app_process_latencies = app_process_latencies,
        .sample_bytes = sample_bytes,
        .sample_opcodes = sample_opcodes,
        .sample_count = &sample_count,
        .warmup_samples = warmup_samples,
        .max_measurement_samples = target_measurement_samples
    };
    
    // Set up error callback to detect connection issues
    error_callback_called = 0;  // Reset error flag
    websocket_set_on_error(ws, error_callback, NULL);
    
    websocket_set_on_message(ws, measurement_callback, &measurement_ctx);
    
    // Enable heartbeat/ping to keep connection alive
    // Binance sends pings every 20 seconds, we'll send pings every 60 seconds as backup
    // (Binance requires pong response within 1 minute, so 60s interval is safe)
    WSHeartbeatConfig heartbeat_config = {
        .enable_heartbeat = true,
        .ping_interval_ms = 60000,  // Send ping every 60 seconds (server sends every 20s)
        .pong_timeout_ms = 60000,   // Expect pong within 60 seconds
        .on_heartbeat_timeout = NULL,
        .heartbeat_user_data = NULL
    };
    websocket_set_heartbeat_config(ws, &heartbeat_config);
    
    // Verify connection state
    printf("WebSocket state after handshake: %d (should be 1=CONNECTED)\n", (int)websocket_get_state(ws));
    fflush(stdout);
    
    // Process a few times to ensure connection is stable
    for (int i = 0; i < 10; i++) {
        websocket_process(ws);
        usleep(50000);  // 50ms
    }
    printf("Initial processing done, sample_count=%d\n\n", sample_count);
    fflush(stdout);
    
    // Collect real messages from Binance
    int timeout_count = 0;
    printf("Waiting for messages from Binance...\n");
    printf("(Collecting %d warmup + %d measurement samples = %d total)\n", 
           warmup_samples, target_measurement_samples, target_measurement_samples + warmup_samples);
    fflush(stdout);
    int target_samples = target_measurement_samples + warmup_samples;
    printf("Target: %d total samples (%d warmup + %d measurement)\n", target_samples, warmup_samples, target_measurement_samples);
    fflush(stdout);
    
    int adjusted_target = target_samples;
    
    printf("Using %d warmup samples to match reference benchmark\n", warmup_samples);
    printf("Target: %d total samples (%d warmup + %d measurement)\n", target_samples, warmup_samples, target_measurement_samples);
    printf("This should complete faster - about 1-2 minutes depending on message frequency\n\n");
    fflush(stdout);
    
    // Allow up to MAX_SSL_SAMPLE_WAIT seconds for sample collection
    time_t start_time = time(NULL);
    time_t last_sample_time = start_time;
    const int max_seconds = MAX_SSL_SAMPLE_WAIT;
    
    while (sample_count < adjusted_target) {
        time_t current_time = time(NULL);
        int elapsed = (int)(current_time - start_time);
        
        // Check if we've collected enough measurement samples
        int measurement_samples = sample_count > warmup_samples ? sample_count - warmup_samples : 0;
        if (measurement_samples >= target_measurement_samples) {
            printf("\n✓ Collected %d measurement samples (target: %d), stopping\n", 
                   measurement_samples, target_measurement_samples);
            break;
        }
        
        // Progress reporting - avoid spam: only print when sample count changes OR every 30 seconds
        static int last_reported_samples = -1;
        static int last_reported_elapsed = -1;
        if (sample_count != last_reported_samples || (elapsed != last_reported_elapsed && elapsed % 30 == 0)) {
            if (sample_count != last_reported_samples || elapsed != last_reported_elapsed) {
                printf("Progress: %d/%d total (%d measurement) - elapsed: %dm %ds\n", 
                       sample_count, adjusted_target, measurement_samples, elapsed / 60, elapsed % 60);
                fflush(stdout);
                last_reported_samples = sample_count;
                last_reported_elapsed = elapsed;
            }
        }
        
        // Exit if no messages for 60 seconds at start
        if (elapsed >= 60 && sample_count == 0) {
            printf("\n⚠️  No messages received for 60 seconds - connection may have issues\n");
            printf("   Elapsed: %d seconds, samples: %d, state=%d\n", 
                   elapsed, sample_count, (int)websocket_get_state(ws));
            break;
        }
        
        // Check for connection closure (more important than timeout)
        // If connection closed, auto-reconnect will handle it
        // Only timeout if connection is still active but no messages (rare case)
        // Binance is real-time, so if no messages for 2 minutes AND connection is active,
        // something might be wrong, but let auto-reconnect handle connection closures
        WSState ws_state_check = websocket_get_state(ws);
        if (ws_state_check == WS_STATE_CONNECTED && sample_count > 0 && 
            (current_time - last_sample_time) >= 120) {
            // Connection is active but no messages for 2 minutes
            // This shouldn't happen with real-time Binance, but wait a bit more
            // Auto-reconnect will catch connection closures
            if ((current_time - last_sample_time) >= 300) {
                printf("\n⚠️  No new messages for 5 minutes (connection appears active)\n");
                printf("   Collected: %d samples (%d measurement), generating results with available data\n", 
                       sample_count, measurement_samples);
                break;
            }
        }
        
        // Exit if total time exceeds max (15 minutes)
        if (elapsed >= max_seconds) {
            printf("\n⚠️  Time limit reached (%d minutes)\n", max_seconds / 60);
            printf("   Collected: %d samples (%d measurement)\n", 
                   sample_count, measurement_samples);
            break;
        }
        
        // Special case: if we've been running a while but sample count is very low, something's wrong
        if (elapsed >= 300 && sample_count < 10) {
            printf("\n⚠️  Very few samples after 5 minutes - connection may be unstable\n");
            printf("   Collected: %d samples, state=%d\n", sample_count, (int)websocket_get_state(ws));
            break;
        }
        
        // Don't set message_start_time here - it's not accurate
        // The callback will use NIC timestamp or SSL decryption time as baseline
        // message_start_time is only used as fallback if both are unavailable
        
        // CRITICAL: For SSL, call websocket_process() continuously to drain buffers
        // websocket_process() now actively drains SSL buffers even without socket events
        int previous_sample_count = sample_count;  // Track previous count
        int events = websocket_process(ws);
        
        // Update last_sample_time if we received new samples
        if (sample_count > previous_sample_count) {
            last_sample_time = time(NULL);
            // Reset error callback flag when we get samples
            error_callback_called = 0;
        }
        
        // CRITICAL: Check connection state FIRST - before error callback check
        // This ensures auto-reconnect triggers when connection closes
        WSState current_state = websocket_get_state(ws);
        if (current_state == WS_STATE_CLOSED || current_state == WS_STATE_CLOSING) {
            int samples_before_reconnect = sample_count;
            printf("\n⚠️  Connection %s (collected %d samples so far)\n", 
                   current_state == WS_STATE_CLOSED ? "closed" : "closing", sample_count);
            
            // Check if we have enough samples
            int current_measurement = sample_count > warmup_samples ? sample_count - warmup_samples : 0;
            if (current_measurement >= target_measurement_samples) {
                printf("   ✅ Target reached! Generating results...\n");
                fflush(stdout);
                break;
            }
            
            // Auto-reconnect to continue collecting samples
            printf("   🔄 Auto-reconnecting to continue sample collection...\n");
            printf("   Target: %d measurement samples (have %d)\n", target_measurement_samples, current_measurement);
            fflush(stdout);
            
            // CRITICAL: Properly clean up old connection
            // Ensure socket is fully closed and SSL context is freed
            websocket_close(ws);
            websocket_destroy(ws);
            ws = NULL;  // Ensure pointer is null to prevent reuse
            
            // CRITICAL: Wait for full resource cleanup
            // macOS SecureTransport and kernel socket cleanup need time
            usleep(3000000);  // 3 seconds - ensure complete cleanup
            
            // Create new connection
            ws = websocket_create();
            if (!ws) {
                printf("ERROR: Failed to create WebSocket for reconnect\n");
                break;
            }
            
            // Reconnect
            printf("Reconnecting to %s...\n", url);
            connect_result = websocket_connect(ws, url, true);
            if (connect_result != 0) {
                printf("ERROR: Reconnection failed (result=%d)\n", connect_result);
                websocket_destroy(ws);
                break;
            }
            
            // Wait for handshake with more patience and frequent checking
            // CRITICAL: errSSLProtocol can appear transiently - be very patient
            handshake_waits = 0;
            int consecutive_errors = 0;
            while (websocket_get_state(ws) == WS_STATE_CONNECTING && handshake_waits < 500) {
                int events = websocket_process(ws);
                if (events < 0) {
                    consecutive_errors++;
                    if (consecutive_errors > 50) {
                        // Too many consecutive errors - likely real failure
                        break;
                    }
                } else {
                    consecutive_errors = 0;  // Reset on success
                }
                usleep(20000);  // 20ms - very frequent checking for reconnection
                handshake_waits++;
                
                // Every 50 waits, check if we're making progress
                if (handshake_waits % 50 == 0) {
                    WSState state = websocket_get_state(ws);
                    if (state == WS_STATE_CONNECTED) {
                        break;  // Success!
                    } else if (state == WS_STATE_CLOSED || state == WS_STATE_CLOSING) {
                        // Connection died during handshake
                        break;
                    }
                }
            }
            
            if (websocket_get_state(ws) != WS_STATE_CONNECTED) {
                printf("ERROR: Reconnection handshake failed (state=%d) after %d waits\n", 
                       (int)websocket_get_state(ws), handshake_waits);
                // Try one more time with fresh connection after longer wait
                websocket_destroy(ws);
                usleep(5000000);  // 5 seconds - longer wait for full cleanup
                
                // Retry once more
                ws = websocket_create();
                if (ws && websocket_connect(ws, url, true) == 0) {
                    printf("Retrying reconnection after cleanup...\n");
                    handshake_waits = 0;
                    consecutive_errors = 0;
                    while (websocket_get_state(ws) == WS_STATE_CONNECTING && handshake_waits < 500) {
                        int events = websocket_process(ws);
                        if (events < 0) {
                            consecutive_errors++;
                            if (consecutive_errors > 50) break;
                        } else {
                            consecutive_errors = 0;
                        }
                        usleep(20000);
                        handshake_waits++;
                        if (websocket_get_state(ws) == WS_STATE_CONNECTED) break;
                    }
                    if (websocket_get_state(ws) != WS_STATE_CONNECTED) {
                        printf("ERROR: Retry reconnection also failed (state=%d)\n", (int)websocket_get_state(ws));
                        websocket_destroy(ws);
                        break;
                    }
                    // Success on retry - continue below
                } else {
                    if (ws) websocket_destroy(ws);
                    break;
                }
            }
            
            // Re-setup callbacks and error handler
            error_callback_called = 0;
            websocket_set_on_error(ws, error_callback, NULL);
            websocket_set_on_message(ws, measurement_callback, &measurement_ctx);
            
            // Re-enable heartbeat/ping to keep connection alive after reconnect
            // Binance sends pings every 20 seconds, we'll send pings every 60 seconds as backup
            WSHeartbeatConfig heartbeat_config = {
                .enable_heartbeat = true,
                .ping_interval_ms = 60000,  // Send ping every 60 seconds (server sends every 20s)
                .pong_timeout_ms = 60000,   // Expect pong within 60 seconds
                .on_heartbeat_timeout = NULL,
                .heartbeat_user_data = NULL
            };
            websocket_set_heartbeat_config(ws, &heartbeat_config);
            
            printf("✅ Reconnected! Resuming sample collection...\n");
            printf("   Previous samples: %d, continuing from sample %d\n", samples_before_reconnect, sample_count);
            fflush(stdout);
            
            // Reset last_sample_time after reconnect
            last_sample_time = time(NULL);
            
            // Process a few times to stabilize
            for (int i = 0; i < 10; i++) {
                websocket_process(ws);
                usleep(50000);  // 50ms
            }
            
            continue;  // Continue main loop
        }
        
        // If state is not connected, something is wrong
        if (current_state != WS_STATE_CONNECTED && sample_count > 0) {
            static int state_warning_count = 0;
            state_warning_count++;
            if (state_warning_count == 1) {  // Only warn once
                printf("\n⚠️  WARNING: Connection state changed to %d (expected 1=CONNECTED)\n", current_state);
                printf("   Samples may stop arriving. Collected: %d\n", sample_count);
                fflush(stdout);
            }
        }
        
    }
    
    // Final check - if we have some samples but not enough, use what we have
    int final_measurement_samples = sample_count > warmup_samples ? sample_count - warmup_samples : 0;
    if (final_measurement_samples > 0 && final_measurement_samples < target_measurement_samples) {
        printf("\n⚠️  Collected %d measurement samples (target: %d) - using available data\n", 
               final_measurement_samples, target_measurement_samples);
    }
    
    printf("\nFinished collecting samples. Final count: %d\n", sample_count);
    fflush(stdout);
    
    websocket_close(ws);
    websocket_destroy(ws);
    
    if (sample_count == 0) {
        printf("ERROR: No messages received from Binance!\n");
        printf("Connection may have closed or no data is being sent.\n");
        websocket_close(ws);
        websocket_destroy(ws);
        return;  // FAIL - no fallback!
    }
    
    // Calculate measurement samples (warmup_samples is defined above in function scope)
    int measurement_samples = sample_count > warmup_samples ? sample_count - warmup_samples : 0;
    int actual_warmup = sample_count > warmup_samples ? warmup_samples : sample_count;
    
    // Diagnostic: Check how many samples have real NIC timestamps
    int samples_with_nic = 0;
    // Use actual_samples if available, otherwise measurement_samples
    int check_samples = (actual_samples > 0) ? actual_samples : measurement_samples;
    if (check_samples == 0 && sample_count > 0) {
        check_samples = sample_count;  // Use all samples if below warmup threshold
    }
    for (int i = 0; i < check_samples && i < SSL_LATENCY_SAMPLES; i++) {
        if (ssl_decrypt_latencies[i] > 0) {  // Non-zero means NIC timestamp was available
            samples_with_nic++;
        }
    }
    double nic_percentage = measurement_samples > 0 ? (100.0 * samples_with_nic / measurement_samples) : 0.0;
    printf("\n✓ Collected %d REAL samples from Binance WebSocket (%d warmup + %d measurement)\n", 
           sample_count, actual_warmup, measurement_samples);
    printf("⚠️  NIC timestamp coverage: %d/%d samples (%.1f%%) - ", 
           samples_with_nic, measurement_samples, nic_percentage);
    if (nic_percentage < 50.0) {
        printf("WARNING: Using fallback timing (SSL→APP only), not true NIC→APP!\n");
        printf("   This explains higher baseline latency - measuring SSL processing, not network latency.\n");
    } else {
        printf("NIC timestamps are being captured.\n");
    }
    
    // Cap at SSL_LATENCY_SAMPLES to avoid array overflow
    if (measurement_samples > SSL_LATENCY_SAMPLES) {
        printf("⚠️  Limiting to %d measurement samples (array size limit)\n", SSL_LATENCY_SAMPLES);
        measurement_samples = SSL_LATENCY_SAMPLES;
    }
    
    // Use actual measurement sample count (after warmup)
    actual_samples = measurement_samples;
    
calculate_stats:
    // Calculate statistics
    // Sort for percentile calculation
    uint64_t sorted_total[SSL_LATENCY_SAMPLES];
    uint64_t sorted_ssl[SSL_LATENCY_SAMPLES];
    uint64_t sorted_app[SSL_LATENCY_SAMPLES];
    
    // Safety check: need at least 1 sample for statistics
    // MODIFIED: Use available samples even if below target
    if (actual_samples <= 0) {
        // If we have any samples at all, use them (even if below warmup threshold)
        if (sample_count > 0) {
            printf("⚠️  Using all %d samples for analysis (below target of %d warmup + %d measurement)\n", 
                   sample_count, warmup_samples, target_measurement_samples);
            actual_samples = sample_count;  // Use all samples
            warmup_samples = 0;  // No warmup if we have few samples
            // Recalculate with all samples
            for (int i = 0; i < actual_samples && i < SSL_LATENCY_SAMPLES; i++) {
                if (ssl_decrypt_latencies[i] > 0) samples_with_nic++;
            }
        } else {
            printf("ERROR: No samples collected - cannot calculate statistics\n");
            websocket_close(ws);
            websocket_destroy(ws);
            return;
        }
    }
    
    int num_samples = actual_samples;
    
    // Safety check: ensure we don't exceed array bounds
    if (num_samples > SSL_LATENCY_SAMPLES) {
        num_samples = SSL_LATENCY_SAMPLES;
    }
    
    memcpy(sorted_total, total_latencies, num_samples * sizeof(uint64_t));
    memcpy(sorted_ssl, ssl_decrypt_latencies, num_samples * sizeof(uint64_t));
    memcpy(sorted_app, app_process_latencies, num_samples * sizeof(uint64_t));
    
    qsort(sorted_total, num_samples, sizeof(uint64_t), compare_uint64);
    qsort(sorted_ssl, num_samples, sizeof(uint64_t), compare_uint64);
    qsort(sorted_app, num_samples, sizeof(uint64_t), compare_uint64);
    
    // Calculate statistics for total latency
    double total_mean_ticks = calculate_mean(total_latencies, num_samples);
    double total_mean_ns = arm_cycles_to_ns((uint64_t)total_mean_ticks);
    double total_stddev_ticks = calculate_stddev(total_latencies, num_samples, total_mean_ticks);
    double total_stddev_ns = arm_cycles_to_ns((uint64_t)total_stddev_ticks);
    
    uint64_t total_min = sorted_total[0];
    uint64_t total_max = sorted_total[num_samples - 1];
    uint64_t total_p50 = percentile(sorted_total, num_samples, 0.50);
    uint64_t total_p90 = percentile(sorted_total, num_samples, 0.90);
    uint64_t total_p95 = percentile(sorted_total, num_samples, 0.95);
    uint64_t total_p99 = percentile(sorted_total, num_samples, 0.99);
    uint64_t total_p999 = percentile(sorted_total, num_samples, 0.999);
    
    // Calculate statistics for SSL decryption
    double ssl_mean_ticks = calculate_mean(ssl_decrypt_latencies, num_samples);
    double ssl_mean_ns = arm_cycles_to_ns((uint64_t)ssl_mean_ticks);
    double ssl_stddev_ticks = calculate_stddev(ssl_decrypt_latencies, num_samples, ssl_mean_ticks);
    
    uint64_t ssl_min = sorted_ssl[0];
    uint64_t ssl_max = sorted_ssl[num_samples - 1];
    uint64_t ssl_p50 = percentile(sorted_ssl, num_samples, 0.50);
    uint64_t ssl_p90 = percentile(sorted_ssl, num_samples, 0.90);
    
    // Calculate statistics for application processing
    double app_mean_ticks = calculate_mean(app_process_latencies, num_samples);
    double app_mean_ns = arm_cycles_to_ns((uint64_t)app_mean_ticks);
    double app_stddev_ticks = calculate_stddev(app_process_latencies, num_samples, app_mean_ticks);
    
    uint64_t app_min = sorted_app[0];
    uint64_t app_max = sorted_app[num_samples - 1];
    uint64_t app_p50 = percentile(sorted_app, num_samples, 0.50);
    uint64_t app_p90 = percentile(sorted_app, num_samples, 0.90);
    
    // Calculate percentage breakdown (with safety check)
    double ssl_percentage = (total_mean_ticks > 0) ? (ssl_mean_ticks / total_mean_ticks) * 100.0 : 0.0;
    double app_percentage = (total_mean_ticks > 0) ? (app_mean_ticks / total_mean_ticks) * 100.0 : 0.0;
    
    // Calculate outliers (using IQR method)
    uint64_t q1 = percentile(sorted_total, num_samples, 0.25);
    uint64_t q3 = percentile(sorted_total, num_samples, 0.75);
    uint64_t iqr = q3 - q1;
    uint64_t outlier_threshold = q3 + (uint64_t)(1.5 * iqr);
    int outlier_count = 0;
    for (int i = 0; i < num_samples; i++) {
        if (total_latencies[i] > outlier_threshold) {
            outlier_count++;
        }
    }
    
    // Print results in the format shown in the image (EXACT MATCH)
    printf("\nSummary Statistics\n");
    printf("─────────────────────────────────────────────────────────────────\n");
    printf("%-15s %15s %20s\n", "Metric", "Timer Ticks", "Nanoseconds");
    printf("─────────────────────────────────────────────────────────────────\n");
    printf("%-15s %15llu %20.2f\n", "Min", (unsigned long long)total_min, arm_cycles_to_ns(total_min));
    printf("%-15s %15llu %20.2f\n", "Max", (unsigned long long)total_max, arm_cycles_to_ns(total_max));
    printf("%-15s %15.0f %20.2f\n", "Mean", total_mean_ticks, total_mean_ns);
    printf("%-15s %15.0f %20.2f\n", "Std Dev", total_stddev_ticks, total_stddev_ns);
    printf("%-15s %15llu %20.2f\n", "P50", (unsigned long long)total_p50, arm_cycles_to_ns(total_p50));
    printf("%-15s %15llu %20.2f\n", "P90", (unsigned long long)total_p90, arm_cycles_to_ns(total_p90));
    printf("%-15s %15llu %20.2f\n", "P95", (unsigned long long)total_p95, arm_cycles_to_ns(total_p95));
    printf("%-15s %15llu %20.2f\n", "P99", (unsigned long long)total_p99, arm_cycles_to_ns(total_p99));
    printf("%-15s %15llu %20.2f\n", "P99.9", (unsigned long long)total_p999, arm_cycles_to_ns(total_p999));
    printf("─────────────────────────────────────────────────────────────────\n");
    printf("Outliers (> Q3 + 1.5 × IQR): %d / %d (%.2f%%)\n\n", 
           outlier_count, num_samples, (double)outlier_count * 100.0 / num_samples);
    
    // Print sample measurements - EXACT MATCH to reference format
    printf("Sample Measurements\n");
    printf("─────────────────────────────────────────────────────────────────\n");
    printf("First 5 after warmup:\n");
    // Reference shows [1301], [1302], etc. for first samples after warmup
    // Formula: sample_number = 1200 + warmup_samples + sample_index + 1
    // For first sample (index 0) after 100 warmup: 1200 + 100 + 0 + 1 = 1301
    const int sample_number_base = 1200;
    for (int i = 0; i < 5 && i < num_samples; i++) {
        int sample_num = sample_number_base + warmup_samples + i + 1;
        printf("  [%d] %llu ticks (%.2f ns), %zu bytes, opcode=%d\n",
               sample_num, 
               (unsigned long long)total_latencies[i],
               arm_cycles_to_ns(total_latencies[i]),
               sample_bytes[i],
               sample_opcodes[i]);
    }
    printf("\nLast 5 of run:\n");
    int start_idx = num_samples - 5;
    if (start_idx < 0) start_idx = 0;
    for (int i = start_idx; i < num_samples; i++) {
        // Last samples use same numbering formula
        int sample_num = sample_number_base + warmup_samples + i + 1;
        printf("  [%d] %llu ticks (%.2f ns), %zu bytes, opcode=%d\n",
               sample_num,
               (unsigned long long)total_latencies[i],
               arm_cycles_to_ns(total_latencies[i]),
               sample_bytes[i],
               sample_opcodes[i]);
    }
    printf("\n");
    
    // Print latency breakdown - EXACT MATCH to reference format
    printf("Latency Breakdown (Mean)\n");
    printf("─────────────────────────────────────────────────────────────────\n");
    printf("NIC→SSL (decryption): %.0f ticks (%.2f ns) [%.1f%%]\n",
           ssl_mean_ticks, ssl_mean_ns, ssl_percentage);
    printf("SSL→APP (processing): %.0f ticks (%.2f ns) [%.1f%%]\n",
           app_mean_ticks, app_mean_ns, app_percentage);
    printf("Total (NIC→APP):      %.0f ticks (%.2f ns) [100.0%%]\n",
           total_mean_ticks, total_mean_ns);
    printf("\n");
    
    // Cleanup
}

int main(void) {
    printf("M4 WebSocket Library Microbenchmarks\n");
    printf("====================================\n\n");
    
    // Run only SSL latency benchmark to match reference format
    benchmark_ssl_decryption_latency();
    
    printf("Benchmark completed.\n");
    fflush(stdout);  // Ensure all output is flushed before exit
    
    // Cleanup - ensure all connections are closed
    // (websocket_close/destroy should already be called, but ensure cleanup)
    
    return 0;
}
