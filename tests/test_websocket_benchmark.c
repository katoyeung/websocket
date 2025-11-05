/**
 * @file test_websocket_benchmark.c
 * @brief Performance benchmark test for websocket_hft library using Binance WebSocket
 * 
 * This benchmark measures the same metrics as the libwebsockets benchmark:
 * - Message throughput (messages/second)
 * - Latency distribution (min, max, avg, p50, p95, p99)
 * - Memory usage
 * - Connection stability
 * - Data throughput (bytes/second)
 * 
 * Metrics are designed to be comparable with libwebsockets and other websocket libraries.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <signal.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <time.h>
#include <math.h>
#include <pthread.h>
#include <mach/mach_time.h>
#include "../src/websocket.h"

// Comparison function for qsort
static int compare_double(const void* a, const void* b) {
    double da = *(const double*)a;
    double db = *(const double*)b;
    if (da < db) return -1;
    if (da > db) return 1;
    return 0;
}

// Statistics collection
typedef struct {
    uint64_t message_count;
    uint64_t byte_count;
    uint64_t connection_errors;
    uint64_t reconnect_count;
    
    double* latencies;  // Latency in microseconds
    size_t latency_count;
    size_t latency_capacity;
    pthread_mutex_t latencies_mutex;
    
    struct timeval start_time;
    struct timeval last_message_time;
    
    uint64_t last_message_count;
    double last_throughput;
    
    size_t initial_memory;
    size_t peak_memory;
} BenchmarkStats;

static BenchmarkStats g_stats = {0};
static volatile bool g_running = true;
static WebSocket* g_ws = NULL;
static char* g_connection_url = NULL;  // Store URL for reconnection

// Signal handler
void signal_handler(int sig) {
    (void)sig;
    g_running = false;
}

// Calculate percentiles
static void calculate_percentiles(const double* sorted, size_t count,
                                  double* p50, double* p95, double* p99) {
    if (count == 0) {
        *p50 = *p95 = *p99 = 0.0;
        return;
    }
    
    *p50 = sorted[(size_t)(count * 0.50)];
    *p95 = sorted[(size_t)(count * 0.95)];
    *p99 = sorted[(size_t)(count * 0.99)];
}

// Initialize stats
static void stats_init(BenchmarkStats* stats) {
    memset(stats, 0, sizeof(BenchmarkStats));
    stats->latency_capacity = 100000;
    stats->latencies = calloc(stats->latency_capacity, sizeof(double));
    pthread_mutex_init(&stats->latencies_mutex, NULL);
    gettimeofday(&stats->start_time, NULL);
    stats->last_message_time = stats->start_time;
    
    struct rusage usage;
    getrusage(RUSAGE_SELF, &usage);
    stats->initial_memory = usage.ru_maxrss * 1024;
}

// Cleanup stats
static void stats_cleanup(BenchmarkStats* stats) {
    if (stats->latencies) {
        free(stats->latencies);
        stats->latencies = NULL;
    }
    pthread_mutex_destroy(&stats->latencies_mutex);
}

// Record latency
static void stats_record_latency(BenchmarkStats* stats, double latency_us) {
    pthread_mutex_lock(&stats->latencies_mutex);
    if (stats->latency_count < stats->latency_capacity) {
        stats->latencies[stats->latency_count++] = latency_us;
    } else {
        // Keep only recent latencies - remove oldest 50%
        size_t keep = stats->latency_capacity / 2;
        memmove(stats->latencies, stats->latencies + keep, 
                (stats->latency_capacity - keep) * sizeof(double));
        stats->latency_count = stats->latency_capacity - keep;
        stats->latencies[stats->latency_count++] = latency_us;
    }
    pthread_mutex_unlock(&stats->latencies_mutex);
}

// Print statistics
static void stats_print(BenchmarkStats* stats) {
    struct timeval now;
    gettimeofday(&now, NULL);
    
    double elapsed = (now.tv_sec - stats->start_time.tv_sec) + 
                     (now.tv_usec - stats->start_time.tv_usec) / 1000000.0;
    
    if (elapsed < 0.1) elapsed = 0.1;
    
    uint64_t msg_count = stats->message_count;
    uint64_t bytes = stats->byte_count;
    
    // Calculate throughput
    double msg_per_sec = (double)msg_count / elapsed;
    double bytes_per_sec = (double)bytes / elapsed;
    
    // Get memory usage
    struct rusage usage;
    getrusage(RUSAGE_SELF, &usage);
    size_t current_memory = usage.ru_maxrss * 1024;
    
    // Calculate latency statistics
    double* sorted_latencies = NULL;
    double min_latency = 0.0, max_latency = 0.0, avg_latency = 0.0;
    double p50_latency = 0.0, p95_latency = 0.0, p99_latency = 0.0;
    size_t latency_count = 0;
    
    pthread_mutex_lock(&stats->latencies_mutex);
    latency_count = stats->latency_count;
    if (latency_count > 0) {
        sorted_latencies = malloc(latency_count * sizeof(double));
        memcpy(sorted_latencies, stats->latencies, latency_count * sizeof(double));
        
        // Sort for percentiles (numeric comparison)
        qsort(sorted_latencies, latency_count, sizeof(double), compare_double);
        
        min_latency = sorted_latencies[0];
        max_latency = sorted_latencies[latency_count - 1];
        
        double sum = 0.0;
        for (size_t i = 0; i < latency_count; i++) {
            sum += sorted_latencies[i];
        }
        avg_latency = sum / latency_count;
        
        calculate_percentiles(sorted_latencies, latency_count, 
                              &p50_latency, &p95_latency, &p99_latency);
    }
    pthread_mutex_unlock(&stats->latencies_mutex);
    
    // Print statistics
    printf("\033[2J\033[H"); // Clear screen and move cursor to top
    printf("╔════════════════════════════════════════════════════════════════════════╗\n");
    printf("║       websocket_hft Performance Benchmark - Binance WebSocket          ║\n");
    printf("╠════════════════════════════════════════════════════════════════════════╣\n");
    printf("║ Runtime: %10.0f seconds", elapsed);
    printf("%*s", (int)(48 - (elapsed >= 100 ? 3 : (elapsed >= 10 ? 2 : 1))), "");
    printf("║\n");
    printf("╠════════════════════════════════════════════════════════════════════════╣\n");
    
    // Throughput metrics
    printf("║ THROUGHPUT METRICS                                                    ║\n");
    printf("║   Messages/sec:     %12.2f msg/s", msg_per_sec);
    printf("%*s", 30, "");
    printf("║\n");
    printf("║   Data throughput:  %12.2f MB/s", bytes_per_sec / 1024.0 / 1024.0);
    printf("%*s", 30, "");
    printf("║\n");
    printf("║   Total messages:   %12llu", (unsigned long long)msg_count);
    printf("%*s", 35, "");
    printf("║\n");
    printf("║   Total bytes:      %12llu MB", (unsigned long long)(bytes / 1024 / 1024));
    printf("%*s", 33, "");
    printf("║\n");
    printf("╠════════════════════════════════════════════════════════════════════════╣\n");
    
    // Latency metrics
    printf("║ LATENCY METRICS (microseconds)                                        ║\n");
    printf("║   Min:              %12.2f μs", min_latency);
    printf("%*s", 30, "");
    printf("║\n");
    printf("║   Max:              %12.2f μs", max_latency);
    printf("%*s", 30, "");
    printf("║\n");
    printf("║   Average:          %12.2f μs", avg_latency);
    printf("%*s", 30, "");
    printf("║\n");
    printf("║   P50 (median):     %12.2f μs", p50_latency);
    printf("%*s", 30, "");
    printf("║\n");
    printf("║   P95:              %12.2f μs", p95_latency);
    printf("%*s", 30, "");
    printf("║\n");
    printf("║   P99:              %12.2f μs", p99_latency);
    printf("%*s", 30, "");
    printf("║\n");
    printf("╠════════════════════════════════════════════════════════════════════════╣\n");
    
    // Connection metrics
    printf("║ CONNECTION METRICS                                                    ║\n");
    printf("║   Connection errors: %10llu", (unsigned long long)stats->connection_errors);
    printf("%*s", 34, "");
    printf("║\n");
    printf("║   Reconnects:        %10llu", (unsigned long long)stats->reconnect_count);
    printf("%*s", 34, "");
    printf("║\n");
    printf("╠════════════════════════════════════════════════════════════════════════╣\n");
    
    // Resource metrics
    printf("║ RESOURCE METRICS                                                     ║\n");
    printf("║   Memory usage:     %12.2f MB", current_memory / 1024.0 / 1024.0);
    printf("%*s", 30, "");
    printf("║\n");
    printf("╠════════════════════════════════════════════════════════════════════════╣\n");
    
    // Diagnostic metrics (for throughput investigation)
    extern WebSocket* g_ws;
    if (g_ws) {
        uint64_t ssl_bytes = 0, ssl_calls = 0, frames_parsed = 0, frames_processed = 0;
        websocket_get_diagnostics(g_ws, &ssl_bytes, &ssl_calls, &frames_parsed, &frames_processed);
        printf("║ DIAGNOSTIC METRICS (for throughput investigation)                 ║\n");
        printf("║   SSL bytes read:      %12llu bytes (%llu KB)", 
               (unsigned long long)ssl_bytes, (unsigned long long)(ssl_bytes / 1024));
        printf("%*s", 20, "");
        printf("║\n");
        printf("║   SSL read calls:     %12llu", (unsigned long long)ssl_calls);
        printf("%*s", 35, "");
        printf("║\n");
        printf("║   Frames parsed:      %12llu", (unsigned long long)frames_parsed);
        printf("%*s", 35, "");
        printf("║\n");
        printf("║   Frames processed:   %12llu", (unsigned long long)frames_processed);
        printf("%*s", 33, "");
        printf("║\n");
        if (ssl_calls > 0) {
            printf("║   Avg bytes/SSL read: %12.2f bytes", (double)ssl_bytes / ssl_calls);
            printf("%*s", 33, "");
            printf("║\n");
        }
        if (frames_processed > 0) {
            printf("║   Parse success rate: %12.2f%%", 100.0 * frames_parsed / frames_processed);
            printf("%*s", 32, "");
            printf("║\n");
        }
        printf("╠════════════════════════════════════════════════════════════════════════╣\n");
    }
    
    // Comparison notes
    printf("║ COMPARISON METRICS (for other websocket libraries)                    ║\n");
    printf("║   • Messages/sec:   Compare with libwebsockets, uWebSockets, etc.     ║\n");
    printf("║   • Latency P99:    Critical for HFT - lower is better               ║\n");
    printf("║   • Memory:         Memory efficiency comparison                      ║\n");
    printf("║   • Stability:      Connection error rate                            ║\n");
    printf("╠════════════════════════════════════════════════════════════════════════╣\n");
    printf("║ Press Ctrl+C to stop and print final statistics                      ║\n");
    printf("╚════════════════════════════════════════════════════════════════════════╝\n");
    
    if (sorted_latencies) {
        free(sorted_latencies);
    }
    
    stats->last_message_count = msg_count;
    stats->last_throughput = msg_per_sec;
}

// Message callback
static void on_message(WebSocket* ws, const uint8_t* data, size_t len, void* user_data) {
    (void)ws;
    (void)user_data;
    
    struct timeval now;
    gettimeofday(&now, NULL);
    
    // Measure TRUE processing latency: time from packet arrival (NIC) to callback
    // This is the actual latency, not inter-message time
    uint64_t nic_timestamp_ns = websocket_get_last_nic_timestamp_ns(ws);
    
    if (nic_timestamp_ns > 0) {
        // Get current time in nanoseconds using mach_absolute_time
        static mach_timebase_info_data_t timebase = {0, 0};
        static bool timebase_inited = false;
        if (!timebase_inited) {
            mach_timebase_info(&timebase);
            timebase_inited = true;
        }
        
        uint64_t now_ticks = mach_absolute_time();
        uint64_t now_ns = (now_ticks * timebase.numer) / timebase.denom;
        
        // Calculate processing latency (packet arrival -> callback)
        if (now_ns > nic_timestamp_ns) {
            uint64_t latency_ns = now_ns - nic_timestamp_ns;
            double latency_us = (double)latency_ns / 1000.0; // Convert to microseconds
            stats_record_latency(&g_stats, latency_us);
        }
    } else {
        // Fallback: use inter-message time if NIC timestamp not available
        // This matches libwebsockets benchmark for fair comparison
        struct timeval last = g_stats.last_message_time;
        double time_since_last = (now.tv_sec - last.tv_sec) * 1000000.0 + 
                                (now.tv_usec - last.tv_usec);
        
        if (g_stats.message_count > 0 && time_since_last > 0) {
            stats_record_latency(&g_stats, time_since_last);
        }
    }
    
    g_stats.message_count++;
    g_stats.byte_count += len;
    g_stats.last_message_time = now;
}

// Error callback - just record the error, reconnection handled in main loop
static void on_error(WebSocket* ws, int error_code, const char* error_msg, void* user_data) {
    (void)ws;
    (void)user_data;
    (void)error_code;
    (void)error_msg;
    
    g_stats.connection_errors++;
    // Note: Reconnection is handled in the main loop, not here, to avoid blocking
}

// Stats thread
static void* stats_thread(void* arg) {
    (void)arg;
    while (g_running) {
        usleep(1000000); // 1 second
        if (g_running) {
            stats_print(&g_stats);
        }
    }
    return NULL;
}

int main(int argc, char** argv) {
    // Parse command line arguments
    const char* symbol = "btcusdt";
    int duration_seconds = 60;
    bool show_help = false;
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--symbol") == 0 || strcmp(argv[i], "-s") == 0) {
            if (i + 1 < argc) {
                symbol = argv[++i];
            }
        } else if (strcmp(argv[i], "--duration") == 0 || strcmp(argv[i], "-d") == 0) {
            if (i + 1 < argc) {
                duration_seconds = atoi(argv[++i]);
            }
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            show_help = true;
        }
    }
    
    if (show_help) {
        printf("Usage: %s [OPTIONS]\n", argv[0]);
        printf("Options:\n");
        printf("  -s, --symbol SYMBOL    Trading symbol (default: btcusdt)\n");
        printf("  -d, --duration SEC     Test duration in seconds (default: 60)\n");
        printf("  -h, --help             Show this help message\n");
        printf("\nExample:\n");
        printf("  %s -s ethusdt -d 120\n", argv[0]);
        return 0;
    }
    
    // Setup signal handler
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Initialize stats
    stats_init(&g_stats);
    
    // Create WebSocket
    g_ws = websocket_create();
    if (!g_ws) {
        fprintf(stderr, "✗ Failed to create WebSocket\n");
        stats_cleanup(&g_stats);
        return 1;
    }
    
    // Build WebSocket URL
    char url[512];
    snprintf(url, sizeof(url), 
             "wss://stream.binance.com:443/stream?streams=%s@trade&timeUnit=MICROSECOND", 
             symbol);
    printf("Connecting to: %s\n", url);
    printf("Starting benchmark for %d seconds...\n", duration_seconds);
    printf("Press Ctrl+C to stop early\n\n");
    
    // Store URL for reconnection
    g_connection_url = strdup(url);
    
    // Set callbacks BEFORE connecting
    websocket_set_on_message(g_ws, on_message, NULL);
    websocket_set_on_error(g_ws, on_error, NULL);
    
    // Enable auto-reconnect
    WSReconnectConfig reconnect_config = {
        .auto_reconnect = true,
        .max_retries = 10,  // Allow up to 10 reconnection attempts
        .initial_backoff_ms = 500,
        .max_backoff_ms = 5000,
        .backoff_multiplier = 2.0,
        .reset_backoff_on_success = true
    };
    websocket_set_reconnect_config(g_ws, &reconnect_config);
    
    // Enable heartbeat to keep connection alive
    // Binance sends ping every 20 seconds, we'll send pings every 30 seconds as backup
    // This ensures connection stays alive even if Binance's pings are delayed
    WSHeartbeatConfig heartbeat_config = {
        .enable_heartbeat = true,
        .ping_interval_ms = 30000,  // Send ping every 30 seconds (Binance sends every 20s)
        .pong_timeout_ms = 60000,   // Expect pong within 60 seconds (Binance requirement)
        .on_heartbeat_timeout = NULL,
        .heartbeat_user_data = NULL
    };
    websocket_set_heartbeat_config(g_ws, &heartbeat_config);
    
    // Connect with retry logic
    int connect_result = -1;
    int connect_retries = 0;
    const int max_connect_retries = 3;
    
    while (connect_retries < max_connect_retries) {
        connect_result = websocket_connect(g_ws, url, true);
        if (connect_result == 0) {
            break;  // Success
        }
        
        connect_retries++;
        if (connect_retries < max_connect_retries) {
            printf("Connection attempt %d failed (result=%d), retrying...\n", connect_retries, connect_result);
            websocket_destroy(g_ws);
            usleep(1000000);  // Wait 1 second before retry
            
            g_ws = websocket_create();
            if (!g_ws) {
                fprintf(stderr, "✗ Failed to create WebSocket instance\n");
                stats_cleanup(&g_stats);
                return 1;
            }
            websocket_set_on_message(g_ws, on_message, NULL);
            websocket_set_on_error(g_ws, on_error, NULL);
        }
    }
    
    if (connect_result != 0) {
        fprintf(stderr, "✗ Failed to connect to %s after %d attempts (result=%d)\n", url, connect_retries, connect_result);
        websocket_destroy(g_ws);
        stats_cleanup(&g_stats);
        return 1;
    }
    
    // Wait for connection (with reconnection support and longer timeout)
    int wait_count = 0;
    int max_waits = 300;  // Increased from 200 to 300 (30 seconds total)
    int reconnect_attempts = 0;
    const int max_reconnect_attempts = 3;  // Allow up to 3 reconnection attempts
    
    while (wait_count < max_waits) {
        WSState state = websocket_get_state(g_ws);
        if (state == WS_STATE_CONNECTED) {
            break;
        }
        
        if (state == WS_STATE_CLOSED && g_ws && reconnect_attempts < max_reconnect_attempts) {
            // Connection failed, try to reconnect with exponential backoff
            reconnect_attempts++;
            int backoff_ms = reconnect_config.initial_backoff_ms * (1 << (reconnect_attempts - 1));
            if (backoff_ms > reconnect_config.max_backoff_ms) {
                backoff_ms = reconnect_config.max_backoff_ms;
            }
            
            printf("Connection failed, retrying in %d ms (attempt %d/%d)...\n", 
                   backoff_ms, reconnect_attempts, max_reconnect_attempts);
            usleep(backoff_ms * 1000);  // Backoff delay
            
            websocket_close(g_ws);
            websocket_destroy(g_ws);
            
            g_ws = websocket_create();
            if (g_ws) {
                websocket_set_on_message(g_ws, on_message, NULL);
                websocket_set_on_error(g_ws, on_error, NULL);
                websocket_set_reconnect_config(g_ws, &reconnect_config);
                websocket_set_heartbeat_config(g_ws, &heartbeat_config);
                connect_result = websocket_connect(g_ws, url, true);
                if (connect_result == 0) {
                    wait_count = 0; // Reset wait counter
                    continue;
                } else {
                    printf("✗ Reconnection attempt %d failed (result=%d)\n", reconnect_attempts, connect_result);
                }
            }
        }
        
        // Process I/O events to drive connection
        websocket_process(g_ws);
        usleep(100000); // 100ms
        wait_count++;
        if (wait_count % 30 == 0) {
            printf("Waiting for connection... (state=%d, wait=%d/%d, reconnect=%d/%d)\n", 
                   (int)websocket_get_state(g_ws), wait_count, max_waits, 
                   reconnect_attempts, max_reconnect_attempts);
        }
    }
    
    if (websocket_get_state(g_ws) != WS_STATE_CONNECTED) {
        fprintf(stderr, "✗ Connection failed or timeout after %d attempts (state=%d)\n", 
                reconnect_attempts + 1, (int)websocket_get_state(g_ws));
        websocket_close(g_ws);
        websocket_destroy(g_ws);
        stats_cleanup(&g_stats);
        return 1;
    }
    
    printf("✓ WebSocket connection established\n");
    gettimeofday(&g_stats.start_time, NULL);
    g_stats.last_message_time = g_stats.start_time;
    
    // Start stats thread
    pthread_t stats_tid;
    pthread_create(&stats_tid, NULL, stats_thread, NULL);
    
    // Main loop - optimized for high throughput
    // CRITICAL: Call websocket_process as frequently as possible for maximum throughput
    // Similar to libwebsockets which calls lws_service in a tight loop
    struct timeval start_time;
    gettimeofday(&start_time, NULL);
    struct timeval end_time = start_time;
    end_time.tv_sec += duration_seconds;
    
    // Cache time check to reduce gettimeofday overhead (check every 1000 iterations)
    int time_check_counter = 0;
    const int TIME_CHECK_INTERVAL = 1000;  // Check time every 1000 iterations
    
    // Batch process counter for connected state
    int batch_counter = 0;
    const int BATCH_SIZE = 10;  // Check state every 10 iterations (balance between overhead and responsiveness)
    
    while (g_running) {
        // Check time less frequently to reduce overhead
        time_check_counter++;
        if (time_check_counter >= TIME_CHECK_INTERVAL) {
            time_check_counter = 0;
            struct timeval now;
            gettimeofday(&now, NULL);
            if (timercmp(&now, &end_time, >=)) {
                g_running = false;
                break;
            }
        }
        
        // Check if connection is still valid and handle reconnection
        // Only check state every BATCH_SIZE iterations to reduce overhead
        batch_counter++;
        if (batch_counter >= BATCH_SIZE || !g_ws) {
            batch_counter = 0;
            WSState current_state = g_ws ? websocket_get_state(g_ws) : WS_STATE_CLOSED;
            
            if (current_state == WS_STATE_CLOSED && g_running && g_connection_url) {
                // Connection closed - attempt to reconnect
                printf("🔄 Connection closed, attempting to reconnect...\n");
                g_stats.reconnect_count++;
                
                // Clean up old connection
                if (g_ws) {
                    websocket_close(g_ws);
                    websocket_destroy(g_ws);
                    g_ws = NULL;
                }
                
                // Small delay before reconnecting
                usleep(500000); // 500ms
                
                // Create new connection
                g_ws = websocket_create();
                if (g_ws) {
                    websocket_set_on_message(g_ws, on_message, NULL);
                    websocket_set_on_error(g_ws, on_error, NULL);
                    
                    // Re-enable auto-reconnect
                    WSReconnectConfig reconnect_config = {
                        .auto_reconnect = true,
                        .max_retries = 10,
                        .initial_backoff_ms = 500,
                        .max_backoff_ms = 5000,
                        .backoff_multiplier = 2.0,
                        .reset_backoff_on_success = true
                    };
                    websocket_set_reconnect_config(g_ws, &reconnect_config);
                    
                    // Re-enable heartbeat
                    WSHeartbeatConfig heartbeat_config = {
                        .enable_heartbeat = true,
                        .ping_interval_ms = 30000,
                        .pong_timeout_ms = 60000,
                        .on_heartbeat_timeout = NULL,
                        .heartbeat_user_data = NULL
                    };
                    websocket_set_heartbeat_config(g_ws, &heartbeat_config);
                    
                    // Attempt to reconnect
                    if (websocket_connect(g_ws, g_connection_url, true) == 0) {
                        // Wait for connection to establish
                        int reconnect_wait = 0;
                        while (reconnect_wait < 100 && websocket_get_state(g_ws) == WS_STATE_CONNECTING) {
                            websocket_process(g_ws);
                            usleep(100000); // 100ms
                            reconnect_wait++;
                        }
                        
                        if (websocket_get_state(g_ws) == WS_STATE_CONNECTED) {
                            printf("✓ Reconnected successfully\n");
                            gettimeofday(&g_stats.last_message_time, NULL); // Reset timing
                        } else {
                            printf("⚠ Reconnection attempt failed (state=%d)\n", 
                                   (int)websocket_get_state(g_ws));
                        }
                    } else {
                        fprintf(stderr, "✗ Failed to initiate reconnection\n");
                    }
                }
                continue; // Continue main loop
            }
            
            if (!g_ws || current_state != WS_STATE_CONNECTED) {
                // Not connected and not attempting reconnect - wait a bit
                if (g_running) {
                    usleep(100000); // 100ms
                    continue;
                } else {
                    break;
                }
            }
        }
        
        // OPTIMIZED LOOP: Call websocket_process continuously for maximum throughput
        // This matches libwebsockets' approach of calling lws_service continuously
        // With 0 timeout kqueue, websocket_process returns immediately
        // Batch process to reduce overhead, but not too many to avoid CPU waste
        
        // ULTRA-OPTIMIZED: Call websocket_process as frequently as possible
        // With 0 timeout kqueue, we can call millions of times per second
        // CRITICAL: For maximum throughput, call websocket_process in a tight loop
        // This ensures we catch all kqueue events immediately and drain SSL aggressively
        // Increased batch size to 500 for even more aggressive processing
        for (int batch = 0; batch < 500; batch++) {
            int events = websocket_process(g_ws);
            if (events < 0) {
                // Error - break from batch but continue main loop
                break;
            }
        }
        
        // No sleep - ultra-tight loop for maximum throughput
        // websocket_process uses non-blocking kqueue (0 timeout) and ultra-aggressive SSL polling
        // This ensures we drain SecureTransport continuously for maximum throughput
    }
    
    // Wait for stats thread
    g_running = false;
    pthread_join(stats_tid, NULL);
    
    // Print final statistics
    printf("\n\n");
    printf("╔════════════════════════════════════════════════════════════════════════╗\n");
    printf("║                      FINAL BENCHMARK STATISTICS                        ║\n");
    printf("╚════════════════════════════════════════════════════════════════════════╝\n");
    stats_print(&g_stats);
    
    // Cleanup
    if (g_ws) {
        websocket_close(g_ws);
        websocket_destroy(g_ws);
    }
    if (g_connection_url) {
        free(g_connection_url);
        g_connection_url = NULL;
    }
    stats_cleanup(&g_stats);
    
    printf("\nBenchmark completed.\n");
    return 0;
}

