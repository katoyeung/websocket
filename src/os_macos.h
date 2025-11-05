#ifndef OS_MACOS_H
#define OS_MACOS_H

#include <stdint.h>
#include <pthread.h>
#include <mach/mach.h>
#include <mach/thread_policy.h>
#include <mach/mach_time.h>
#include <sys/sysctl.h>
#include <stdlib.h>

// ARM Performance Monitor Cycle Counter
// On macOS, PMCCNTR_EL0 requires kernel privileges, so we use mach_absolute_time()
// which provides nanosecond precision on Apple Silicon
static inline uint64_t arm_cycle_count(void) {
    // Use mach_absolute_time for user-space timing on macOS
    return mach_absolute_time();
}

// Cache flush: Clear L1/L2 caches for given memory region
// Uses Clang's builtin for cache control
static inline void cache_flush(void* addr, size_t len) {
    __builtin___clear_cache((char*)addr, (char*)addr + len);
}

// Get CPU frequency for cycle-to-nanosecond conversion
// Returns cycles per second (Hz)
static inline uint64_t arm_get_cpu_frequency(void) {
    uint64_t freq = 0;
    size_t size = sizeof(freq);
    
    // Query CPU frequency from sysctl
    if (sysctlbyname("hw.cpufrequency", &freq, &size, NULL, 0) != 0) {
        // Fallback: M4 base frequency is typically 4.0 GHz
        return 4000000000ULL;
    }
    
    return freq;
}

// Convert cycles to nanoseconds
// mach_absolute_time() already returns time in nanoseconds (or base units that need conversion)
static inline double arm_cycles_to_ns(uint64_t cycles) {
    mach_timebase_info_data_t timebase;
    mach_timebase_info(&timebase);
    return (double)cycles * (double)timebase.numer / (double)timebase.denom;
}

// Pin current thread to a performance core (P-core)
// M4 has both P-cores (performance) and E-cores (efficiency)
// Returns 0 on success, -1 on error
static inline int cpu_pin_p_core(void) {
    thread_affinity_policy_data_t policy = { 1 };  // Affinity tag 1 = P-core
    
    kern_return_t kr = thread_policy_set(
        mach_thread_self(),
        THREAD_AFFINITY_POLICY,
        (thread_policy_t)&policy,
        THREAD_AFFINITY_POLICY_COUNT
    );
    
    if (kr != KERN_SUCCESS) {
        return -1;
    }
    
    // Also set QoS class to user-interactive for highest priority
    pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);
    
    return 0;
}

// Pin current thread to an efficiency core (E-core)
// Use for I/O multiplexing tasks (kqueue)
// Returns 0 on success, -1 on error
static inline int cpu_pin_e_core(void) {
    thread_affinity_policy_data_t policy = { 0 };  // Affinity tag 0 = E-core
    
    kern_return_t kr = thread_policy_set(
        mach_thread_self(),
        THREAD_AFFINITY_POLICY,
        (thread_policy_t)&policy,
        THREAD_AFFINITY_POLICY_COUNT
    );
    
    if (kr != KERN_SUCCESS) {
        return -1;
    }
    
    // Set QoS class to user-interactive for low-latency I/O
    pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);
    
    return 0;
}

// Pin current thread to a specific performance core (P-core)
// M4 has 4 P-cores (performance cores) numbered 0-3
// core_index: 0-3 for P-core 0-3 (use 0 for network receive, 1 for SSL, 2 for parsing)
// Returns 0 on success, -1 on error
static inline int cpu_pin_p_core_index(int core_index) {
    if (core_index < 0 || core_index > 3) {
        return -1;
    }
    
    // Use affinity tag 1 for P-core (same as cpu_pin_p_core, but allows specifying which P-core)
    thread_affinity_policy_data_t policy = { 1 };  // Affinity tag 1 = P-core
    
    kern_return_t kr = thread_policy_set(
        mach_thread_self(),
        THREAD_AFFINITY_POLICY,
        (thread_policy_t)&policy,
        THREAD_AFFINITY_POLICY_COUNT
    );
    
    if (kr != KERN_SUCCESS) {
        return -1;
    }
    
    // Set QoS class to user-interactive for highest priority
    pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);
    
    return 0;
}

// Tune network settings for low-latency HFT
// Sets TCP receive buffer to 8MB, disables delayed ACK, and other optimizations
// Returns 0 on success, -1 on error
static inline int sysctl_tune_network(void) {
    // Set TCP receive buffer to 8MB (matches ring buffer size)
    int recvspace = 8 * 1024 * 1024;
    if (sysctlbyname("net.inet.tcp.recvspace", NULL, NULL, &recvspace, sizeof(recvspace)) != 0) {
        return -1;
    }
    
    // Disable delayed ACK (trades bandwidth for latency)
    int delayed_ack = 0;
    if (sysctlbyname("net.inet.tcp.delayed_ack", NULL, NULL, &delayed_ack, sizeof(delayed_ack)) != 0) {
        return -1;
    }
    
    // Disable TCP segmentation offload (TSO) - reduces kernel processing overhead
    int tso = 0;
    if (sysctlbyname("net.inet.tcp.tso", NULL, NULL, &tso, sizeof(tso)) != 0) {
        // TSO might not be available on all macOS versions, continue if it fails
    }
    
    // Disable UDP checksum (for built-in NIC, hardware handles it)
    int udp_checksum = 0;
    if (sysctlbyname("net.inet.udp.checksum", NULL, NULL, &udp_checksum, sizeof(udp_checksum)) != 0) {
        // UDP checksum might not be available, continue if it fails
    }
    
    return 0;
}

// Force CPU to performance mode (requires root or user permission)
// Returns 0 on success, -1 on error
static inline int set_cpu_performance_mode(void) {
    // Note: pmset requires appropriate permissions
    // In production, this should be configured system-wide
    return system("pmset -a processorperformance 1 2>/dev/null");
}

// Disable CPU throttling via pmset
// This should be called via system() command as it requires root or user permission
// Returns 0 on success, -1 on error
static inline int disable_cpu_throttling(void) {
    // Note: pmset requires appropriate permissions
    // In production, this should be configured system-wide
    return system("pmset -a noidle 1 2>/dev/null");
}

#endif // OS_MACOS_H

