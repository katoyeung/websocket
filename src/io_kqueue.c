#include "io_kqueue.h"
#include "os_macos.h"
#include <sys/event.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>

#ifdef __APPLE__
#include <dispatch/dispatch.h>
#endif

int io_init(IOContext* ctx) {
    if (!ctx) {
        return -1;
    }
    
    memset(ctx, 0, sizeof(IOContext));
    
    // Create kqueue
    ctx->kq = kqueue();
    if (ctx->kq == -1) {
        return -1;
    }
    
#ifdef __APPLE__
    // M4 OPTIMIZATION: Create GCD queues with CPU core binding
    // Use Dispatch.framework for optimized CPU scheduling
    
    // I/O queue: Pin to E-core for efficient I/O multiplexing
    if (cpu_pin_e_core() == 0) {
        ctx->e_core_pinned = 1;
    }
    
    // M4 OPTIMIZATION: Create GCD queues with high-priority QoS for optimal CPU scheduling
    // Use dispatch_queue_attr_make_with_qos_class for better performance than set_target_queue
    dispatch_queue_attr_t qos_attr = dispatch_queue_attr_make_with_qos_class(
        DISPATCH_QUEUE_SERIAL, QOS_CLASS_USER_INTERACTIVE, 0);
    
    // I/O operations queue (E-core optimized)
    ctx->io_queue = dispatch_queue_create("com.hft.io", qos_attr);
    
    // Network receive queue (P-core 0 optimized)
    ctx->net_queue = dispatch_queue_create("com.hft.net", qos_attr);
    
    // SSL encryption queue (P-core 1 optimized)
    ctx->ssl_queue = dispatch_queue_create("com.hft.ssl", qos_attr);
    
    // Parsing queue (P-core 2 optimized)
    ctx->parse_queue = dispatch_queue_create("com.hft.parse", qos_attr);
#endif
    
    // Set real-time priority (fallback if GCD not available)
    struct sched_param param = {.sched_priority = 49};
    if (pthread_setschedparam(pthread_self(), SCHED_FIFO, &param) != 0) {
        // Real-time scheduling may require privileges, continue if it fails
        // Silently continue - this is expected if running without privileges
    }
    
    return 0;
}

void io_cleanup(IOContext* ctx) {
    if (!ctx) {
        return;
    }
    
    // Remove all sockets
    for (int i = 0; i < ctx->socket_count; i++) {
        if (ctx->sockets[i].fd != -1) {
            io_remove_socket(ctx, ctx->sockets[i].fd);
        }
    }
    
    if (ctx->kq != -1) {
        close(ctx->kq);
        ctx->kq = -1;
    }
    
#ifdef __APPLE__
    // Release GCD queues
    if (ctx->io_queue) {
        dispatch_release((dispatch_queue_t)ctx->io_queue);
        ctx->io_queue = NULL;
    }
    if (ctx->net_queue) {
        dispatch_release((dispatch_queue_t)ctx->net_queue);
        ctx->net_queue = NULL;
    }
    if (ctx->ssl_queue) {
        dispatch_release((dispatch_queue_t)ctx->ssl_queue);
        ctx->ssl_queue = NULL;
    }
    if (ctx->parse_queue) {
        dispatch_release((dispatch_queue_t)ctx->parse_queue);
        ctx->parse_queue = NULL;
    }
#endif
    
    ctx->socket_count = 0;
}

int io_add_socket(IOContext* ctx, int fd, RingBuffer* rx_ring, RingBuffer* tx_ring, void* user_data) {
    if (!ctx || fd < 0 || ctx->socket_count >= IO_MAX_SOCKETS) {
        return -1;
    }
    
    // Set socket to non-blocking
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        return -1;
    }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        return -1;
    }
    
    // Enable SO_TIMESTAMP_OLD for kernel-level packet timestamps
    int timestamp = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_TIMESTAMP, &timestamp, sizeof(timestamp)) == -1) {
        // SO_TIMESTAMP_OLD might not be available on all macOS versions
        // Try SO_TIMESTAMP as fallback
        setsockopt(fd, SOL_SOCKET, SO_TIMESTAMP, &timestamp, sizeof(timestamp));
    }

    // FUTURE: Enable hardware timestamping if NIC supports it
    // This would require ioctl() calls to configure NIC hardware timestamping
    // and is typically only available on server-grade NICs with PTP support
    
    // Register socket in our array
    int idx = ctx->socket_count++;
    ctx->sockets[idx].fd = fd;
    ctx->sockets[idx].rx_ring = rx_ring;
    ctx->sockets[idx].tx_ring = tx_ring;
    ctx->sockets[idx].user_data = user_data;
    ctx->sockets[idx].last_nic_timestamp_ns = 0;
    ctx->sockets[idx].last_nic_timestamp_ticks = 0;
    
    // Add socket to kqueue with level-triggered flags (not edge-triggered)
    // EV_ONESHOT only fires once per event - we need continuous events for high throughput
    // Use EV_ADD | EV_CLEAR | EV_ENABLE (without EV_ONESHOT) for continuous data flow
    struct kevent ev;
    EV_SET(&ev, fd, EVFILT_READ, EV_ADD | EV_CLEAR | EV_ENABLE, 0, 0, (void*)(intptr_t)idx);
    
    if (kevent(ctx->kq, &ev, 1, NULL, 0, NULL) == -1) {
        ctx->socket_count--;  // Rollback
        return -1;
    }
    
    return idx;
}

int io_remove_socket(IOContext* ctx, int fd) {
    if (!ctx || fd < 0) {
        return -1;
    }
    
    // Find socket index
    int idx = -1;
    for (int i = 0; i < ctx->socket_count; i++) {
        if (ctx->sockets[i].fd == fd) {
            idx = i;
            break;
        }
    }
    
    if (idx == -1) {
        return -1;
    }
    
    // Remove from kqueue
    struct kevent ev;
    EV_SET(&ev, fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
    kevent(ctx->kq, &ev, 1, NULL, 0, NULL);
    
    // Remove from array (swap with last element)
    if (idx < ctx->socket_count - 1) {
        ctx->sockets[idx] = ctx->sockets[ctx->socket_count - 1];
        
        // Update kqueue registration for swapped socket
        int swapped_fd = ctx->sockets[idx].fd;
        EV_SET(&ev, swapped_fd, EVFILT_READ, EV_ADD | EV_CLEAR | EV_ENABLE, 0, 0, (void*)(intptr_t)idx);
        kevent(ctx->kq, &ev, 1, NULL, 0, NULL);
    }
    
    ctx->socket_count--;
    return 0;
}

int io_poll(IOContext* ctx, struct kevent* events, int max_events, int timeout_us) {
    if (!ctx || !events || max_events <= 0) {
        return -1;
    }
    
    // Configure timeout (default 10µs for HFT optimization - balances responsiveness and CPU usage)
    struct timespec timeout;
    if (timeout_us <= 0) {
        // Non-blocking poll
        timeout.tv_sec = 0;
        timeout.tv_nsec = 0;
    } else {
        // Convert microseconds to timespec
        timeout.tv_sec = timeout_us / 1000000;
        timeout.tv_nsec = (timeout_us % 1000000) * 1000;
    }
    
    int n = kevent(ctx->kq, NULL, 0, events, max_events, &timeout);
    
    // Re-enable events (no need for EV_ONESHOT - using level-triggered)
    // Only re-enable if we're using EV_ONESHOT mode (which we're not anymore)
    // Events will fire automatically when socket is readable (level-triggered)
    
    return n;
}

// Helper to convert timespec to nanoseconds (inlined for performance)
static inline uint64_t timespec_to_ns(const struct timespec* ts) {
    return (uint64_t)ts->tv_sec * 1000000000ULL + (uint64_t)ts->tv_nsec;
}

ssize_t io_read(IOContext* ctx, int socket_index) {
    if (!ctx || socket_index < 0 || socket_index >= ctx->socket_count) {
        return -1;
    }
    
    IOSocket* sock = &ctx->sockets[socket_index];
    if (!sock->rx_ring || sock->fd < 0) {
        return -1;
    }
    
    // Get write pointer and available space
    char* write_ptr;
    size_t available;
    ringbuffer_write_inline(sock->rx_ring, &write_ptr, &available);
    
    if (__builtin_expect(available == 0, 0)) {  // Cold path: buffer full is rare
        return 0;
    }
    
    // Use recvmsg() to capture NIC timestamp via SO_TIMESTAMP_OLD
    struct msghdr msg;
    struct iovec iov;
    char control[CMSG_SPACE(sizeof(struct timespec))];
    
    iov.iov_base = write_ptr;
    iov.iov_len = available;
    
    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control;
    msg.msg_controllen = sizeof(control);
    msg.msg_flags = 0;
    
    ssize_t n = recvmsg(sock->fd, &msg, 0);
    
    if (__builtin_expect(n > 0, 1)) {  // Hot path: expect success
        // Extract NIC timestamp from control message
        // macOS uses SO_TIMESTAMP which provides SCM_TIMESTAMP control message
        struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
        while (cmsg != NULL) {
            if (__builtin_expect(cmsg->cmsg_level == SOL_SOCKET, 1)) {  // Hot path: expect socket level
                // Try both SCM_TIMESTAMP and SCM_TIMESTAMPNS (if available)
                // On macOS, SO_TIMESTAMP gives SCM_TIMESTAMP with timeval
                // SO_TIMESTAMPNS gives SCM_TIMESTAMPNS with timespec
                #ifdef SCM_TIMESTAMPNS
                if (__builtin_expect(cmsg->cmsg_type == SCM_TIMESTAMPNS, 1)) {  // Hot path: prefer nanosecond precision
                    struct timespec* ts = (struct timespec*)CMSG_DATA(cmsg);
                    uint64_t nic_ns = timespec_to_ns(ts);
                
                    // Store NIC timestamp
                    sock->last_nic_timestamp_ns = nic_ns;
                
                    // Convert to CPU cycles using integer arithmetic only (HFT optimization)
                    uint64_t now_ticks = mach_absolute_time();
                    // Use cached timebase (same as ssl.c)
                    static mach_timebase_info_data_t cached_timebase_io = {0, 0};
                    static bool timebase_initialized_io = false;
                    if (!timebase_initialized_io) {
                        mach_timebase_info(&cached_timebase_io);
                        timebase_initialized_io = true;
                    }
                    uint64_t now_ns = (now_ticks * cached_timebase_io.numer) / cached_timebase_io.denom;
                
                    // Estimate NIC timestamp in ticks using integer arithmetic
                    if (nic_ns <= now_ns && now_ns > 0) {
                        uint64_t diff_ns = now_ns - nic_ns;
                        // Integer-only conversion: convert diff_ns to cycles
                        uint64_t diff_ticks = (diff_ns * cached_timebase_io.denom) / cached_timebase_io.numer;
                        sock->last_nic_timestamp_ticks = now_ticks > diff_ticks ? now_ticks - diff_ticks : 0;
                    } else {
                        sock->last_nic_timestamp_ticks = now_ticks;
                    }
                    break;
                }
                #endif
                #ifdef SCM_TIMESTAMP
                if (cmsg->cmsg_type == SCM_TIMESTAMP) {
                    // SCM_TIMESTAMP provides timeval (not timespec) on macOS
                    struct timeval* tv = (struct timeval*)CMSG_DATA(cmsg);
                    uint64_t nic_ns = (uint64_t)tv->tv_sec * 1000000000ULL + (uint64_t)tv->tv_usec * 1000ULL;
                
                    // Store NIC timestamp
                    sock->last_nic_timestamp_ns = nic_ns;
                
                    // Convert to CPU cycles using integer arithmetic only (HFT optimization)
                    uint64_t now_ticks = mach_absolute_time();
                    // Use cached timebase (same as ssl.c)
                    static mach_timebase_info_data_t cached_timebase_io = {0, 0};
                    static bool timebase_initialized_io = false;
                    if (!timebase_initialized_io) {
                        mach_timebase_info(&cached_timebase_io);
                        timebase_initialized_io = true;
                    }
                    uint64_t now_ns = (now_ticks * cached_timebase_io.numer) / cached_timebase_io.denom;
                
                    // Estimate NIC timestamp in ticks using integer arithmetic
                    if (nic_ns <= now_ns && now_ns > 0) {
                        uint64_t diff_ns = now_ns - nic_ns;
                        // Integer-only conversion: convert diff_ns to cycles
                        uint64_t diff_ticks = (diff_ns * cached_timebase_io.denom) / cached_timebase_io.numer;
                        sock->last_nic_timestamp_ticks = now_ticks > diff_ticks ? now_ticks - diff_ticks : 0;
                    } else {
                        sock->last_nic_timestamp_ticks = now_ticks;
                    }
                    break;
                }
                #endif
            }
            cmsg = CMSG_NXTHDR(&msg, cmsg);
        }
        
        // Update ring buffer write pointer
        size_t wp = sock->rx_ring->write_ptr;
        size_t new_wp = wp + n;
        
        if (new_wp >= sock->rx_ring->size) {
            size_t first_part = sock->rx_ring->size - wp;
            size_t second_part = n - first_part;
            new_wp = second_part;
        }
        
        __atomic_thread_fence(__ATOMIC_RELEASE);
        sock->rx_ring->write_ptr = new_wp % sock->rx_ring->size;
    } else if (__builtin_expect(n < 0 && errno != EAGAIN && errno != EWOULDBLOCK, 0)) {
        return -1;  // Error (cold path)
    } else if (__builtin_expect(n == 0, 0)) {
        return -1;  // EOF (cold path)
    }
    
    return n;
}

ssize_t io_write(IOContext* ctx, int socket_index) {
    if (!ctx || socket_index < 0 || socket_index >= ctx->socket_count) {
        return -1;
    }
    
    IOSocket* sock = &ctx->sockets[socket_index];
    if (!sock->tx_ring || sock->fd < 0) {
        return -1;
    }
    
    // Get read pointer and available data
    char* read_ptr;
    size_t available;
    ringbuffer_read_inline(sock->tx_ring, &read_ptr, &available);
    
    if (__builtin_expect(available == 0, 0)) {  // Cold path: no data is rare
        return 0;
    }
    
    RingBuffer* rb = sock->tx_ring;
    struct iovec iov[2] = {0};
    int iov_cnt = 1;
    
    iov[0].iov_base = read_ptr;
    iov[0].iov_len = available;
    
    // Handle wrap-around with scatter-gather (cold path: wrap-around is rare)
    if (__builtin_expect(rb->read_ptr + available > rb->size, 0)) {
        iov[0].iov_len = rb->size - rb->read_ptr;
        iov[1].iov_base = rb->buf;
        iov[1].iov_len = available - iov[0].iov_len;
        iov_cnt = 2;
    }
    
    // Zero-copy batch write
    ssize_t n = writev(sock->fd, iov, iov_cnt);
    
    if (__builtin_expect(n > 0, 1)) {  // Hot path: expect success
        // Update ring buffer read pointer
        size_t rp = rb->read_ptr;
        __atomic_thread_fence(__ATOMIC_RELEASE);
        rb->read_ptr = (rp + n) % rb->size;
    }
    
    return n;
}

uint64_t io_get_last_nic_timestamp_ns(IOContext* ctx, int socket_index) {
    if (!ctx || socket_index < 0 || socket_index >= ctx->socket_count) {
        return 0;
    }
    return ctx->sockets[socket_index].last_nic_timestamp_ns;
}

uint64_t io_get_last_nic_timestamp_ticks(IOContext* ctx, int socket_index) {
    if (!ctx || socket_index < 0 || socket_index >= ctx->socket_count) {
        return 0;
    }
    return ctx->sockets[socket_index].last_nic_timestamp_ticks;
}

#ifdef __APPLE__
// M4 OPTIMIZATION: Get GCD queues for optimized CPU scheduling
void* io_get_io_queue(IOContext* ctx) {
    return ctx ? ctx->io_queue : NULL;
}

void* io_get_net_queue(IOContext* ctx) {
    return ctx ? ctx->net_queue : NULL;
}

void* io_get_ssl_queue(IOContext* ctx) {
    return ctx ? ctx->ssl_queue : NULL;
}

void* io_get_parse_queue(IOContext* ctx) {
    return ctx ? ctx->parse_queue : NULL;
}
#endif

