#ifndef RINGBUFFER_H
#define RINGBUFFER_H

#include <stddef.h>
#include <stdint.h>

#ifndef RINGBUFFER_SIZE
#define RINGBUFFER_SIZE (8 * 1024 * 1024)  // 8MB default (can be overridden via CMake)
#endif
#define RINGBUFFER_ALIGNMENT 128           // M4 cache line size

typedef struct {
    char* buf;              // Buffer base address (128-byte aligned)
    size_t size;            // Total buffer size
    volatile size_t read_ptr;   // Consumer position (volatile for lock-free)
    volatile size_t write_ptr;  // Producer position (volatile for lock-free)
    int locked;             // Whether buffer is locked in memory
} RingBuffer;

// Initialize ring buffer with 128-byte alignment and memory locking
int ringbuffer_init(RingBuffer* rb);

// Cleanup: unlock memory and release
void ringbuffer_cleanup(RingBuffer* rb);

// Write data to ring buffer (single producer)
// Returns bytes written (may be less than len if buffer is full)
size_t ringbuffer_write(RingBuffer* rb, const void* data, size_t len);

// Read data from ring buffer (single consumer)
// Returns bytes read (may be less than len if buffer is empty)
size_t ringbuffer_read(RingBuffer* rb, void* data, size_t len);

// Get available space for writing (bytes)
size_t ringbuffer_writeable(RingBuffer* rb);

// Get available data for reading (bytes)
size_t ringbuffer_readable(RingBuffer* rb);

// Reset ring buffer (set read/write pointers to 0)
void ringbuffer_reset(RingBuffer* rb);

// Batch operations (HFT optimization: reduce function call overhead)
// Write multiple chunks in a single call
// Returns total bytes written
size_t ringbuffer_batch_write(RingBuffer* rb, const void** data_array, size_t* len_array, size_t count);

// Read multiple chunks in a single call
// Returns total bytes read
size_t ringbuffer_batch_read(RingBuffer* rb, void** data_array, size_t* len_array, size_t count);

// Hot path: inline read (returns pointer and length directly)
static inline void ringbuffer_read_inline(RingBuffer* rb, char** data, size_t* len) 
    __attribute__((always_inline));

// Hot path: inline write (returns pointer and available space)
static inline void ringbuffer_write_inline(RingBuffer* rb, char** data, size_t* len) 
    __attribute__((always_inline));

// Implementation of inline functions (with atomic operations for SPSC)
// Note: Using GCC builtin atomics (__atomic_*) which don't require stdatomic.h

static inline void ringbuffer_read_inline(RingBuffer* rb, char** data, size_t* len) {
    size_t rp = __atomic_load_n(&rb->read_ptr, __ATOMIC_RELAXED);
    size_t wp = __atomic_load_n(&rb->write_ptr, __ATOMIC_ACQUIRE);
    
    if (wp >= rp) {
        *len = wp - rp;
    } else {
        *len = rb->size - rp + wp;
    }
    
    *data = rb->buf + rp;
}

static inline void ringbuffer_write_inline(RingBuffer* rb, char** data, size_t* len) {
    size_t rp = __atomic_load_n(&rb->read_ptr, __ATOMIC_ACQUIRE);
    size_t wp = __atomic_load_n(&rb->write_ptr, __ATOMIC_RELAXED);
    
    if (wp >= rp) {
        *len = rb->size - wp;
        if (rp == 0 && wp == rb->size) {
            *len = 0;  // Buffer full
        }
    } else {
        *len = rp - wp;
    }
    
    *data = rb->buf + wp;
}

#endif // RINGBUFFER_H

