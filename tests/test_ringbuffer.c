#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "../src/ringbuffer.h"

#define TEST_ASSERT(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "FAIL: %s\n", msg); \
            exit(1); \
        } \
    } while(0)

// Test 128-byte alignment
void test_alignment(void) {
    RingBuffer rb;
    TEST_ASSERT(ringbuffer_init(&rb) == 0, "Ring buffer init failed");
    
    // Check alignment
    uintptr_t addr = (uintptr_t)rb.buf;
    TEST_ASSERT((addr % RINGBUFFER_ALIGNMENT) == 0, "Buffer not 128-byte aligned");
    
    printf("PASS: 128-byte alignment test\n");
    ringbuffer_cleanup(&rb);
}

// Test SPSC correctness
void test_spsc_correctness(void) {
    RingBuffer rb;
    TEST_ASSERT(ringbuffer_init(&rb) == 0, "Ring buffer init failed");
    
    // Write test data
    const char* test_data = "Hello, World!";
    size_t data_len = strlen(test_data);
    
    size_t written = ringbuffer_write(&rb, test_data, data_len);
    TEST_ASSERT(written == data_len, "Write failed");
    
    // Read test data
    char read_buf[256];
    size_t read = ringbuffer_read(&rb, read_buf, sizeof(read_buf));
    TEST_ASSERT(read == data_len, "Read failed");
    
    read_buf[read] = '\0';
    TEST_ASSERT(strcmp(read_buf, test_data) == 0, "Data mismatch");
    
    printf("PASS: SPSC correctness test\n");
    ringbuffer_cleanup(&rb);
}

// Test wrap-around behavior
void test_wrap_around(void) {
    RingBuffer rb;
    TEST_ASSERT(ringbuffer_init(&rb) == 0, "Ring buffer init failed");
    
    // Write until near the end
    size_t write_size = rb.size - 1024;
    char* write_data = malloc(write_size);
    TEST_ASSERT(write_data != NULL, "Malloc failed");
    memset(write_data, 'A', write_size);
    
    size_t written = ringbuffer_write(&rb, write_data, write_size);
    TEST_ASSERT(written == write_size, "Write failed");
    
    // Read some data
    size_t read_size = rb.size / 2;
    char* read_buf = malloc(read_size);
    TEST_ASSERT(read_buf != NULL, "Malloc failed");
    
    size_t read = ringbuffer_read(&rb, read_buf, read_size);
    TEST_ASSERT(read == read_size, "Read failed");
    
    // Write more to trigger wrap-around
    size_t additional_write = 2048;
    char* additional_data = malloc(additional_write);
    TEST_ASSERT(additional_data != NULL, "Malloc failed");
    memset(additional_data, 'B', additional_write);
    
    written = ringbuffer_write(&rb, additional_data, additional_write);
    TEST_ASSERT(written == additional_write, "Wrap-around write failed");
    
    // Read remaining
    read = ringbuffer_read(&rb, read_buf, write_size - read_size);
    TEST_ASSERT(read == (write_size - read_size), "Wrap-around read failed");
    
    free(write_data);
    free(read_buf);
    free(additional_data);
    
    printf("PASS: Wrap-around test\n");
    ringbuffer_cleanup(&rb);
}

// Test available space calculations
void test_available_space(void) {
    RingBuffer rb;
    TEST_ASSERT(ringbuffer_init(&rb) == 0, "Ring buffer init failed");
    
    size_t initial_writeable = ringbuffer_writeable(&rb);
    TEST_ASSERT(initial_writeable > 0, "Initial writeable space should be > 0");
    
    // Write some data
    char data[1024];
    memset(data, 'X', sizeof(data));
    size_t written = ringbuffer_write(&rb, data, sizeof(data));
    TEST_ASSERT(written == sizeof(data), "Write failed");
    
    size_t readable = ringbuffer_readable(&rb);
    TEST_ASSERT(readable == sizeof(data), "Readable space mismatch");
    
    size_t writeable_after = ringbuffer_writeable(&rb);
    TEST_ASSERT(writeable_after < initial_writeable, "Writeable space should decrease");
    
    printf("PASS: Available space test\n");
    ringbuffer_cleanup(&rb);
}

// Test reset functionality
void test_reset(void) {
    RingBuffer rb;
    TEST_ASSERT(ringbuffer_init(&rb) == 0, "Ring buffer init failed");
    
    // Write some data
    char data[512];
    memset(data, 'Y', sizeof(data));
    ringbuffer_write(&rb, data, sizeof(data));
    
    // Reset
    ringbuffer_reset(&rb);
    
    size_t readable = ringbuffer_readable(&rb);
    TEST_ASSERT(readable == 0, "After reset, readable should be 0");
    
    size_t writeable = ringbuffer_writeable(&rb);
    TEST_ASSERT(writeable > 0, "After reset, writeable should be > 0");
    
    printf("PASS: Reset test\n");
    ringbuffer_cleanup(&rb);
}

// Test inline functions
void test_inline_functions(void) {
    RingBuffer rb;
    TEST_ASSERT(ringbuffer_init(&rb) == 0, "Ring buffer init failed");
    
    // Test inline write
    char* write_ptr;
    size_t write_len;
    ringbuffer_write_inline(&rb, &write_ptr, &write_len);
    TEST_ASSERT(write_ptr != NULL, "Write pointer should not be NULL");
    TEST_ASSERT(write_len > 0, "Write length should be > 0");
    
    // Write some data
    memset(write_ptr, 'Z', 100);
    rb.write_ptr += 100;
    
    // Test inline read
    char* read_ptr;
    size_t read_len;
    ringbuffer_read_inline(&rb, &read_ptr, &read_len);
    TEST_ASSERT(read_ptr != NULL, "Read pointer should not be NULL");
    TEST_ASSERT(read_len >= 100, "Read length should be >= 100");
    
    printf("PASS: Inline functions test\n");
    ringbuffer_cleanup(&rb);
}

int main(void) {
    printf("Running ring buffer unit tests...\n\n");
    
    test_alignment();
    test_spsc_correctness();
    test_wrap_around();
    test_available_space();
    test_reset();
    test_inline_functions();
    
    printf("\nAll ring buffer tests passed!\n");
    return 0;
}

