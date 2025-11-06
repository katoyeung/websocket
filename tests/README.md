# Comprehensive Testing Suite

This directory contains a comprehensive testing and stress testing suite for the HFT WebSocket library, covering stability, performance, and memory management.

## Test Categories

### 1. Unit Tests

#### `test_ringbuffer.c`
- Ring buffer alignment (128-byte cache line)
- SPSC (single-producer/single-consumer) correctness
- Wrap-around behavior
- Available space calculations
- Reset functionality
- Inline function tests

#### `test_parser_neon.c`
- Neon SIMD WebSocket frame parsing
- JSON field extraction
- Scalar fallback comparison

#### `test_kqueue.c`
- kqueue I/O multiplexing
- Edge-triggered event handling
- Socket event processing

#### `test_memory.c` (NEW)
- **Memory leak detection**: 10,000 create/destroy cycles
- **Ring buffer alignment**: Multiple init/cleanup cycles
- **Buffer overflow protection**: Bounds checking
- **Resource exhaustion**: Memory limit testing
- **Double-free protection**: AddressSanitizer detection
- **Use-after-free detection**: Safety checks
- **Memory locking**: mlock() verification
- **Rapid init/cleanup cycles**: 1,000 cycles stress test

#### `test_errors.c` (NEW)
- **Invalid WebSocket frames**: Malformed headers, reserved bits
- **Invalid connection parameters**: Malformed URLs, invalid ports
- **Connection refused**: Error handling
- **State machine edge cases**: Invalid state transitions
- **Callback during destruction**: Safety checks
- **Frame fragmentation**: Incomplete frame handling
- **NULL WebSocket operations**: Null pointer safety
- **Timeout handling**: Connection timeout scenarios
- **SSL/TLS errors**: Certificate validation
- **Ring buffer edge cases**: Null pointer, zero-length operations

#### `test_threading.c` (NEW)
- **SPSC correctness**: Lock-free producer/consumer verification
- **Concurrent WebSocket instances**: Multiple independent connections
- **Memory ordering**: Acquire/release semantics verification
- **Race condition stress**: Multi-threaded stress test

### 2. Stress Tests

#### `test_stress.c` (NEW)
- **High-throughput processing**: 100K messages with varying payload sizes
- **Rapid connect/disconnect**: 1,000 connection cycles
- **Ring buffer saturation**: Backpressure handling
- **Long-running connection**: Configurable duration (default 5 minutes)
- **Concurrent connections**: Multiple simultaneous connections
- **Message burst handling**: Sudden 10x rate spikes

### 3. Performance Tests

#### `test_performance.c` (NEW)
- **Latency percentile tracking**: P50, P90, P95, P99, P99.9 measurements
- **Throughput benchmarks**: Messages/second at various payload sizes
- **Neon SIMD speedup**: Verification of 4x speedup target
- **Performance regression detection**: Comparison against baseline
- **Cache behavior verification**: 128-byte alignment effectiveness

#### `benchmark.c` (Existing)
- WebSocket frame parsing benchmarks
- JSON parsing benchmarks
- Ring buffer throughput
- SSL/TLS decryption latency

### 4. Integration Tests

#### `test_integration_binance.c` (Existing)
- Real Binance WebSocket connection
- Latency measurement
- Message processing

#### `test_websocket_reconnect.c` (Existing)
- Auto-reconnect functionality
- Connection state management

#### `test_integration_stress.c` (NEW)
- **Extended Binance connection**: 1+ hour duration test
- **Reconnection stress**: 20 rapid reconnect cycles
- **Message rate spike handling**: Burst detection
- **Multiple symbol streams**: Concurrent symbol subscriptions

## Running Tests

### Quick Start

Run all tests:
```bash
./tests/run_all_tests.sh
```

Run specific test categories:
```bash
./tests/run_all_tests.sh --unit-only      # Unit tests only
./tests/run_all_tests.sh --stress-only    # Stress tests only
./tests/run_all_tests.sh --performance-only  # Performance tests only
./tests/run_all_tests.sh --integration-only  # Integration tests only
```

Run with AddressSanitizer:
```bash
./tests/run_all_tests.sh --asan
```

Quick mode (skip long-running tests):
```bash
./tests/run_all_tests.sh --quick
```

### Building Tests

Build all tests:
```bash
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(sysctl -n hw.ncpu)
```

Build with AddressSanitizer:
```bash
mkdir -p build_asan && cd build_asan
cmake .. -DCMAKE_BUILD_TYPE=Debug -DBUILD_WITH_ASAN=ON
make -j$(sysctl -n hw.ncpu)
```

### Running Individual Tests

```bash
# From build directory
./test_memory
./test_stress
./test_errors
./test_performance
./test_threading
./test_integration_stress
```

### Using CTest

```bash
cd build
ctest                    # Run all CTest tests
ctest -R test_memory     # Run specific test
ctest -V                 # Verbose output
ctest -j4                # Parallel execution
```

## Test Configuration

### Environment Variables

- `STRESS_DURATION`: Duration for stress tests in seconds (default: 300)
- `STRESS_CONNECTIONS`: Number of concurrent connections (default: 10)
- `STRESS_MESSAGES`: Target message count (default: 100000)
- `STRESS_PAYLOAD_SIZE`: Message payload size range
- `INTEGRATION_DURATION`: Integration test duration in minutes (default: 60)

Example:
```bash
export STRESS_DURATION=600  # 10 minutes
export STRESS_CONNECTIONS=20
./tests/run_all_tests.sh --stress-only
```

## Performance Baselines

Performance baselines are stored in `tests/baseline.txt` and are used for regression detection.

### Current Targets

- **Latency**: P99 < 40µs (40,000 nanoseconds)
- **Throughput**: > 15,000 messages/second
- **Neon Speedup**: 4x over scalar code
- **Memory Growth**: < 1% after 10,000 create/destroy cycles

### Creating a Baseline

Run performance tests to create a baseline:
```bash
cd build
./test_performance
```

The baseline file will be created at `tests/baseline.txt`.

### Regression Detection

Performance tests compare current metrics against the baseline and fail if:
- P99 latency regresses by >10%
- Throughput drops below target
- Other metrics exceed thresholds

## Memory Profiling

### AddressSanitizer

Build with AddressSanitizer:
```bash
mkdir -p build_asan && cd build_asan
cmake .. -DCMAKE_BUILD_TYPE=Debug -DBUILD_WITH_ASAN=ON
make -j$(sysctl -n hw.ncpu)
```

Run tests:
```bash
./test_memory  # Will detect memory leaks, buffer overflows, use-after-free
```

### Manual Memory Tracking

Memory tracking is built into test helpers and reports:
- RSS (Resident Set Size) growth
- Heap size changes
- Allocation counts
- Peak memory usage

## Test Results Interpretation

### Success Criteria

- **Unit Tests**: All tests must pass
- **Stress Tests**: No crashes, <20% memory growth over test duration
- **Performance Tests**: Meet latency/throughput targets, <10% regression
- **Integration Tests**: Stable connections, successful reconnects

### Common Issues

1. **Memory Leaks**: Check AddressSanitizer output, review allocation patterns
2. **Performance Regression**: Compare against baseline, check for optimization changes
3. **Connection Failures**: Network issues, firewall, or server-side problems
4. **Timeout Errors**: Increase timeout values or check network latency

## Continuous Integration

### CI Integration

The test suite can be integrated into CI pipelines:

```yaml
# Example GitHub Actions workflow
- name: Run Tests
  run: |
    mkdir -p build && cd build
    cmake .. -DCMAKE_BUILD_TYPE=Release
    make -j$(sysctl -n hw.ncpu)
    cd ..
    ./tests/run_all_tests.sh --unit-only --performance-only
```

### Test Coverage

Current test coverage includes:
- ✅ Memory management (leaks, bounds, exhaustion)
- ✅ Error handling (invalid inputs, network errors)
- ✅ Performance (latency, throughput, regression)
- ✅ Thread safety (SPSC correctness, concurrent access)
- ✅ Stress testing (long-running, high-throughput)
- ✅ Integration (real exchange connections)

## Contributing

When adding new features:

1. Add corresponding unit tests
2. Update stress tests if applicable
3. Add performance benchmarks if performance-critical
4. Update baseline if performance characteristics change
5. Document test configuration options

## Troubleshooting

### Tests Failing

1. Check system resources (memory, file descriptors)
2. Verify network connectivity for integration tests
3. Review test logs for specific error messages
4. Run with AddressSanitizer to detect memory issues

### Performance Degradation

1. Compare current results with baseline
2. Check for system load (CPU, memory, network)
3. Review recent code changes
4. Re-run tests multiple times to rule out variance

### Build Issues

1. Ensure CMake 3.20+ is installed
2. Verify Xcode Command Line Tools are installed
3. Check for missing dependencies (OpenSSL)
4. Clean build directory: `rm -rf build && mkdir build`

## Additional Resources

- Main README: `../README.md`
- API Documentation: `../README.md#api-reference`
- Performance Targets: `../README.md#performance-targets`

