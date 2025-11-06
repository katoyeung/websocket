cmake_minimum_required(VERSION 3.20)
project(websocket_hft VERSION 1.0.0 LANGUAGES C)

# M4-specific compiler flags for Apple Silicon optimization
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Enable blocks support for Network.framework (required for dispatch blocks)
if(APPLE)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fblocks")
endif()

# Detect Apple Silicon (ARM64)
if(APPLE AND CMAKE_SYSTEM_PROCESSOR MATCHES "arm64|aarch64")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mcpu=apple-m4 -mtune=apple-m4")
    message(STATUS "Detected Apple Silicon - enabling M4 optimizations")
endif()

# Ring buffer size option (default 1MB for lower memory, can be set to 8MB for HFT)
# Use set() with CACHE STRING to allow numeric override, default to 1MB
set(WEBSOCKET_RING_BUFFER_SIZE_MB "1" CACHE STRING "Ring buffer size in MB (default: 1, use 8 for HFT)")

# Parse the value - handle both string and numeric, default to 1MB
set(RING_BUFFER_SIZE_MB 1)  # Default value

# Check if it's a valid number (not ON/OFF boolean)
if(WEBSOCKET_RING_BUFFER_SIZE_MB)
    if(WEBSOCKET_RING_BUFFER_SIZE_MB MATCHES "^[0-9]+$")
        # Valid numeric value
        set(RING_BUFFER_SIZE_MB ${WEBSOCKET_RING_BUFFER_SIZE_MB})
    endif()
endif()

# Calculate bytes and set compile definition
math(EXPR RING_BUFFER_SIZE_BYTES "${RING_BUFFER_SIZE_MB} * 1024 * 1024")
add_compile_definitions(RINGBUFFER_SIZE=${RING_BUFFER_SIZE_BYTES})
message(STATUS "WebSocket ring buffer size: ${RING_BUFFER_SIZE_MB}MB (${RING_BUFFER_SIZE_BYTES} bytes)")

# Optimize for HFT (low latency, no dynamic allocations in hot path)
set(CMAKE_C_FLAGS_RELEASE "-O3 -ffast-math -fno-pie")
set(CMAKE_C_FLAGS_DEBUG "-O0 -g -fsanitize=address")

# Additional M4-specific flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wno-unused-parameter")

# Enhanced CPU-specific optimizations for Apple M4
if(APPLE AND CMAKE_SYSTEM_PROCESSOR MATCHES "arm64|aarch64")
    # Enable Neon SIMD and crypto extensions for M4 (use simd instead of neon for newer clang)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -march=armv8.2-a+simd+crypto")
    # Tune for Apple M4 (Cortex-A76 derived)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mtune=cortex-a76")
endif()

# Link-Time Optimization (LTO) for cross-module optimizations
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -flto=thin")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -flto=thin")

# Loop unrolling (carefully applied for hot paths)
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -funroll-loops")

# Additional HFT optimizations
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -fno-trapping-math -fomit-frame-pointer")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -ffunction-sections -fdata-sections")
# Use macOS-compatible linker flags (--gc-sections is GNU-specific, not supported on macOS)
# Note: -z,now is Linux-specific and not applicable on macOS
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-dead_strip")

# Source files
set(SOURCES
    src/ringbuffer.c
    src/io_kqueue.c
    src/ssl.c
    src/parser_neon.c
    src/websocket.c
    src/network_framework.c
)

set(HEADERS
    src/ringbuffer.h
    src/io_kqueue.h
    src/ssl.h
    src/parser_neon.h
    src/websocket.h
    src/os_macos.h
    src/internal.h
    src/network_framework.h
)

# Create static library
add_library(websocket_hft STATIC ${SOURCES} ${HEADERS})

# Include directories
target_include_directories(websocket_hft PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# Link SecureTransport framework (primary TLS implementation)
find_library(SECURITY_FRAMEWORK Security)
if(SECURITY_FRAMEWORK)
    target_link_libraries(websocket_hft PRIVATE ${SECURITY_FRAMEWORK})
endif()

# Link Network.framework for user-space kernel bypass (M4 optimization)
# REQUIRED: network_framework.c is compiled and uses Network.framework APIs
# Even though websocket.c doesn't use it directly, network_framework.c is part of the build
find_library(NETWORK_FRAMEWORK Network)
if(NETWORK_FRAMEWORK)
    target_link_libraries(websocket_hft PRIVATE ${NETWORK_FRAMEWORK})
    message(STATUS "Network.framework found - enabling user-space kernel bypass")
else()
    message(WARNING "Network.framework not found - network_framework.c will use fallback")
endif()

# Link Dispatch.framework (GCD) for optimized CPU scheduling (M4 optimization)
# Used in io_kqueue.c for dispatch queues (I/O operations)
# Also used in network_framework.c for Network.framework queues
find_library(DISPATCH_FRAMEWORK dispatch)
if(DISPATCH_FRAMEWORK)
    target_link_libraries(websocket_hft PRIVATE ${DISPATCH_FRAMEWORK})
    message(STATUS "Dispatch.framework found - enabling GCD scheduling")
else()
    message(WARNING "Dispatch.framework not found - using pthread fallback")
endif()

# Link system libraries
target_link_libraries(websocket_hft PRIVATE
    pthread
)

# Optional: Link OpenSSL 3.x if available (for fallback)
find_package(OpenSSL QUIET)
if(OpenSSL_FOUND)
    target_link_libraries(websocket_hft PRIVATE ${OPENSSL_LIBRARIES})
    target_include_directories(websocket_hft PRIVATE ${OPENSSL_INCLUDE_DIR})
    target_compile_definitions(websocket_hft PRIVATE HAVE_OPENSSL)
    message(STATUS "OpenSSL found - fallback TLS support enabled")
else()
    # Try to find OpenSSL via pkg-config or common paths
    find_path(OPENSSL_INCLUDE_DIR openssl/ssl.h
        PATHS /usr/local/include /opt/homebrew/include
    )
    find_library(OPENSSL_SSL_LIB ssl
        PATHS /usr/local/lib /opt/homebrew/lib /usr/lib
    )
    find_library(OPENSSL_CRYPTO_LIB crypto
        PATHS /usr/local/lib /opt/homebrew/lib /usr/lib
    )
    if(OPENSSL_INCLUDE_DIR AND OPENSSL_SSL_LIB AND OPENSSL_CRYPTO_LIB)
        target_link_libraries(websocket_hft PRIVATE ${OPENSSL_SSL_LIB} ${OPENSSL_CRYPTO_LIB})
        target_include_directories(websocket_hft PRIVATE ${OPENSSL_INCLUDE_DIR})
        target_compile_definitions(websocket_hft PRIVATE HAVE_OPENSSL)
        message(STATUS "OpenSSL found via manual search - fallback TLS support enabled")
    else()
        message(STATUS "OpenSSL not found - using SecureTransport only (OpenSSL functions used in websocket.c require linking)")
        # Note: websocket.c uses OpenSSL for Base64 encoding, so we need at least that
        # For now, we'll rely on SecureTransport for TLS
    endif()
endif()

# OpenSSL is needed for Base64 encoding in websocket.c even if not using OpenSSL for TLS
# Try to find it in system paths
if(NOT OPENSSL_CRYPTO_LIB)
    find_library(CRYPTO_LIB crypto
        PATHS /usr/local/lib /opt/homebrew/lib /usr/lib
    )
    if(CRYPTO_LIB)
        target_link_libraries(websocket_hft PRIVATE ${CRYPTO_LIB})
        message(STATUS "Found crypto library for Base64 support")
    endif()
endif()

# Test executables
add_executable(test_ringbuffer tests/test_ringbuffer.c)
target_link_libraries(test_ringbuffer websocket_hft)

add_executable(test_parser_neon tests/test_parser_neon.c)
target_link_libraries(test_parser_neon websocket_hft)

add_executable(test_kqueue tests/test_kqueue.c)
target_link_libraries(test_kqueue websocket_hft)

add_executable(test_integration_binance tests/test_integration_binance.c)
target_link_libraries(test_integration_binance websocket_hft)

add_executable(test_websocket_reconnect tests/test_websocket_reconnect.c)
target_link_libraries(test_websocket_reconnect websocket_hft)

add_executable(benchmark tests/benchmark.c)
target_link_libraries(benchmark websocket_hft)
target_link_libraries(benchmark m)  # Link math library for sqrt()

# Comprehensive test suite executables
add_executable(test_memory tests/test_memory.c)
target_link_libraries(test_memory websocket_hft)
target_link_libraries(test_memory m)  # For sqrt() in helpers

add_executable(test_stress tests/test_stress.c)
target_link_libraries(test_stress websocket_hft)
target_link_libraries(test_stress m)

add_executable(test_errors tests/test_errors.c)
target_link_libraries(test_errors websocket_hft)

add_executable(test_performance tests/test_performance.c)
target_link_libraries(test_performance websocket_hft)
target_link_libraries(test_performance m)

add_executable(test_threading tests/test_threading.c)
target_link_libraries(test_threading websocket_hft)

add_executable(test_integration_stress tests/test_integration_stress.c)
target_link_libraries(test_integration_stress websocket_hft)
target_link_libraries(test_integration_stress m)

# WebSocket benchmark test (comparable with libwebsockets benchmark)
add_executable(test_websocket_benchmark tests/test_websocket_benchmark.c)
target_link_libraries(test_websocket_benchmark websocket_hft)
target_link_libraries(test_websocket_benchmark m)
target_link_libraries(test_websocket_benchmark pthread)

# Example executable
add_executable(binance_ticker examples/binance_ticker.c)
target_link_libraries(binance_ticker websocket_hft)

# Installation
install(TARGETS websocket_hft
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
)

install(FILES ${HEADERS}
    DESTINATION include/websocket_hft
)

# CTest support
enable_testing()
add_test(NAME test_ringbuffer COMMAND test_ringbuffer)
add_test(NAME test_parser_neon COMMAND test_parser_neon)
add_test(NAME test_kqueue COMMAND test_kqueue)
add_test(NAME test_memory COMMAND test_memory)
add_test(NAME test_errors COMMAND test_errors)
add_test(NAME test_threading COMMAND test_threading)
add_test(NAME test_performance COMMAND test_performance)

# Note: Stress and integration tests are not included in CTest by default
# as they may take a long time. Run them manually or via run_all_tests.sh

# AddressSanitizer build configuration
option(BUILD_WITH_ASAN "Build with AddressSanitizer" OFF)
if(BUILD_WITH_ASAN)
    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fsanitize=address -fno-omit-frame-pointer")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=address")
    message(STATUS "Building with AddressSanitizer enabled")
endif()

