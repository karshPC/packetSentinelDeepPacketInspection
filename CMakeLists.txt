cmake_minimum_required(VERSION 3.16)

project(PacketAnalyzer VERSION 1.0 LANGUAGES CXX)

# ============================================================
# C++ Configuration
# ============================================================

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Generate compile_commands.json for VS Code IntelliSense
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ============================================================
# Threads
# ============================================================

find_package(Threads REQUIRED)

# ============================================================
# Include directories
# ============================================================

include_directories(
    ${CMAKE_SOURCE_DIR}/include
)

# ============================================================
# Core DPI Types
# ============================================================

add_library(dpi_types
    src/types.cpp
)

target_include_directories(dpi_types
    PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)

# ============================================================
# PCAP Reader
# ============================================================

add_library(pcap_reader
    src/pcap_reader.cpp
)

target_include_directories(pcap_reader
    PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)

# ============================================================
# Packet Parser
# ============================================================

add_library(packet_parser
    src/packet_parser.cpp
)

target_include_directories(packet_parser
    PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(packet_parser
    PUBLIC
    dpi_types
)

# ============================================================
# Packet Job Builder
# ============================================================

add_library(packet_job_builder
    src/packet_job_builder.cpp
)

target_include_directories(packet_job_builder
    PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(packet_job_builder
    PUBLIC
    packet_parser
    pcap_reader
    dpi_types
)

# ============================================================
# Connection Tracker
# ============================================================

add_library(connection_tracker
    src/connection_tracker.cpp
)

target_include_directories(connection_tracker
    PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(connection_tracker
    PUBLIC
    dpi_types
    Threads::Threads
)

# ============================================================
# Rule Manager
# ============================================================

add_library(rule_manager
    src/rule_manager.cpp
)

target_include_directories(rule_manager
    PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(rule_manager
    PUBLIC
    dpi_types
    Threads::Threads
)

# ============================================================
# SNI / HTTP Deep Inspection
# ============================================================

add_library(sni_extractor
    src/sni_extractor.cpp
)

target_include_directories(sni_extractor
    PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(sni_extractor
    PUBLIC
    dpi_types
)

# ============================================================
# Fast Path
# ============================================================

add_library(fast_path
    src/fast_path.cpp
)

target_include_directories(fast_path
    PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(fast_path
    PUBLIC
    connection_tracker
    rule_manager
    dpi_types
    Threads::Threads
)

# ============================================================
# Fast Path Manager
# ============================================================

add_library(fp_manager
    src/fp_manager.cpp
)

target_include_directories(fp_manager
    PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(fp_manager
    PUBLIC
    fast_path
    rule_manager
    connection_tracker
    dpi_types
    Threads::Threads
)

# ============================================================
# Load Balancer
# ============================================================

add_library(load_balancer
    src/load_balancer.cpp
)

target_include_directories(load_balancer
    PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(load_balancer
    PUBLIC
    dpi_types
    Threads::Threads
)

# ============================================================
# Pipeline Manager
# ============================================================

add_library(pipeline_manager
    src/pipeline_manager.cpp
)

target_include_directories(pipeline_manager
    PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(pipeline_manager
    PUBLIC
    load_balancer
    fp_manager
    fast_path
    connection_tracker
    dpi_types
    Threads::Threads
)

# ============================================================
# DPI Engine
# ============================================================

add_library(dpi_engine
    src/dpi_engine.cpp
)

target_include_directories(dpi_engine
    PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(dpi_engine
    PUBLIC
    pipeline_manager
    rule_manager
    load_balancer
    fp_manager
    fast_path
    packet_job_builder
    packet_parser
    pcap_reader
    connection_tracker
    sni_extractor
    dpi_types
    Threads::Threads
)

# ============================================================
# DPI Engine CLI
# ============================================================

add_executable(dpi_engine_app
    src/main.cpp
)

target_link_libraries(dpi_engine_app
    PRIVATE
    dpi_engine
    Threads::Threads
)

# ============================================================
# PCAP Reader Test
# ============================================================

add_executable(pcap_reader_test
    tests/pcap_reader_test.cpp
)

target_link_libraries(pcap_reader_test
    PRIVATE
    pcap_reader
)

# ============================================================
# Packet Parser Test
# ============================================================

add_executable(packet_parser_test
    tests/packet_parser_test.cpp
)

target_link_libraries(packet_parser_test
    PRIVATE
    packet_parser
    pcap_reader
)

# ============================================================
# Five Tuple Test
# ============================================================

add_executable(five_tuple_test
    tests/five_tuple_test.cpp
)

target_link_libraries(five_tuple_test
    PRIVATE
    packet_parser
    pcap_reader
    dpi_types
)

# ============================================================
# Thread Safe Queue Test
# ============================================================

add_executable(thread_safe_queue_test
    tests/thread_safe_queue_test.cpp
)

target_link_libraries(thread_safe_queue_test
    PRIVATE
    Threads::Threads
)

# ============================================================
# Packet Job Test
# ============================================================

add_executable(packet_job_test
    tests/packet_job_test.cpp
)

target_link_libraries(packet_job_test
    PRIVATE
    packet_job_builder
)

# ============================================================
# Packet Pipeline Test
# ============================================================

add_executable(packet_pipeline_test
    tests/packet_pipeline_test.cpp
)

target_link_libraries(packet_pipeline_test
    PRIVATE
    packet_job_builder
    packet_parser
    pcap_reader
    dpi_types
    Threads::Threads
)

# ============================================================
# Connection Tracker Test
# ============================================================

add_executable(connection_tracker_test
    tests/connection_tracker_test.cpp
)

target_link_libraries(connection_tracker_test
    PRIVATE
    connection_tracker
    dpi_types
    Threads::Threads
)

# ============================================================
# Load Balancer Test
# ============================================================

add_executable(load_balancer_test
    tests/load_balancer_test.cpp
)

target_link_libraries(load_balancer_test
    PRIVATE
    load_balancer
    dpi_types
    Threads::Threads
)

# ============================================================
# PCAP -> Load Balancer -> FP Queue Test
# ============================================================

add_executable(pcap_load_balancer_test
    tests/pcap_load_balancer_test.cpp
)

target_link_libraries(pcap_load_balancer_test
    PRIVATE
    load_balancer
    packet_job_builder
    packet_parser
    pcap_reader
    dpi_types
    Threads::Threads
)

# ============================================================
# Fast Path Test
# ============================================================

add_executable(fast_path_test
    tests/fast_path_test.cpp
)

target_link_libraries(fast_path_test
    PRIVATE
    fast_path
    connection_tracker
    dpi_types
    Threads::Threads
)

# ============================================================
# Fast Path Manager Test
# ============================================================

add_executable(fp_manager_test
    tests/fp_manager_test.cpp
)

target_link_libraries(fp_manager_test
    PRIVATE
    fp_manager
    fast_path
    connection_tracker
    dpi_types
    Threads::Threads
)

# ============================================================
# Pipeline Manager Test
# ============================================================

add_executable(pipeline_manager_test
    tests/pipeline_manager_test.cpp
)

target_link_libraries(pipeline_manager_test
    PRIVATE
    pipeline_manager
    load_balancer
    fp_manager
    fast_path
    connection_tracker
    dpi_types
    Threads::Threads
)

# ============================================================
# DPI Engine Test
# ============================================================

add_executable(dpi_engine_test
    tests/dpi_engine_test.cpp
)

target_link_libraries(dpi_engine_test
    PRIVATE
    dpi_engine
    pipeline_manager
    rule_manager
    load_balancer
    fp_manager
    fast_path
    packet_job_builder
    packet_parser
    pcap_reader
    connection_tracker
    dpi_types
    Threads::Threads
)

# ============================================================
# SNI / HTTP Deep Inspection Test
# ============================================================

add_executable(sni_extractor_test
    tests/sni_extractor_test.cpp
)

target_link_libraries(sni_extractor_test
    PRIVATE
    sni_extractor
    dpi_types
)