cmake_minimum_required(VERSION 3.16)

project(PacketAnalyzer VERSION 1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Header files
include_directories(${CMAKE_SOURCE_DIR}/include)

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
        pthread
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
        pthread
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
        pthread
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
        pthread
)