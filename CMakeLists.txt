cmake_minimum_required(VERSION 3.16)

project(PacketAnalyzer VERSION 1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Header files location
include_directories(${CMAKE_SOURCE_DIR}/include)

# ---- Core DPI types ----
add_library(dpi_types
    src/types.cpp
)

target_include_directories(dpi_types
    PUBLIC
        ${CMAKE_SOURCE_DIR}/include
)

# ---- PCAP reader ----
add_library(pcap_reader
    src/pcap_reader.cpp
)

target_include_directories(pcap_reader
    PUBLIC
        ${CMAKE_SOURCE_DIR}/include
)

# ---- PCAP reader test ----
add_executable(pcap_reader_test
    tests/pcap_reader_test.cpp
)

target_link_libraries(pcap_reader_test
    PRIVATE
        pcap_reader
)