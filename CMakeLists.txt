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

# ---- Packet parser ----
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

# ---- PCAP reader test ----
add_executable(pcap_reader_test
    tests/pcap_reader_test.cpp
)

target_link_libraries(pcap_reader_test
    PRIVATE
        pcap_reader
)

# ---- Packet parser test ----
add_executable(packet_parser_test
    tests/packet_parser_test.cpp
)

target_link_libraries(packet_parser_test
    PRIVATE
        packet_parser
        pcap_reader
)

# ---- Five tuple test ----
add_executable(five_tuple_test
    tests/five_tuple_test.cpp
)

target_link_libraries(five_tuple_test
    PRIVATE
        packet_parser
        pcap_reader
        dpi_types
)

# ---- Thread-safe queue test ----
add_executable(thread_safe_queue_test
    tests/thread_safe_queue_test.cpp

)

target_link_libraries(thread_safe_queue_test
    PRIVATE
        pthread
)