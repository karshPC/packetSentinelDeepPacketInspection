#ifndef PACKET_JOB_H
#define PACKET_JOB_H

#include "types.h"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace DPI {

struct PacketJob {
    uint32_t packet_id = 0;

    FiveTuple tuple{};

    std::vector<uint8_t> data;

    size_t eth_offset = 0;
    size_t ip_offset = 0;
    size_t transport_offset = 0;
    size_t payload_offset = 0;
    size_t payload_length = 0;

    uint8_t tcp_flags = 0;

    uint32_t ts_sec = 0;
    uint32_t ts_usec = 0;
};

} // namespace DPI

#endif // PACKET_JOB_H