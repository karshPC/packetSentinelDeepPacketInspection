#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <cstdint>
#include <cstddef>

namespace PacketAnalyzer {

// Ethernet header
struct EthernetHeader {
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t ether_type;
};

// IPv4 header
struct IPv4Header {
    uint8_t version_ihl;
    uint8_t tos;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_fragment_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
};

// Result of packet parsing
struct ParsedPacket {
    bool valid = false;

    const uint8_t* data = nullptr;
    size_t length = 0;

    const EthernetHeader* ethernet = nullptr;
    const IPv4Header* ipv4 = nullptr;

    uint16_t ether_type = 0;

    size_t ip_header_length = 0;
};

// Parser for raw Ethernet packets
class PacketParser {
public:
    static ParsedPacket parse(
        const uint8_t* data,
        size_t length
    );
};

} // namespace PacketAnalyzer

#endif // PACKET_PARSER_H