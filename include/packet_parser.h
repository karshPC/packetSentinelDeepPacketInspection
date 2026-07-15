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

// TCP header
struct TCPHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t sequence_number;
    uint32_t acknowledgement_number;
    uint8_t data_offset_reserved;
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_pointer;
};

// Result of packet parsing
struct ParsedPacket {
    bool valid = false;

    const uint8_t* data = nullptr;
    size_t length = 0;

    const EthernetHeader* ethernet = nullptr;
    const IPv4Header* ipv4 = nullptr;
    const TCPHeader* tcp = nullptr;

    uint16_t ether_type = 0;

    size_t ip_header_length = 0;
    size_t tcp_header_length = 0;

    uint16_t src_port = 0;
    uint16_t dst_port = 0;

    const uint8_t* payload = nullptr;
    size_t payload_length = 0;
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