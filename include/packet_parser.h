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

// Result of packet parsing
struct ParsedPacket {
    bool valid = false;

    const uint8_t* data = nullptr;
    size_t length = 0;

    const EthernetHeader* ethernet = nullptr;

    uint16_t ether_type = 0;
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