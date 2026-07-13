#include "packet_parser.h"

namespace PacketAnalyzer {

namespace {

constexpr size_t ETHERNET_HEADER_SIZE = 14;

uint16_t read16(const uint8_t* data) {
    return static_cast<uint16_t>(
        (static_cast<uint16_t>(data[0]) << 8) |
        static_cast<uint16_t>(data[1])
    );
}

} // namespace

ParsedPacket PacketParser::parse(
    const uint8_t* data,
    size_t length
) {
    ParsedPacket packet;

    if (data == nullptr || length < ETHERNET_HEADER_SIZE) {
        return packet;
    }

    packet.data = data;
    packet.length = length;

    packet.ethernet =
        reinterpret_cast<const EthernetHeader*>(data);

    packet.ether_type =
        read16(data + 12);

    packet.valid = true;

    return packet;
}

} // namespace PacketAnalyzer