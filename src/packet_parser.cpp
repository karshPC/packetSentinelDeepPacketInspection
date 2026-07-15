#include "packet_parser.h"

namespace PacketAnalyzer {

namespace {

constexpr size_t ETHERNET_HEADER_SIZE = 14;
constexpr uint16_t ETHERTYPE_IPV4 = 0x0800;

constexpr uint8_t IP_PROTOCOL_TCP = 6;

uint16_t read16(const uint8_t* data) {
    return static_cast<uint16_t>(
        (static_cast<uint16_t>(data[0]) << 8) |
        static_cast<uint16_t>(data[1])
    );
}

uint32_t read32(const uint8_t* data) {
    return
        (static_cast<uint32_t>(data[0]) << 24) |
        (static_cast<uint32_t>(data[1]) << 16) |
        (static_cast<uint32_t>(data[2]) << 8) |
        static_cast<uint32_t>(data[3]);
}

} // namespace

ParsedPacket PacketParser::parse(
    const uint8_t* data,
    size_t length
) {
    ParsedPacket packet;

    if (data == nullptr ||
        length < ETHERNET_HEADER_SIZE) {
        return packet;
    }

    packet.data = data;
    packet.length = length;

    packet.ethernet =
        reinterpret_cast<const EthernetHeader*>(data);

    packet.ether_type =
        read16(data + 12);

    if (packet.ether_type != ETHERTYPE_IPV4) {
        packet.valid = true;
        return packet;
    }

    constexpr size_t MIN_IPV4_HEADER_SIZE = 20;

    if (length <
        ETHERNET_HEADER_SIZE +
        MIN_IPV4_HEADER_SIZE) {
        return packet;
    }

    const uint8_t* ip_data =
        data + ETHERNET_HEADER_SIZE;

    packet.ipv4 =
        reinterpret_cast<const IPv4Header*>(ip_data);

    const uint8_t version =
        (ip_data[0] >> 4) & 0x0F;

    const uint8_t ihl =
        ip_data[0] & 0x0F;

    if (version != 4 || ihl < 5) {
        return packet;
    }

    packet.ip_header_length =
        static_cast<size_t>(ihl) * 4;

    if (length <
        ETHERNET_HEADER_SIZE +
        packet.ip_header_length) {
        return packet;
    }

    // Only TCP is handled at this stage.
    if (packet.ipv4->protocol != IP_PROTOCOL_TCP) {
        packet.valid = true;
        return packet;
    }

    const size_t tcp_offset =
        ETHERNET_HEADER_SIZE +
        packet.ip_header_length;

    constexpr size_t MIN_TCP_HEADER_SIZE = 20;

    if (length < tcp_offset + MIN_TCP_HEADER_SIZE) {
        return packet;
    }

    const uint8_t* tcp_data =
        data + tcp_offset;

    packet.tcp =
        reinterpret_cast<const TCPHeader*>(tcp_data);

    packet.src_port =
        read16(tcp_data);

    packet.dst_port =
        read16(tcp_data + 2);

    const uint8_t data_offset =
        (tcp_data[12] >> 4) & 0x0F;

    if (data_offset < 5) {
        return packet;
    }

    packet.tcp_header_length =
        static_cast<size_t>(data_offset) * 4;

    if (length <
        tcp_offset +
        packet.tcp_header_length) {
        return packet;
    }

    packet.payload =
        data +
        tcp_offset +
        packet.tcp_header_length;

    packet.payload_length =
        length -
        tcp_offset -
        packet.tcp_header_length;

    packet.valid = true;

    return packet;
}

} // namespace PacketAnalyzer