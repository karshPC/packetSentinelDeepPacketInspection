#include "packet_parser.h"

namespace PacketAnalyzer {

namespace {

constexpr size_t ETHERNET_HEADER_SIZE = 14;
constexpr uint16_t ETHERTYPE_IPV4 = 0x0800;

constexpr uint8_t IP_PROTOCOL_TCP = 6;
constexpr uint8_t IP_PROTOCOL_UDP = 17;

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

    if (data == nullptr ||
        length < ETHERNET_HEADER_SIZE) {
        return packet;
    }

    packet.data = data;
    packet.length = length;
    packet.eth_offset = 0;

    packet.ethernet =
        reinterpret_cast<const EthernetHeader*>(data);

    packet.ether_type =
        read16(data + 12);

    if (packet.ether_type != ETHERTYPE_IPV4) {
        packet.valid = true;
        return packet;
    }

    constexpr size_t MIN_IPV4_HEADER_SIZE = 20;

    packet.ip_offset = ETHERNET_HEADER_SIZE;

    if (length <
        packet.ip_offset +
        MIN_IPV4_HEADER_SIZE) {
        return packet;
    }

    const uint8_t* ip_data =
        data + packet.ip_offset;

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
        packet.ip_offset +
        packet.ip_header_length) {
        return packet;
    }

    packet.protocol =
        packet.ipv4->protocol;

    packet.transport_offset =
        packet.ip_offset +
        packet.ip_header_length;

    // ================================================================
    // TCP
    // ================================================================

    if (packet.protocol == IP_PROTOCOL_TCP) {

        constexpr size_t MIN_TCP_HEADER_SIZE = 20;

        if (length <
            packet.transport_offset +
            MIN_TCP_HEADER_SIZE) {
            return packet;
        }

        const uint8_t* tcp_data =
            data + packet.transport_offset;

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

        packet.transport_header_length =
            static_cast<size_t>(data_offset) * 4;

        if (length <
            packet.transport_offset +
            packet.transport_header_length) {
            return packet;
        }

        packet.tcp_flags =
            tcp_data[13];

        packet.payload_offset =
            packet.transport_offset +
            packet.transport_header_length;

        packet.payload =
            data + packet.payload_offset;

        packet.payload_length =
            length - packet.payload_offset;

        packet.valid = true;

        return packet;
    }

    // ================================================================
    // UDP
    // ================================================================

    if (packet.protocol == IP_PROTOCOL_UDP) {

        constexpr size_t UDP_HEADER_SIZE = 8;

        if (length <
            packet.transport_offset +
            UDP_HEADER_SIZE) {
            return packet;
        }

        const uint8_t* udp_data =
            data + packet.transport_offset;

        packet.udp =
            reinterpret_cast<const UDPHeader*>(udp_data);

        packet.src_port =
            read16(udp_data);

        packet.dst_port =
            read16(udp_data + 2);

        packet.transport_header_length =
            UDP_HEADER_SIZE;

        packet.payload_offset =
            packet.transport_offset +
            UDP_HEADER_SIZE;

        packet.payload =
            data + packet.payload_offset;

        packet.payload_length =
            length - packet.payload_offset;

        packet.valid = true;

        return packet;
    }

    packet.valid = true;

    return packet;
}

DPI::FiveTuple PacketParser::extractFiveTuple(
    const ParsedPacket& packet
) {
    DPI::FiveTuple tuple{};

    if (!packet.valid ||
        packet.ipv4 == nullptr) {
        return tuple;
    }

    tuple.src_ip =
        packet.ipv4->src_ip;

    tuple.dst_ip =
        packet.ipv4->dst_ip;

    tuple.src_port =
        packet.src_port;

    tuple.dst_port =
        packet.dst_port;

    tuple.protocol =
        packet.protocol;

    return tuple;
}

} // namespace PacketAnalyzer