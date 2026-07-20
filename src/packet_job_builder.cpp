#include "packet_job_builder.h"

#include <algorithm>

namespace DPI {

PacketJob PacketJobBuilder::build(
    uint32_t packet_id,
    const PacketAnalyzer::RawPacket& raw_packet,
    const PacketAnalyzer::ParsedPacket& parsed_packet
) {
    PacketJob job;

    job.packet_id = packet_id;

    job.data = raw_packet.data;

    job.ts_sec = raw_packet.header.ts_sec;
    job.ts_usec = raw_packet.header.ts_usec;

    job.eth_offset = parsed_packet.eth_offset;
    job.ip_offset = parsed_packet.ip_offset;
    job.transport_offset = parsed_packet.transport_offset;
    job.payload_offset = parsed_packet.payload_offset;
    job.payload_length = parsed_packet.payload_length;

    job.tcp_flags = parsed_packet.tcp_flags;

    job.tuple =
        PacketAnalyzer::PacketParser::extractFiveTuple(
            parsed_packet
        );

    return job;
}

} // namespace DPI