#ifndef PACKET_JOB_BUILDER_H
#define PACKET_JOB_BUILDER_H

#include "packet_job.h"
#include "packet_parser.h"
#include "pcap_reader.h"

namespace DPI {

class PacketJobBuilder {
public:
    static PacketJob build(
        uint32_t packet_id,
        const PacketAnalyzer::RawPacket& raw_packet,
        const PacketAnalyzer::ParsedPacket& parsed_packet
    );
};

} // namespace DPI

#endif // PACKET_JOB_BUILDER_H