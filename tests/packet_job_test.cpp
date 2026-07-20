#include "packet_job.h"
#include "packet_job_builder.h"
#include "packet_parser.h"
#include "pcap_reader.h"

#include <iostream>

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: packet_job_test <pcap-file>\n";
        return 1;
    }

    PacketAnalyzer::PcapReader reader;

    if (!reader.open(argv[1])) {
        return 1;
    }

    PacketAnalyzer::RawPacket raw_packet;

    uint32_t packet_id = 0;
    uint64_t jobs_created = 0;

    while (reader.readNextPacket(raw_packet)) {
        ++packet_id;

        PacketAnalyzer::ParsedPacket parsed_packet =
            PacketAnalyzer::PacketParser::parse(
                raw_packet.data.data(),
                raw_packet.data.size()
            );

        if (!parsed_packet.valid) {
            std::cerr << "Invalid packet: "
                      << packet_id
                      << '\n';

            continue;
        }

        DPI::PacketJob job =
            DPI::PacketJobBuilder::build(
                packet_id,
                raw_packet,
                parsed_packet
            );

        ++jobs_created;

        std::cout
            << "Job "
            << job.packet_id
            << ": "
            << job.tuple.toString()
            << ", payload="
            << job.payload_length
            << " bytes\n";
    }

    reader.close();

    std::cout << "\n================================\n";
    std::cout << "Packet Job Test Complete\n";
    std::cout << "================================\n";

    std::cout << "Packets read: "
              << packet_id
              << '\n';

    std::cout << "Jobs created: "
              << jobs_created
              << '\n';

    if (jobs_created != packet_id) {
        std::cerr << "Not every packet produced a job\n";
        return 1;
    }

    return 0;
}