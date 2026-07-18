#include "pcap_reader.h"
#include "packet_parser.h"
#include "types.h"

#include <iostream>
#include <iomanip>
#include <string>

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: five_tuple_test <pcap-file>\n";
        return 1;
    }

    PacketAnalyzer::PcapReader reader;

    if (!reader.open(argv[1])) {
        return 1;
    }

    PacketAnalyzer::RawPacket raw_packet;

    uint64_t packet_count = 0;
    uint64_t tuple_count = 0;

    while (reader.readNextPacket(raw_packet)) {
        ++packet_count;

        PacketAnalyzer::ParsedPacket packet =
            PacketAnalyzer::PacketParser::parse(
                raw_packet.data.data(),
                raw_packet.data.size()
            );

        if (!packet.valid || packet.ipv4 == nullptr) {
            continue;
        }

        DPI::FiveTuple tuple =
            PacketAnalyzer::PacketParser::extractFiveTuple(packet);

        ++tuple_count;

        std::cout
            << "Packet "
            << packet_count
            << ": "
            << tuple.toString()
            << '\n';
    }

    reader.close();

    std::cout << "\n================================\n";
    std::cout << "FiveTuple Test Complete\n";
    std::cout << "================================\n";
    std::cout << "Packets read: "
              << packet_count
              << '\n';

    std::cout << "Five-tuples extracted: "
              << tuple_count
              << '\n';

    return 0;
}