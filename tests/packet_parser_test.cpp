#include "pcap_reader.h"
#include "packet_parser.h"

#include <iostream>
#include <iomanip>
#include <cstdint>

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: packet_parser_test <pcap-file>\n";
        return 1;
    }

    PacketAnalyzer::PcapReader reader;

    if (!reader.open(argv[1])) {
        return 1;
    }

    PacketAnalyzer::RawPacket raw_packet;

    uint64_t packet_count = 0;
    uint64_t valid_packets = 0;
    uint64_t tcp_packets = 0;
    uint64_t udp_packets = 0;
    uint64_t other_packets = 0;
    uint64_t invalid_packets = 0;

    while (reader.readNextPacket(raw_packet)) {
        ++packet_count;

        PacketAnalyzer::ParsedPacket packet =
            PacketAnalyzer::PacketParser::parse(
                raw_packet.data.data(),
                raw_packet.data.size()
            );

        if (!packet.valid) {
            ++invalid_packets;

            std::cout << "Packet "
                      << packet_count
                      << ": INVALID\n";

            continue;
        }

        ++valid_packets;

        if (packet.tcp != nullptr) {
            ++tcp_packets;

            std::cout << "Packet "
                      << packet_count
                      << ": TCP "
                      << packet.src_port
                      << " -> "
                      << packet.dst_port
                      << ", payload="
                      << packet.payload_length
                      << " bytes\n";

        } else if (packet.udp != nullptr) {
            ++udp_packets;

            std::cout << "Packet "
                      << packet_count
                      << ": UDP "
                      << packet.src_port
                      << " -> "
                      << packet.dst_port
                      << ", payload="
                      << packet.payload_length
                      << " bytes\n";

        } else {
            ++other_packets;

            std::cout << "Packet "
                      << packet_count
                      << ": OTHER\n";
        }
    }

    reader.close();

    std::cout << "\n================================\n";
    std::cout << "Packet Parser Test Complete\n";
    std::cout << "================================\n";

    std::cout << "Total packets:   "
              << packet_count << '\n';

    std::cout << "Valid packets:   "
              << valid_packets << '\n';

    std::cout << "TCP packets:     "
              << tcp_packets << '\n';

    std::cout << "UDP packets:     "
              << udp_packets << '\n';

    std::cout << "Other packets:   "
              << other_packets << '\n';

    std::cout << "Invalid packets: "
              << invalid_packets << '\n';

    return 0;
}