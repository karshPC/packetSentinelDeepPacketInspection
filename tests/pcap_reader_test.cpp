#include "pcap_reader.h"

#include <iostream>
#include <string>

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: pcap_reader_test <pcap-file>\n";
        return 1;
    }

    const std::string filename = argv[1];

    PacketAnalyzer::PcapReader reader;

    if (!reader.open(filename)) {
        std::cerr << "Failed to open PCAP file\n";
        return 1;
    }

    PacketAnalyzer::RawPacket packet;

    uint64_t packet_count = 0;
    uint64_t total_bytes = 0;

    while (reader.readNextPacket(packet)) {
        ++packet_count;
        total_bytes += packet.data.size();

        std::cout << "Packet " << packet_count
                  << ": "
                  << packet.data.size()
                  << " bytes\n";
    }

    reader.close();

    std::cout << "\nPCAP processing complete\n";
    std::cout << "Packets: " << packet_count << '\n';
    std::cout << "Bytes:   " << total_bytes << '\n';

    return 0;
}