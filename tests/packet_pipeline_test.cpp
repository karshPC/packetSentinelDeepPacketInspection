#include "packet_job.h"
#include "packet_job_builder.h"
#include "packet_parser.h"
#include "pcap_reader.h"
#include "thread_safe_queue.h"

#include <atomic>
#include <iostream>
#include <thread>

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: packet_pipeline_test <pcap-file>\n";
        return 1;
    }

    DPI::ThreadSafeQueue<DPI::PacketJob> queue(16);

    std::atomic<uint64_t> produced{0};
    std::atomic<uint64_t> consumed{0};

    std::thread producer(
        [&queue, &produced, filename = std::string(argv[1])]() {

            PacketAnalyzer::PcapReader reader;

            if (!reader.open(filename)) {
                queue.shutdown();
                return;
            }

            PacketAnalyzer::RawPacket raw_packet;

            uint32_t packet_id = 0;

            while (reader.readNextPacket(raw_packet)) {
                ++packet_id;

                PacketAnalyzer::ParsedPacket parsed_packet =
                    PacketAnalyzer::PacketParser::parse(
                        raw_packet.data.data(),
                        raw_packet.data.size()
                    );

                if (!parsed_packet.valid) {
                    continue;
                }

                DPI::PacketJob job =
                    DPI::PacketJobBuilder::build(
                        packet_id,
                        raw_packet,
                        parsed_packet
                    );

                queue.push(job);

                ++produced;
            }

            reader.close();

            queue.shutdown();
        }
    );

    std::thread consumer(
        [&queue, &consumed]() {

            DPI::PacketJob job;

            while (queue.pop(job)) {
                ++consumed;

                std::cout
                    << "Consumed job "
                    << job.packet_id
                    << ": "
                    << job.tuple.toString()
                    << '\n';
            }
        }
    );

    producer.join();
    consumer.join();

    std::cout << "\n================================\n";
    std::cout << "Packet Pipeline Test Complete\n";
    std::cout << "================================\n";

    std::cout << "Jobs produced: "
              << produced.load()
              << '\n';

    std::cout << "Jobs consumed: "
              << consumed.load()
              << '\n';

    std::cout << "Queue remaining: "
              << queue.size()
              << '\n';

    if (produced != consumed) {
        std::cerr << "ERROR: Produced and consumed counts differ\n";
        return 1;
    }

    if (!queue.empty()) {
        std::cerr << "ERROR: Queue is not empty\n";
        return 1;
    }

    std::cout << "Producer/consumer pipeline test passed\n";

    return 0;
}