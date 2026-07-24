#include "load_balancer.h"
#include "packet_job_builder.h"
#include "packet_parser.h"
#include "pcap_reader.h"

#include <chrono>
#include <iostream>
#include <thread>
#include <vector>

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr
            << "Usage: pcap_load_balancer_test <pcap-file>\n";

        return 1;
    }

    // ============================================================
    // Create four FP queues.
    //
    // LB0 -> FP0, FP1
    // LB1 -> FP2, FP3
    // ============================================================

    DPI::ThreadSafeQueue<DPI::PacketJob> fp0(1000);
    DPI::ThreadSafeQueue<DPI::PacketJob> fp1(1000);
    DPI::ThreadSafeQueue<DPI::PacketJob> fp2(1000);
    DPI::ThreadSafeQueue<DPI::PacketJob> fp3(1000);

    std::vector<
        DPI::ThreadSafeQueue<DPI::PacketJob>*
    > fp_queues = {
        &fp0,
        &fp1,
        &fp2,
        &fp3
    };

    DPI::LBManager manager(
        2,
        2,
        fp_queues
    );

    manager.startAll();

    // ============================================================
    // Open the real PCAP file.
    // ============================================================

    PacketAnalyzer::PcapReader reader;

    if (!reader.open(argv[1])) {
        manager.stopAll();
        return 1;
    }

    PacketAnalyzer::RawPacket raw_packet;

    uint32_t packet_id = 0;
    uint64_t jobs_created = 0;

    // ============================================================
    // Read every packet and send it through the LB layer.
    // ============================================================

    while (reader.readNextPacket(raw_packet)) {
        ++packet_id;

        PacketAnalyzer::ParsedPacket parsed_packet =
            PacketAnalyzer::PacketParser::parse(
                raw_packet.data.data(),
                raw_packet.data.size()
            );

        if (!parsed_packet.valid) {
            std::cerr
                << "Invalid packet: "
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

        DPI::LoadBalancer& lb =
            manager.getLBForPacket(
                job.tuple
            );

        lb.getInputQueue().push(
            std::move(job)
        );

        ++jobs_created;
    }

    reader.close();

    // ============================================================
    // Give the LB worker threads time to drain their input queues.
    // ============================================================

    while (true) {
        const auto stats =
            manager.getAggregatedStats();

        if (stats.total_dispatched ==
            jobs_created) {
            break;
        }

        std::this_thread::sleep_for(
            std::chrono::milliseconds(10)
        );
    }

    manager.stopAll();

    // ============================================================
    // Collect packets from all FP queues.
    // ============================================================

    std::vector<
        DPI::ThreadSafeQueue<DPI::PacketJob>*
    > queues = {
        &fp0,
        &fp1,
        &fp2,
        &fp3
    };

    uint64_t total_fp_packets = 0;

    std::cout
        << "\n================================\n"
        << "FP Queue Distribution\n"
        << "================================\n";

    for (size_t i = 0;
         i < queues.size();
         ++i) {

        const size_t count =
            queues[i]->size();

        total_fp_packets += count;

        std::cout
            << "FP"
            << i
            << ": "
            << count
            << " packets\n";
    }

    // ============================================================
    // Load balancer statistics.
    // ============================================================

    const auto stats =
        manager.getAggregatedStats();

    std::cout
        << "\n================================\n"
        << "PCAP Load Balancer Test\n"
        << "================================\n";

    std::cout
        << "Packets read:       "
        << packet_id
        << '\n';

    std::cout
        << "Jobs created:       "
        << jobs_created
        << '\n';

    std::cout
        << "LB received:        "
        << stats.total_received
        << '\n';

    std::cout
        << "LB dispatched:      "
        << stats.total_dispatched
        << '\n';

    std::cout
        << "FP packets total:   "
        << total_fp_packets
        << '\n';

    // ============================================================
    // Verify the complete pipeline.
    // ============================================================

    if (packet_id != 77) {
        std::cerr
            << "ERROR: Expected 77 packets, got "
            << packet_id
            << '\n';

        return 1;
    }

    if (jobs_created != packet_id) {
        std::cerr
            << "ERROR: Not every packet produced a PacketJob\n";

        return 1;
    }

    if (stats.total_received != jobs_created) {
        std::cerr
            << "ERROR: LB did not receive all jobs\n";

        return 1;
    }

    if (stats.total_dispatched != jobs_created) {
        std::cerr
            << "ERROR: LB did not dispatch all jobs\n";

        return 1;
    }

    if (total_fp_packets != jobs_created) {
        std::cerr
            << "ERROR: FP queues did not receive all jobs\n";

        return 1;
    }

    std::cout
        << "\nPCAP -> LB -> FP pipeline test passed\n";

    return 0;
}