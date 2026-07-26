#include "fp_manager.h"

#include <chrono>
#include <iostream>
#include <thread>

int main() {
    // ============================================================
    // Create four Fast Paths.
    // ============================================================

    DPI::FPManager manager(
        4
    );

    if (manager.getNumFPs() != 4) {
        std::cerr
            << "Expected 4 Fast Paths\n";

        return 1;
    }

    // ============================================================
    // Get queue pointers for the Load Balancer.
    // ============================================================

    auto queues =
        manager.getQueuePtrs();

    if (queues.size() != 4) {
        std::cerr
            << "Expected 4 FP queues\n";

        return 1;
    }

    // ============================================================
    // Start all Fast Paths.
    // ============================================================

    manager.startAll();

    if (!manager.allRunning()) {
        std::cerr
            << "Not all Fast Paths started\n";

        manager.stopAll();

        return 1;
    }

    // ============================================================
    // Create one packet for each FP queue.
    // ============================================================

    for (uint32_t i = 0; i < 4; ++i) {
        DPI::PacketJob job;

        job.packet_id =
            i + 1;

        job.tuple.src_ip =
            0x6401A8C0 + i;

        job.tuple.dst_ip =
            0x08080808;

        job.tuple.src_port =
            static_cast<uint16_t>(
                50000 + i
            );

        job.tuple.dst_port = 443;

        job.tuple.protocol = 6;

        job.data.resize(
            100 + i
        );

        queues[i]->push(
            job
        );
    }

    // Give the workers time to process.
    std::this_thread::sleep_for(
        std::chrono::milliseconds(300)
    );

    // ============================================================
    // Read aggregated statistics.
    // ============================================================

    const auto stats =
        manager.getAggregatedStats();

    std::cout
        << "\n========================================\n"
        << "FP Manager Test\n"
        << "========================================\n";

    std::cout
        << "Fast Paths:          "
        << manager.getNumFPs()
        << '\n';

    std::cout
        << "Packets processed:   "
        << stats.total_processed
        << '\n';

    std::cout
        << "Bytes processed:     "
        << stats.total_bytes
        << '\n';

    std::cout
        << "Connections seen:    "
        << stats.total_connections
        << '\n';

    // ============================================================
    // Stop all workers.
    // ============================================================

    manager.stopAll();

    // ============================================================
    // Verify.
    // ============================================================

    if (stats.total_processed != 4) {
        std::cerr
            << "Expected 4 processed packets, got "
            << stats.total_processed
            << '\n';

        return 1;
    }

    if (stats.total_connections != 4) {
        std::cerr
            << "Expected 4 connections, got "
            << stats.total_connections
            << '\n';

        return 1;
    }

    std::cout
        << "FP manager test passed\n";

    return 0;
}