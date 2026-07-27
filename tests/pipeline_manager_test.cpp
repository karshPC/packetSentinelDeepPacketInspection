#include "pipeline_manager.h"

#include <chrono>
#include <iostream>
#include <thread>

int main() {
    // ============================================================
    // Create:
    //
    // 2 Load Balancers
    // 4 Fast Paths
    //
    // LB0 -> FP0, FP1
    // LB1 -> FP2, FP3
    // ============================================================

    DPI::PipelineManager pipeline(
        2,
        2
    );

    pipeline.start();

    // ============================================================
    // Submit 20 PacketJobs.
    // ============================================================

    constexpr uint32_t PACKET_COUNT = 20;

    for (uint32_t i = 0;
         i < PACKET_COUNT;
         ++i) {

        DPI::PacketJob job;

        job.packet_id =
            i + 1;

        job.tuple.src_ip =
            0x6401A8C0 + i;

        job.tuple.dst_ip =
            0x08080808;

        job.tuple.src_port =
            static_cast<uint16_t>(
                40000 + i
            );

        job.tuple.dst_port = 443;

        job.tuple.protocol = 6;

        job.data.resize(
            100 + i
        );

        pipeline.submit(
            std::move(job)
        );
    }

    // ============================================================
    // Wait for all packets to pass through:
    //
    // Pipeline
    //    ->
    // LB
    //    ->
    // FP
    // ============================================================

    for (int i = 0;
         i < 100;
         ++i) {

        const auto stats =
            pipeline.getStats();

        if (stats.packets_processed_by_fp ==
            PACKET_COUNT) {

            break;
        }

        std::this_thread::sleep_for(
            std::chrono::milliseconds(10)
        );
    }

    const auto stats =
        pipeline.getStats();

    // ============================================================
    // Stop pipeline.
    // ============================================================

    pipeline.stop();

    // ============================================================
    // Report.
    // ============================================================

    std::cout
        << "\n========================================\n"
        << "Pipeline Manager Test\n"
        << "========================================\n";

    std::cout
        << "Packets submitted:       "
        << stats.packets_submitted
        << '\n';

    std::cout
        << "LB packets received:     "
        << stats.packets_received_by_lb
        << '\n';

    std::cout
        << "LB packets dispatched:   "
        << stats.packets_dispatched_by_lb
        << '\n';

    std::cout
        << "FP packets processed:    "
        << stats.packets_processed_by_fp
        << '\n';

    std::cout
        << "FP bytes processed:      "
        << stats.bytes_processed_by_fp
        << '\n';

    // ============================================================
    // Verify complete pipeline.
    // ============================================================

    if (stats.packets_submitted != PACKET_COUNT) {
        std::cerr
            << "ERROR: Incorrect submitted count\n";

        return 1;
    }

    if (stats.packets_received_by_lb != PACKET_COUNT) {
        std::cerr
            << "ERROR: LB did not receive all packets\n";

        return 1;
    }

    if (stats.packets_dispatched_by_lb != PACKET_COUNT) {
        std::cerr
            << "ERROR: LB did not dispatch all packets\n";

        return 1;
    }

    if (stats.packets_processed_by_fp != PACKET_COUNT) {
        std::cerr
            << "ERROR: FP did not process all packets\n";

        return 1;
    }

    std::cout
        << "Pipeline manager test passed\n";

    return 0;
}