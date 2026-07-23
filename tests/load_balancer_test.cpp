#include "load_balancer.h"

#include <chrono>
#include <iostream>
#include <thread>
#include <vector>

int main() {
    using namespace DPI;

    // ------------------------------------------------------------
    // Create four FP queues.
    // ------------------------------------------------------------

    ThreadSafeQueue<PacketJob> fp0(100);
    ThreadSafeQueue<PacketJob> fp1(100);
    ThreadSafeQueue<PacketJob> fp2(100);
    ThreadSafeQueue<PacketJob> fp3(100);

    std::vector<
        ThreadSafeQueue<PacketJob>*
    > fp_queues = {
        &fp0,
        &fp1,
        &fp2,
        &fp3
    };

    // ------------------------------------------------------------
    // Create two load balancers.
    //
    // LB0 -> FP0, FP1
    // LB1 -> FP2, FP3
    // ------------------------------------------------------------

    LBManager manager(
        2,
        2,
        fp_queues
    );

    if (manager.getNumLBs() != 2) {
        std::cerr
            << "Incorrect number of load balancers\n";

        return 1;
    }

    manager.startAll();

    // ------------------------------------------------------------
    // Create test packets.
    // ------------------------------------------------------------

    std::vector<PacketJob> jobs;

    for (uint32_t i = 0; i < 20; ++i) {
        PacketJob job{};

        job.packet_id = i;

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

        jobs.push_back(
            std::move(job)
        );
    }

    // ------------------------------------------------------------
    // Send packets through the LB layer.
    // ------------------------------------------------------------

    for (const auto& job : jobs) {
        LoadBalancer& lb =
            manager.getLBForPacket(
                job.tuple
            );

        lb.getInputQueue().push(job);
    }

    // Give worker threads time to dispatch.
    std::this_thread::sleep_for(
        std::chrono::milliseconds(300)
    );

    manager.stopAll();

    // ------------------------------------------------------------
    // Verify aggregated statistics.
    // ------------------------------------------------------------

    const auto stats =
        manager.getAggregatedStats();

    if (stats.total_received != jobs.size()) {
        std::cerr
            << "Expected "
            << jobs.size()
            << " packets received, got "
            << stats.total_received
            << "\n";

        return 1;
    }

    if (stats.total_dispatched != jobs.size()) {
        std::cerr
            << "Expected "
            << jobs.size()
            << " packets dispatched, got "
            << stats.total_dispatched
            << "\n";

        return 1;
    }

    // ------------------------------------------------------------
    // Count packets arriving at FP queues.
    // ------------------------------------------------------------

    size_t total_fp_packets = 0;

    const std::vector<
        ThreadSafeQueue<PacketJob>*
    > queues = {
        &fp0,
        &fp1,
        &fp2,
        &fp3
    };

    for (auto* queue : queues) {
        total_fp_packets += queue->size();
    }

    if (total_fp_packets != jobs.size()) {
        std::cerr
            << "Expected "
            << jobs.size()
            << " packets in FP queues, got "
            << total_fp_packets
            << "\n";

        return 1;
    }

    // ------------------------------------------------------------
    // Verify deterministic hashing.
    //
    // The same tuple should always map to the same LB.
    // ------------------------------------------------------------

    FiveTuple test_tuple =
        jobs[0].tuple;

    LoadBalancer& lb_a =
        manager.getLBForPacket(
            test_tuple
        );

    LoadBalancer& lb_b =
        manager.getLBForPacket(
            test_tuple
        );

    if (lb_a.getId() != lb_b.getId()) {
        std::cerr
            << "FiveTuple hashing is not deterministic\n";

        return 1;
    }

    std::cout
        << "Load balancer test passed\n";

    return 0;
}