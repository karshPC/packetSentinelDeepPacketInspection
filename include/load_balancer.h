#ifndef LOAD_BALANCER_H
#define LOAD_BALANCER_H

#include "packet_job.h"
#include "thread_safe_queue.h"
#include "types.h"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <thread>
#include <utility>
#include <vector>

namespace DPI {

// ============================================================================
// Load Balancer
// ============================================================================
//
// Reader
//   |
//   v
// Load Balancer
//   |
//   +----> FP Queue 0
//   |
//   +----> FP Queue 1
//   |
//   +----> FP Queue 2
//   |
//   +----> FP Queue 3
//
// Packets belonging to the same FiveTuple are deterministically assigned
// using the FiveTuple hash.
// ============================================================================

class LoadBalancer {
public:
    LoadBalancer(
        int lb_id,
        std::vector<ThreadSafeQueue<PacketJob>*> fp_queues,
        int fp_start_id
    );

    ~LoadBalancer();

    // Start the LB worker thread.
    void start();

    // Stop the LB worker thread.
    void stop();

    // Queue used by the reader to submit PacketJobs.
    ThreadSafeQueue<PacketJob>& getInputQueue() {
        return input_queue_;
    }

    struct LBStats {
        uint64_t packets_received = 0;
        uint64_t packets_dispatched = 0;

        std::vector<uint64_t> per_fp_packets;
    };

    LBStats getStats() const;

    int getId() const {
        return lb_id_;
    }

    bool isRunning() const {
        return running_.load();
    }

private:
    int lb_id_;
    int fp_start_id_;
    int num_fps_;

    // Input queue receiving jobs from the reader.
    ThreadSafeQueue<PacketJob> input_queue_;

    // Output queues belonging to the FPs served by this LB.
    std::vector<
        ThreadSafeQueue<PacketJob>*
    > fp_queues_;

    // Statistics.
    std::atomic<uint64_t> packets_received_{0};
    std::atomic<uint64_t> packets_dispatched_{0};

    std::vector<uint64_t> per_fp_counts_;

    // Thread control.
    std::atomic<bool> running_{false};
    std::thread thread_;

    // Worker loop.
    void run();

    // Select an FP using the FiveTuple hash.
    int selectFP(
        const FiveTuple& tuple
    ) const;
};

// ============================================================================
// Load Balancer Manager
// ============================================================================

class LBManager {
public:
    LBManager(
        int num_lbs,
        int fps_per_lb,
        std::vector<ThreadSafeQueue<PacketJob>*> fp_queues
    );

    ~LBManager();

    // Start every LB thread.
    void startAll();

    // Stop every LB thread.
    void stopAll();

    // Select the LB responsible for a packet.
    LoadBalancer& getLBForPacket(
        const FiveTuple& tuple
    );

    // Access a specific LB.
    LoadBalancer& getLB(int id) {
        return *lbs_[id];
    }

    int getNumLBs() const {
        return static_cast<int>(
            lbs_.size()
        );
    }

    struct AggregatedStats {
        uint64_t total_received = 0;
        uint64_t total_dispatched = 0;
    };

    AggregatedStats getAggregatedStats() const;

private:
    std::vector<
        std::unique_ptr<LoadBalancer>
    > lbs_;

    int fps_per_lb_;
};

} // namespace DPI

#endif // LOAD_BALANCER_H