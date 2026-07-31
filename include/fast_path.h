#ifndef FAST_PATH_H
#define FAST_PATH_H

#include "rule_manager.h"
#include "connection_tracker.h"
#include "packet_job.h"
#include "thread_safe_queue.h"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <string>
#include <thread>

namespace DPI {

// ============================================================================
// Fast Path
// ============================================================================
//
// Each FastPath owns:
//
//     PacketJob input queue
//           |
//           v
//      FastPath worker
//           |
//           v
//      RuleManager check
//           |
//       +---+---+
//       |       |
//      DROP   FORWARD
//       |       |
//       v       v
//    drop    ConnectionTracker
//                |
//                v
//           Output Queue
//
// The Load Balancer obtains the input queue through getInputQueue().
//
// Accepted packets are pushed into the shared output queue.
// Dropped packets never reach the output queue.
//
// ============================================================================

class FastPath {
public:

    FastPath(
        int fp_id,
        size_t max_connections = 100000,
        RuleManager* rule_manager = nullptr,
        ThreadSafeQueue<PacketJob>* output_queue = nullptr
    );

    ~FastPath();

    // Start worker thread.
    void start();

    // Stop worker thread.
    void stop();

    // Process one packet synchronously.
    //
    // Returns true if the packet is accepted/processed.
    // Returns false if the packet is dropped by a rule.
    bool processPacket(
        const PacketJob& job
    );

    // Get the input queue used by the Load Balancer.
    ThreadSafeQueue<PacketJob>& getInputQueue() {
        return input_queue_;
    }

    int getId() const {
        return fp_id_;
    }

    bool isRunning() const {
        return running_.load();
    }

    // Attach or replace the RuleManager.
    //
    // RuleManager is thread-safe, so multiple FastPaths
    // can safely point to the same instance.
    void setRuleManager(
        RuleManager* rule_manager
    );

    RuleManager* getRuleManager() const {
        return rule_manager_;
    }

    // Attach or replace the output queue.
    //
    // Accepted packets are pushed into this queue after
    // FastPath processing. Dropped packets are never pushed.
    void setOutputQueue(
        ThreadSafeQueue<PacketJob>* output_queue
    );

    ThreadSafeQueue<PacketJob>* getOutputQueue() const {
        return output_queue_;
    }

    struct FPStats {
        uint64_t packets_processed = 0;
        uint64_t bytes_processed = 0;
        uint64_t packets_dropped = 0;
        uint64_t connections_created = 0;
        uint64_t active_connections = 0;
    };

    FPStats getStats() const;

    ConnectionTracker& getConnectionTracker() {
        return tracker_;
    }

private:

    int fp_id_;

    // FastPath owns its own input queue.
    ThreadSafeQueue<PacketJob> input_queue_;

    // Each FP owns its own connection tracker.
    ConnectionTracker tracker_;

    // Optional shared RuleManager.
    //
    // All FastPaths may point to the same RuleManager.
    RuleManager* rule_manager_ = nullptr;

    // Shared output queue owned by DPIEngine.
    //
    // FastPaths only hold a non-owning pointer.
    ThreadSafeQueue<PacketJob>* output_queue_ = nullptr;

    std::atomic<bool> running_{false};

    std::atomic<uint64_t> packets_processed_{0};
    std::atomic<uint64_t> bytes_processed_{0};
    std::atomic<uint64_t> packets_dropped_{0};

    std::thread thread_;

    void run();

    bool isOutbound(
        const PacketJob& job
    ) const;

    // Returns true when the packet should be dropped.
    bool shouldDrop(
        const PacketJob& job
    ) const;
};

} // namespace DPI

#endif // FAST_PATH_H