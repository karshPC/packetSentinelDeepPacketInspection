#ifndef FAST_PATH_H
#define FAST_PATH_H

#include "connection_tracker.h"
#include "packet_job.h"
#include "thread_safe_queue.h"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <thread>

namespace DPI {

// ============================================================================
// Fast Path
// ============================================================================
//
// Each FastPath owns:
//
//     PacketJob queue
//           |
//           v
//      FastPath worker
//           |
//           v
//    ConnectionTracker
//
// The Load Balancer obtains the queue through getInputQueue().
//
// ============================================================================

class FastPath {
public:
    FastPath(
        int fp_id,
        size_t max_connections = 100000
    );

    ~FastPath();

    // Start worker thread.
    void start();

    // Stop worker thread.
    void stop();

    // Process one packet synchronously.
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

    struct FPStats {
        uint64_t packets_processed = 0;
        uint64_t bytes_processed = 0;
        uint64_t connections_created = 0;
        uint64_t active_connections = 0;
    };

    FPStats getStats() const;

    ConnectionTracker& getConnectionTracker() {
        return tracker_;
    }

private:
    int fp_id_;

    // FastPath owns its own queue.
    ThreadSafeQueue<PacketJob> input_queue_;

    // Each FP owns its own connection tracker.
    ConnectionTracker tracker_;

    std::atomic<bool> running_{false};

    std::atomic<uint64_t> packets_processed_{0};
    std::atomic<uint64_t> bytes_processed_{0};

    std::thread thread_;

    void run();

    bool isOutbound(
        const PacketJob& job
    ) const;
};

} // namespace DPI

#endif // FAST_PATH_H