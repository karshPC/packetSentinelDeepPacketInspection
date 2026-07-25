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
// Each FastPath instance owns:
//
//     PacketJob queue
//           |
//           v
//      FastPath worker
//           |
//           v
//    ConnectionTracker
//
// A FastPath processes all packets assigned to its queue.
//
// ============================================================================

class FastPath {
public:
    FastPath(
        int fp_id,
        ThreadSafeQueue<PacketJob>& input_queue,
        size_t max_connections = 100000
    );

    ~FastPath();

    // Start the worker thread.
    void start();

    // Stop the worker thread.
    void stop();

    // Process one packet synchronously.
    bool processPacket(
        const PacketJob& job
    );

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

    ThreadSafeQueue<PacketJob>& input_queue_;

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