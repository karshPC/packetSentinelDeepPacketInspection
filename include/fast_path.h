#ifndef FAST_PATH_H
#define FAST_PATH_H

#include "rule_manager.h"
#include "connection_tracker.h"
#include "packet_job.h"
#include "thread_safe_queue.h"
#include "sni_extractor.h"

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
//     PacketJob input queue
//           |
//           v
//      FastPath worker
//           |
//           v
//      ConnectionTracker
//           |
//           v
//      Application Inspection
//       /              \
//     TLS              HTTP
//      |                |
//     SNI              Host
//      |                |
//      +-------+--------+
//              |
//              v
//        Application Classification
//              |
//              v
//          RuleManager
//          /        \
//       DROP       ACCEPT
//        |            |
//        v            v
//      discard    Output Queue
//
// The Load Balancer obtains the input queue through getInputQueue().
//
// The RuleManager may be shared by all FastPaths.
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
    // Returns true if the packet is accepted.
    // Returns false if the packet is dropped.
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
    void setRuleManager(
        RuleManager* rule_manager
    );

    RuleManager* getRuleManager() const {
        return rule_manager_;
    }

    // Attach or replace the output queue.
    void setOutputQueue(
        ThreadSafeQueue<PacketJob>* output_queue
    );

    ThreadSafeQueue<PacketJob>* getOutputQueue() const {
        return output_queue_;
    }

    // ========================================================================
    // Statistics
    // ========================================================================

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

    // Each FastPath owns its own connection tracker.
    ConnectionTracker tracker_;

    // Shared RuleManager.
    RuleManager* rule_manager_ = nullptr;

    // Shared output queue owned by DPIEngine.
    // FastPath does not own this object.
    ThreadSafeQueue<PacketJob>* output_queue_ = nullptr;

    std::atomic<bool> running_{false};

    std::atomic<uint64_t> packets_processed_{0};
    std::atomic<uint64_t> bytes_processed_{0};
    std::atomic<uint64_t> packets_dropped_{0};

    std::thread thread_;

    // Worker loop.
    void run();

    // Determine whether the packet originates from a private
    // network address.
    bool isOutbound(
        const PacketJob& job
    ) const;

    // Evaluate all applicable rules after application
    // classification has taken place.
    //
    // The connection contains:
    //   - AppType
    //   - SNI / Host
    //
    // Returns true when the packet/connection should be dropped.
    bool shouldDrop(
        const PacketJob& job,
        const Connection* connection
    ) const;

    // Inspect application payload and classify the connection.
    //
    // TLS:
    //     ClientHello -> SNI -> AppType
    //
    // HTTP:
    //     Host header -> AppType
    void inspectApplication(
        const PacketJob& job,
        Connection* connection
    );
};

} // namespace DPI

#endif // FAST_PATH_H