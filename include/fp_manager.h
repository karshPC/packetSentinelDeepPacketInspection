#ifndef FP_MANAGER_H
#define FP_MANAGER_H

#include "fast_path.h"
#include "packet_job.h"
#include "thread_safe_queue.h"
#include "rule_manager.h"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace DPI {

// ============================================================================
// Fast Path Manager
// ============================================================================
//
// Owns all FastPath workers.
//
// Responsibilities:
//
// 1. Create FastPath instances.
// 2. Start/stop all FastPath workers.
// 3. Expose FP input queues to the Load Balancer.
// 4. Expose individual FP instances for inspection/reporting.
// 5. Aggregate FastPath statistics.
// 6. Attach the shared RuleManager to every FastPath.
// 7. Attach the shared output queue to every FastPath.
//
// ============================================================================

class FPManager {
public:

    explicit FPManager(
        int num_fps,
        size_t max_connections = 100000,
        RuleManager* rule_manager = nullptr,
        ThreadSafeQueue<PacketJob>* output_queue = nullptr
    );

    ~FPManager();

    // Start all FastPath worker threads.
    void startAll();

    // Stop all FastPath worker threads.
    void stopAll();

    // Get a specific FastPath.
    FastPath& getFP(int id) {
        return *fps_.at(
            static_cast<size_t>(id)
        );
    }

    // Get a specific FastPath input queue.
    ThreadSafeQueue<PacketJob>& getFPQueue(
        int id
    ) {
        return fps_.at(
            static_cast<size_t>(id)
        )->getInputQueue();
    }

    // Get raw queue pointers for Load Balancer Manager.
    std::vector<
        ThreadSafeQueue<PacketJob>*
    > getQueuePtrs();

    // Number of FastPath workers.
    int getNumFPs() const {
        return static_cast<int>(
            fps_.size()
        );
    }

    // Check whether all FastPaths are running.
    bool allRunning() const;

    // Aggregated FastPath statistics.
    struct AggregatedStats {
        uint64_t total_processed = 0;
        uint64_t total_bytes = 0;
        uint64_t total_dropped = 0;
        uint64_t total_connections = 0;
        uint64_t total_active_connections = 0;
    };

    AggregatedStats getAggregatedStats() const;

    // Generate a simple statistics report.
    std::string generateReport() const;

    // Attach or replace the shared RuleManager.
    void setRuleManager(
        RuleManager* rule_manager
    );

    RuleManager* getRuleManager() const {
        return rule_manager_;
    }

    // Attach or replace the shared output queue.
    void setOutputQueue(
        ThreadSafeQueue<PacketJob>* output_queue
    );

    ThreadSafeQueue<PacketJob>* getOutputQueue() const {
        return output_queue_;
    }

private:

    std::vector<
        std::unique_ptr<FastPath>
    > fps_;

    // Shared RuleManager used by all FastPaths.
    RuleManager* rule_manager_;

    // Output queue owned by DPIEngine.
    // FPManager only stores the pointer.
    ThreadSafeQueue<PacketJob>* output_queue_;
};

} // namespace DPI

#endif // FP_MANAGER_H