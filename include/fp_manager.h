#ifndef FP_MANAGER_H
#define FP_MANAGER_H

#include "fast_path.h"
#include "packet_job.h"
#include "thread_safe_queue.h"

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
//
// ============================================================================

class FPManager {
public:
    explicit FPManager(
        int num_fps,
        size_t max_connections = 100000
    );

    ~FPManager();

    // Start all FP worker threads.
    void startAll();

    // Stop all FP worker threads.
    void stopAll();

    // Get a specific FastPath.
    FastPath& getFP(int id) {
        return *fps_.at(
            static_cast<size_t>(id)
        );
    }

    // Get a specific FP input queue.
    ThreadSafeQueue<PacketJob>& getFPQueue(
        int id
    ) {
        return fps_.at(
            static_cast<size_t>(id)
        )->getInputQueue();
    }

    // Get raw queue pointers for LBManager.
    std::vector<
        ThreadSafeQueue<PacketJob>*
    > getQueuePtrs();

    // Number of FastPath workers.
    int getNumFPs() const {
        return static_cast<int>(
            fps_.size()
        );
    }

    // Check whether all FPs are running.
    bool allRunning() const;

    // Aggregated FastPath statistics.
    struct AggregatedStats {
        uint64_t total_processed = 0;
        uint64_t total_bytes = 0;
        uint64_t total_connections = 0;
        uint64_t total_active_connections = 0;
    };

    AggregatedStats getAggregatedStats() const;

    // Generate a simple statistics report.
    std::string generateReport() const;

private:
    std::vector<
        std::unique_ptr<FastPath>
    > fps_;
};

} // namespace DPI

#endif // FP_MANAGER_H