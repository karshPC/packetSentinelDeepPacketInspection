#ifndef PIPELINE_MANAGER_H
#define PIPELINE_MANAGER_H

#include "fp_manager.h"
#include "load_balancer.h"
#include "packet_job.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

namespace DPI {

// ============================================================================
// Pipeline Manager
// ============================================================================
//
// Owns the complete LB -> FP execution pipeline.
//
//
//                     PipelineManager
//                           |
//             ┌─────────────┴─────────────┐
//             │                           │
//         LBManager                  FPManager
//             │                           │
//             ▼                           ▼
//        LB input queues             FP workers
//             │                           ▲
//             └───────────────┬───────────┘
//                             │
//                         FP queues
//
// ============================================================================

class PipelineManager {
public:
    PipelineManager(
        int num_lbs,
        int fps_per_lb,
        size_t max_connections = 100000
    );

    ~PipelineManager();

    // Start all LB and FP worker threads.
    void start();

    // Stop all LB and FP worker threads.
    void stop();

    // Submit a packet to the appropriate Load Balancer.
    void submit(
        PacketJob job
    );

    // Access the FP manager.
    FPManager& getFPManager() {
        return fp_manager_;
    }

    // Access the LB manager.
    LBManager& getLBManager() {
        return lb_manager_;
    }

    struct PipelineStats {
        uint64_t packets_submitted = 0;
        uint64_t packets_received_by_lb = 0;
        uint64_t packets_dispatched_by_lb = 0;
        uint64_t packets_processed_by_fp = 0;
        uint64_t bytes_processed_by_fp = 0;
    };

    PipelineStats getStats() const;

    bool isRunning() const {
        return running_;
    }

private:
    FPManager fp_manager_;
    LBManager lb_manager_;

    uint64_t packets_submitted_ = 0;

    bool running_ = false;
};

} // namespace DPI

#endif // PIPELINE_MANAGER_H