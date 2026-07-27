#include "pipeline_manager.h"

#include <stdexcept>

namespace DPI {

// ============================================================================
// PipelineManager
// ============================================================================

PipelineManager::PipelineManager(
    int num_lbs,
    int fps_per_lb,
    size_t max_connections
)
    : fp_manager_(
          num_lbs * fps_per_lb,
          max_connections
      ),
      lb_manager_(
          num_lbs,
          fps_per_lb,
          fp_manager_.getQueuePtrs()
      ) {
}

PipelineManager::~PipelineManager() {
    stop();
}

void PipelineManager::start() {
    if (running_) {
        return;
    }

    // Start FP workers first so their queues are ready to receive packets.
    fp_manager_.startAll();

    // Then start the Load Balancers.
    lb_manager_.startAll();

    running_ = true;
}

void PipelineManager::stop() {
    if (!running_) {
        return;
    }

    // Stop LBs first so they stop producing new FP work.
    lb_manager_.stopAll();

    // Then stop the FP workers after the LB side has stopped.
    fp_manager_.stopAll();

    running_ = false;
}

void PipelineManager::submit(
    PacketJob job
) {
    if (!running_) {
        throw std::runtime_error(
            "PipelineManager is not running"
        );
    }

    LoadBalancer& lb =
        lb_manager_.getLBForPacket(
            job.tuple
        );

    lb.getInputQueue().push(
        std::move(job)
    );

    ++packets_submitted_;
}

PipelineManager::PipelineStats
PipelineManager::getStats() const {
    PipelineStats stats;

    stats.packets_submitted =
        packets_submitted_;

    const auto lb_stats =
        lb_manager_.getAggregatedStats();

    stats.packets_received_by_lb =
        lb_stats.total_received;

    stats.packets_dispatched_by_lb =
        lb_stats.total_dispatched;

    const auto fp_stats =
        fp_manager_.getAggregatedStats();

    stats.packets_processed_by_fp =
        fp_stats.total_processed;

    stats.bytes_processed_by_fp =
        fp_stats.total_bytes;

    return stats;
}

} // namespace DPI