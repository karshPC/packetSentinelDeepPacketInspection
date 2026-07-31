#include "fp_manager.h"

#include <sstream>
#include <stdexcept>

namespace DPI {

// ============================================================================
// FPManager
// ============================================================================

FPManager::FPManager(
    int num_fps,
    size_t max_connections,
    RuleManager* rule_manager,
    ThreadSafeQueue<PacketJob>* output_queue
)
    : rule_manager_(rule_manager),
      output_queue_(output_queue) {

    if (num_fps <= 0) {
        throw std::invalid_argument(
            "num_fps must be greater than zero"
        );
    }

    fps_.reserve(
        static_cast<size_t>(num_fps)
    );

    for (int fp_id = 0;
         fp_id < num_fps;
         ++fp_id) {

        fps_.push_back(
            std::make_unique<FastPath>(
                fp_id,
                max_connections,
                rule_manager_,
                output_queue_
            )
        );
    }
}

// ============================================================================
// Destructor
// ============================================================================

FPManager::~FPManager() {
    stopAll();
}

// ============================================================================
// Rule Manager
// ============================================================================

void FPManager::setRuleManager(
    RuleManager* rule_manager
) {
    rule_manager_ = rule_manager;

    for (auto& fp : fps_) {
        fp->setRuleManager(
            rule_manager_
        );
    }
}

// ============================================================================
// Output Queue
// ============================================================================

void FPManager::setOutputQueue(
    ThreadSafeQueue<PacketJob>* output_queue
) {
    output_queue_ = output_queue;

    for (auto& fp : fps_) {
        fp->setOutputQueue(
            output_queue_
        );
    }
}

// ============================================================================
// Start / Stop
// ============================================================================

void FPManager::startAll() {

    for (auto& fp : fps_) {
        fp->start();
    }
}

void FPManager::stopAll() {

    for (auto& fp : fps_) {
        fp->stop();
    }
}

// ============================================================================
// Queue Access
// ============================================================================

std::vector<
    ThreadSafeQueue<PacketJob>*
>
FPManager::getQueuePtrs() {

    std::vector<
        ThreadSafeQueue<PacketJob>*
    > queues;

    queues.reserve(
        fps_.size()
    );

    for (auto& fp : fps_) {
        queues.push_back(
            &fp->getInputQueue()
        );
    }

    return queues;
}

// ============================================================================
// State
// ============================================================================

bool FPManager::allRunning() const {

    for (const auto& fp : fps_) {

        if (!fp->isRunning()) {
            return false;
        }
    }

    return true;
}

// ============================================================================
// Statistics
// ============================================================================

FPManager::AggregatedStats
FPManager::getAggregatedStats() const {

    AggregatedStats stats;

    for (const auto& fp : fps_) {

        const auto fp_stats =
            fp->getStats();

        stats.total_processed +=
            fp_stats.packets_processed;

        stats.total_bytes +=
            fp_stats.bytes_processed;

        stats.total_dropped +=
            fp_stats.packets_dropped;

        stats.total_connections +=
            fp_stats.connections_created;

        stats.total_active_connections +=
            fp_stats.active_connections;
    }

    return stats;
}

// ============================================================================
// Report
// ============================================================================

std::string
FPManager::generateReport() const {

    const auto stats =
        getAggregatedStats();

    std::ostringstream output;

    output
        << "\n"
        << "========================================\n"
        << "          FAST PATH REPORT\n"
        << "========================================\n";

    output
        << "Fast Paths:             "
        << fps_.size()
        << '\n';

    output
        << "Packets Processed:      "
        << stats.total_processed
        << '\n';

    output
        << "Packets Dropped:        "
        << stats.total_dropped
        << '\n';

    output
        << "Bytes Processed:        "
        << stats.total_bytes
        << '\n';

    output
        << "Connections Seen:       "
        << stats.total_connections
        << '\n';

    output
        << "Active Connections:     "
        << stats.total_active_connections
        << '\n';

    output
        << "========================================\n";

    return output.str();
}

} // namespace DPI