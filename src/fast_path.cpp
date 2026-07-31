#include "fast_path.h"

#include <chrono>
#include <iostream>

namespace DPI {

// ============================================================================
// FastPath
// ============================================================================

FastPath::FastPath(
    int fp_id,
    size_t max_connections,
    RuleManager* rule_manager,
    ThreadSafeQueue<PacketJob>* output_queue
)
    : fp_id_(fp_id),
      input_queue_(10000),
      tracker_(
          fp_id,
          max_connections
      ),
      rule_manager_(rule_manager),
      output_queue_(output_queue) {
}

// ============================================================================
// Destructor
// ============================================================================

FastPath::~FastPath() {
    stop();
}

// ============================================================================
// Rule Manager
// ============================================================================

void FastPath::setRuleManager(
    RuleManager* rule_manager
) {
    rule_manager_ = rule_manager;
}

// ============================================================================
// Output Queue
// ============================================================================

void FastPath::setOutputQueue(
    ThreadSafeQueue<PacketJob>* output_queue
) {
    output_queue_ = output_queue;
}

// ============================================================================
// Start
// ============================================================================

void FastPath::start() {

    if (running_.load()) {
        return;
    }

    running_.store(true);

    thread_ =
        std::thread(
            &FastPath::run,
            this
        );

    std::cout
        << "[FP"
        << fp_id_
        << "] Started\n";
}

// ============================================================================
// Stop
// ============================================================================

void FastPath::stop() {

    if (!running_.load()) {
        return;
    }

    running_.store(false);

    input_queue_.shutdown();

    if (thread_.joinable()) {
        thread_.join();
    }

    std::cout
        << "[FP"
        << fp_id_
        << "] Stopped\n";
}

// ============================================================================
// Process Packet
// ============================================================================

bool FastPath::processPacket(
    const PacketJob& job
) {

    // ------------------------------------------------------------
    // Check blocking rules before processing the packet.
    // ------------------------------------------------------------

    if (shouldDrop(job)) {

        ++packets_dropped_;

        return false;
    }

    // ------------------------------------------------------------
    // Get or create connection.
    // ------------------------------------------------------------

    Connection* connection =
        tracker_.getOrCreateConnection(
            job.tuple
        );

    if (!connection) {
        return false;
    }

    // ------------------------------------------------------------
    // Determine packet direction.
    // ------------------------------------------------------------

    const bool outbound =
        isOutbound(job);

    // ------------------------------------------------------------
    // Update connection statistics.
    // ------------------------------------------------------------

    tracker_.updateConnection(
        connection,
        job.data.size(),
        outbound
    );

    // ------------------------------------------------------------
    // FastPath statistics.
    // ------------------------------------------------------------

    ++packets_processed_;

    bytes_processed_ +=
        job.data.size();

    // ------------------------------------------------------------
    // Forward accepted packet.
    //
    // Only packets that pass the RuleManager are sent to
    // the output queue.
    // ------------------------------------------------------------

    if (output_queue_) {

        output_queue_->push(
            job
        );
    }

    return true;
}

// ============================================================================
// Worker Thread
// ============================================================================

void FastPath::run() {

    while (running_.load()) {

        PacketJob job;

        const bool received =
            input_queue_.tryPop(
                job,
                std::chrono::milliseconds(100)
            );

        if (!received) {
            continue;
        }

        processPacket(job);
    }
}

// ============================================================================
// Rule Check
// ============================================================================

bool FastPath::shouldDrop(
    const PacketJob& job
) const {

    // No RuleManager means no blocking rules.
    if (!rule_manager_) {
        return false;
    }

    const auto reason =
        rule_manager_->shouldBlock(
            job.tuple.src_ip,
            job.tuple.dst_port,
            AppType::UNKNOWN,
            ""
        );

    if (reason.has_value()) {
        return true;
    }

    return false;
}

// ============================================================================
// Direction Detection
// ============================================================================

bool FastPath::isOutbound(
    const PacketJob& job
) const {

    const uint32_t first_octet =
        (job.tuple.src_ip >> 24) & 0xFF;

    const uint32_t second_octet =
        (job.tuple.src_ip >> 16) & 0xFF;

    // 10.0.0.0/8
    if (first_octet == 10) {
        return true;
    }

    // 172.16.0.0/12
    if (first_octet == 172 &&
        second_octet >= 16 &&
        second_octet <= 31) {

        return true;
    }

    // 192.168.0.0/16
    if (first_octet == 192 &&
        second_octet == 168) {

        return true;
    }

    return false;
}

// ============================================================================
// Statistics
// ============================================================================

FastPath::FPStats
FastPath::getStats() const {

    FPStats stats;

    stats.packets_processed =
        packets_processed_.load();

    stats.bytes_processed =
        bytes_processed_.load();

    stats.packets_dropped =
        packets_dropped_.load();

    const auto tracker_stats =
        tracker_.getStats();

    stats.connections_created =
        tracker_stats.total_connections_seen;

    stats.active_connections =
        tracker_stats.active_connections;

    return stats;
}

} // namespace DPI