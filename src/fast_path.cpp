#include "fast_path.h"

#include <chrono>
#include <iostream>

namespace DPI {

// ============================================================================
// FastPath
// ============================================================================

FastPath::FastPath(
    int fp_id,
    ThreadSafeQueue<PacketJob>& input_queue,
    size_t max_connections
)
    : fp_id_(fp_id),
      input_queue_(input_queue),
      tracker_(
          fp_id,
          max_connections
      ) {
}

FastPath::~FastPath() {
    stop();
}

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

bool FastPath::processPacket(
    const PacketJob& job
) {
    Connection* connection =
        tracker_.getOrCreateConnection(
            job.tuple
        );

    if (!connection) {
        return false;
    }

    const bool outbound =
        isOutbound(job);

    tracker_.updateConnection(
        connection,
        job.data.size(),
        outbound
    );

    ++packets_processed_;

    bytes_processed_ +=
        job.data.size();

    return true;
}

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

bool FastPath::isOutbound(
    const PacketJob& job
) const {
    // The capture used by this project has the local host represented
    // by 192.168.x.x addresses. This helper currently treats traffic
    // originating from a private IPv4 address as outbound.
    //
    // A more general direction-detection mechanism will be introduced
    // later when the Fast Path receives interface/network configuration.

    const uint32_t first_octet =
        (job.tuple.src_ip >> 24) & 0xFF;

    const uint32_t second_octet =
        (job.tuple.src_ip >> 16) & 0xFF;

    if (first_octet == 10) {
        return true;
    }

    if (first_octet == 172 &&
        second_octet >= 16 &&
        second_octet <= 31) {
        return true;
    }

    if (first_octet == 192 &&
        second_octet == 168) {
        return true;
    }

    return false;
}

FastPath::FPStats
FastPath::getStats() const {
    FPStats stats;

    stats.packets_processed =
        packets_processed_.load();

    stats.bytes_processed =
        bytes_processed_.load();

    const auto tracker_stats =
        tracker_.getStats();

    stats.connections_created =
        tracker_stats.total_connections_seen;

    stats.active_connections =
        tracker_stats.active_connections;

    return stats;
}

} // namespace DPI