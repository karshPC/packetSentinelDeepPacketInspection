#include "fast_path.h"

#include <chrono>
#include <iostream>
#include <string>

namespace DPI {

// ============================================================================
// Constructor
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

    // ------------------------------------------------------------------------
    // Step 1: Get or create connection.
    // ------------------------------------------------------------------------

    Connection* connection =
        tracker_.getOrCreateConnection(
            job.tuple
        );

    if (!connection) {
        return false;
    }

    // ------------------------------------------------------------------------
    // Step 2: Determine packet direction.
    // ------------------------------------------------------------------------

    const bool outbound =
        isOutbound(job);

    // ------------------------------------------------------------------------
    // Step 3: Update connection statistics.
    // ------------------------------------------------------------------------

    tracker_.updateConnection(
        connection,
        job.data.size(),
        outbound
    );

    // ------------------------------------------------------------------------
    // Step 4: Inspect application payload.
    //
    // This must happen BEFORE the final rule check so that:
    //
    //     TLS SNI
    //     HTTP Host
    //
    // are available to RuleManager.
    // ------------------------------------------------------------------------

    inspectApplication(
        job,
        connection
    );

    // ------------------------------------------------------------------------
    // Step 5: Evaluate rules.
    //
    // RuleManager can now inspect:
    //
    //     source IP
    //     destination port
    //     application
    //     domain/SNI
    // ------------------------------------------------------------------------

    if (shouldDrop(
            job,
            connection
        )) {

        tracker_.blockConnection(
            connection
        );

        ++packets_dropped_;

        return false;
    }

    // ------------------------------------------------------------------------
    // Step 6: Packet accepted.
    // ------------------------------------------------------------------------

    ++packets_processed_;

    bytes_processed_ +=
        job.data.size();

    // ------------------------------------------------------------------------
    // Step 7: Forward accepted packet.
    // ------------------------------------------------------------------------

    if (output_queue_) {

        output_queue_->push(
            job
        );
    }

    return true;
}

// ============================================================================
// Application Inspection
// ============================================================================

void FastPath::inspectApplication(
    const PacketJob& job,
    Connection* connection
) {
    if (!connection) {
        return;
    }

    // ------------------------------------------------------------------------
    // Do not repeatedly classify an already classified connection.
    // ------------------------------------------------------------------------

    if (
        connection->state ==
            ConnectionState::CLASSIFIED ||
        connection->state ==
            ConnectionState::BLOCKED ||
        connection->state ==
            ConnectionState::CLOSED
    ) {
        return;
    }

    // ------------------------------------------------------------------------
    // Validate payload.
    // ------------------------------------------------------------------------

    if (job.payload_length == 0) {
        return;
    }

    if (job.payload_offset >= job.data.size()) {
        return;
    }

    if (
        job.payload_length >
        job.data.size() - job.payload_offset
    ) {
        return;
    }

    // ------------------------------------------------------------------------
    // Point directly at application payload.
    // ------------------------------------------------------------------------

    const uint8_t* payload =
        job.data.data() +
        job.payload_offset;

    const size_t length =
        job.payload_length;

    // ------------------------------------------------------------------------
    // TLS ClientHello -> SNI -> AppType
    // ------------------------------------------------------------------------

    if (
        SNIExtractor::isTLS(
            payload,
            length
        )
    ) {

        const std::string sni =
            SNIExtractor::extractTLS_SNI(
                payload,
                length
            );

        if (!sni.empty()) {

            const AppType app =
                SNIExtractor::classifyHost(
                    sni
                );

            tracker_.classifyConnection(
                connection,
                app,
                sni
            );

            return;
        }
    }

    // ------------------------------------------------------------------------
    // HTTP request -> Host -> AppType
    // ------------------------------------------------------------------------

    if (
        SNIExtractor::isHTTP(
            payload,
            length
        )
    ) {

        const std::string host =
            SNIExtractor::extractHTTP_Host(
                payload,
                length
            );

        if (!host.empty()) {

            const AppType app =
                SNIExtractor::classifyHost(
                    host
                );

            tracker_.classifyConnection(
                connection,
                app,
                host
            );
        }
    }
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
    const PacketJob& job,
    const Connection* connection
) const {

    // No RuleManager means no blocking rules.
    if (!rule_manager_) {
        return false;
    }

    // ------------------------------------------------------------------------
    // Default values when the connection has not been classified yet.
    // ------------------------------------------------------------------------

    AppType app =
        AppType::UNKNOWN;

    std::string domain;

    if (connection) {

        app =
            connection->app_type;

        domain =
            connection->sni;
    }

    // ------------------------------------------------------------------------
    // Evaluate all rule types through RuleManager.
    // ------------------------------------------------------------------------

    const auto reason =
        rule_manager_->shouldBlock(
            job.tuple.src_ip,
            job.tuple.dst_port,
            app,
            domain
        );

    if (!reason.has_value()) {
        return false;
    }

    // ------------------------------------------------------------------------
    // Verbose diagnostic.
    // ------------------------------------------------------------------------

    std::cout
        << "[FP"
        << fp_id_
        << "] Dropping packet";

    switch (reason->type) {

        case RuleManager::BlockReason::IP:

            std::cout
                << " - IP: "
                << reason->detail;

            break;

        case RuleManager::BlockReason::APP:

            std::cout
                << " - App: "
                << reason->detail;

            break;

        case RuleManager::BlockReason::DOMAIN_RULE:

            std::cout
                << " - Domain: "
                << reason->detail;

            break;

        case RuleManager::BlockReason::PORT:

            std::cout
                << " - Port: "
                << reason->detail;

            break;
    }

    std::cout
        << "\n";

    return true;
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

    // ------------------------------------------------------------------------
    // 10.0.0.0/8
    // ------------------------------------------------------------------------

    if (first_octet == 10) {
        return true;
    }

    // ------------------------------------------------------------------------
    // 172.16.0.0/12
    // ------------------------------------------------------------------------

    if (
        first_octet == 172 &&
        second_octet >= 16 &&
        second_octet <= 31
    ) {
        return true;
    }

    // ------------------------------------------------------------------------
    // 192.168.0.0/16
    // ------------------------------------------------------------------------

    if (
        first_octet == 192 &&
        second_octet == 168
    ) {
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