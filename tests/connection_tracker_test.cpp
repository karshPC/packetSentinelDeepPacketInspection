#include "connection_tracker.h"

#include <iostream>

int main() {
    DPI::ConnectionTracker tracker(
        0,
        100
    );

    DPI::FiveTuple tuple{
        0x6401A8C0,  // 192.168.1.100
        0xCEA9FA8E,  // 142.250.169.206
        49211,
        443,
        6
    };

    DPI::FiveTuple reverse =
        tuple.reverse();

    // ------------------------------------------------------------
    // Create first connection
    // ------------------------------------------------------------

    DPI::Connection* connection =
        tracker.getOrCreateConnection(
            tuple
        );

    if (!connection) {
        std::cerr
            << "Failed to create connection\n";

        return 1;
    }

    if (connection->state !=
        DPI::ConnectionState::NEW) {

        std::cerr
            << "New connection has wrong state\n";

        return 1;
    }

    // ------------------------------------------------------------
    // Update connection
    // ------------------------------------------------------------

    tracker.updateConnection(
        connection,
        100,
        true
    );

    if (connection->packets_out != 1 ||
        connection->bytes_out != 100) {

        std::cerr
            << "Outbound statistics incorrect\n";

        return 1;
    }

    if (connection->state !=
        DPI::ConnectionState::ESTABLISHED) {

        std::cerr
            << "Connection did not become established\n";

        return 1;
    }

    // ------------------------------------------------------------
    // Reverse lookup
    // ------------------------------------------------------------

    DPI::Connection* reverse_connection =
        tracker.getConnection(
            reverse
        );

    if (reverse_connection != connection) {
        std::cerr
            << "Reverse tuple did not find "
               "the original connection\n";

        return 1;
    }

    // ------------------------------------------------------------
    // Classify
    // ------------------------------------------------------------

    tracker.classifyConnection(
        connection,
        DPI::AppType::GOOGLE,
        "www.google.com"
    );

    if (connection->state !=
            DPI::ConnectionState::CLASSIFIED ||
        connection->app_type !=
            DPI::AppType::GOOGLE ||
        connection->sni !=
            "www.google.com") {

        std::cerr
            << "Connection classification failed\n";

        return 1;
    }

    // ------------------------------------------------------------
    // Block
    // ------------------------------------------------------------

    tracker.blockConnection(
        connection
    );

    if (connection->state !=
            DPI::ConnectionState::BLOCKED ||
        connection->action !=
            DPI::PacketAction::DROP) {

        std::cerr
            << "Connection blocking failed\n";

        return 1;
    }

    // ------------------------------------------------------------
    // Statistics
    // ------------------------------------------------------------

    const auto stats =
        tracker.getStats();

    if (stats.active_connections != 1 ||
        stats.total_connections_seen != 1 ||
        stats.classified_connections != 1 ||
        stats.blocked_connections != 1) {

        std::cerr
            << "Tracker statistics are incorrect\n";

        return 1;
    }

    // ------------------------------------------------------------
    // Close
    // ------------------------------------------------------------

    tracker.closeConnection(
        tuple
    );

    if (connection->state !=
        DPI::ConnectionState::CLOSED) {

        std::cerr
            << "Connection did not close\n";

        return 1;
    }

    // ------------------------------------------------------------
    // Cleanup
    // ------------------------------------------------------------

    const size_t removed =
        tracker.cleanupStale(
            std::chrono::seconds(0)
        );

    if (removed != 1 ||
        tracker.getActiveCount() != 0) {

        std::cerr
            << "Connection cleanup failed\n";

        return 1;
    }

    std::cout
        << "Connection tracker test passed\n";

    return 0;
}