#ifndef CONNECTION_TRACKER_H
#define CONNECTION_TRACKER_H

#include "types.h"

#include <chrono>
#include <functional>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace DPI {

// ============================================================================
// Connection Tracker
// ============================================================================
//
// Maintains the flow table for connections handled by one fast-path worker.
//
// Each FiveTuple identifies a flow. Reverse tuples are recognized so that
// packets travelling in the opposite direction can be associated with the
// same connection.
// ============================================================================
class ConnectionTracker {
public:
    ConnectionTracker(
        int fp_id,
        size_t max_connections = 100000
    );

    // Get or create a connection entry.
    Connection* getOrCreateConnection(
        const FiveTuple& tuple
    );

    // Get an existing connection.
    // Checks both the exact tuple and its reverse.
    Connection* getConnection(
        const FiveTuple& tuple
    );

    // Update packet/byte counters and last-seen timestamp.
    void updateConnection(
        Connection* conn,
        size_t packet_size,
        bool is_outbound
    );

    // Mark connection as classified.
    void classifyConnection(
        Connection* conn,
        AppType app,
        const std::string& sni
    );

    // Mark connection as blocked.
    void blockConnection(
        Connection* conn
    );

    // Mark connection as closed.
    void closeConnection(
        const FiveTuple& tuple
    );

    // Remove inactive or closed connections.
    size_t cleanupStale(
        std::chrono::seconds timeout =
            std::chrono::seconds(300)
    );

    // Return a snapshot of all connections.
    std::vector<Connection> getAllConnections() const;

    // Number of currently tracked connections.
    size_t getActiveCount() const;

    struct TrackerStats {
        size_t active_connections = 0;
        size_t total_connections_seen = 0;
        size_t classified_connections = 0;
        size_t blocked_connections = 0;
    };

    TrackerStats getStats() const;

    // Remove all connections.
    void clear();

    // Iterate through all currently tracked connections.
    void forEach(
        std::function<void(const Connection&)> callback
    ) const;

private:
    int fp_id_;
    size_t max_connections_;

    std::unordered_map<
        FiveTuple,
        Connection,
        FiveTupleHash
    > connections_;

    size_t total_seen_ = 0;
    size_t classified_count_ = 0;
    size_t blocked_count_ = 0;

    void evictOldest();
};

// ============================================================================
// Global Connection Table
// ============================================================================
//
// Aggregates statistics from multiple ConnectionTracker instances.
// ============================================================================
class GlobalConnectionTable {
public:
    explicit GlobalConnectionTable(
        size_t num_fps
    );

    void registerTracker(
        int fp_id,
        ConnectionTracker* tracker
    );

    struct GlobalStats {
        size_t total_active_connections = 0;
        size_t total_connections_seen = 0;

        std::unordered_map<
            AppType,
            size_t
        > app_distribution;

        std::vector<
            std::pair<std::string, size_t>
        > top_domains;
    };

    GlobalStats getGlobalStats() const;

    std::string generateReport() const;

private:
    std::vector<ConnectionTracker*> trackers_;

    mutable std::shared_mutex mutex_;
};

} // namespace DPI

#endif // CONNECTION_TRACKER_H