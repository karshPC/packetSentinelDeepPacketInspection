#include "connection_tracker.h"

#include <algorithm>
#include <iomanip>
#include <mutex>
#include <sstream>

using namespace DPI;

// ============================================================================
// ConnectionTracker
// ============================================================================

ConnectionTracker::ConnectionTracker(
    int fp_id,
    size_t max_connections
)
    : fp_id_(fp_id),
      max_connections_(max_connections) {
}

// ============================================================================
// Get or create connection
// ============================================================================

Connection* ConnectionTracker::getOrCreateConnection(
    const FiveTuple& tuple
) {
    auto it = connections_.find(tuple);

    if (it != connections_.end()) {
        return &it->second;
    }

    if (connections_.size() >= max_connections_) {
        evictOldest();
    }

    Connection connection;

    connection.tuple = tuple;
    connection.state = ConnectionState::NEW;
    connection.app_type = AppType::UNKNOWN;
    connection.action = PacketAction::FORWARD;

    const auto now =
        std::chrono::steady_clock::now();

    connection.first_seen = now;
    connection.last_seen = now;

    auto result =
        connections_.emplace(
            tuple,
            std::move(connection)
        );

    if (!result.second) {
        return nullptr;
    }

    ++total_seen_;

    return &result.first->second;
}

// ============================================================================
// Get existing connection
// ============================================================================

Connection* ConnectionTracker::getConnection(
    const FiveTuple& tuple
) {
    auto it = connections_.find(tuple);

    if (it != connections_.end()) {
        return &it->second;
    }

    const FiveTuple reverse =
        tuple.reverse();

    it = connections_.find(reverse);

    if (it != connections_.end()) {
        return &it->second;
    }

    return nullptr;
}

// ============================================================================
// Update connection
// ============================================================================

void ConnectionTracker::updateConnection(
    Connection* conn,
    size_t packet_size,
    bool is_outbound
) {
    if (!conn) {
        return;
    }

    if (is_outbound) {
        ++conn->packets_out;
        conn->bytes_out += packet_size;
    } else {
        ++conn->packets_in;
        conn->bytes_in += packet_size;
    }

    conn->last_seen =
        std::chrono::steady_clock::now();

    if (conn->state == ConnectionState::NEW) {
        conn->state =
            ConnectionState::ESTABLISHED;
    }
}

// ============================================================================
// Classify connection
// ============================================================================

void ConnectionTracker::classifyConnection(
    Connection* conn,
    AppType app,
    const std::string& sni
) {
    if (!conn) {
        return;
    }

    const bool was_classified =
        conn->app_type != AppType::UNKNOWN;

    conn->app_type = app;
    conn->sni = sni;

    if (conn->state != ConnectionState::BLOCKED &&
        conn->state != ConnectionState::CLOSED) {

        conn->state =
            ConnectionState::CLASSIFIED;
    }

    if (!was_classified &&
        app != AppType::UNKNOWN) {

        ++classified_count_;
    }
}

// ============================================================================
// Block connection
// ============================================================================

void ConnectionTracker::blockConnection(
    Connection* conn
) {
    if (!conn) {
        return;
    }

    if (conn->state != ConnectionState::BLOCKED) {
        ++blocked_count_;
    }

    conn->state =
        ConnectionState::BLOCKED;

    conn->action =
        PacketAction::DROP;
}

// ============================================================================
// Close connection
// ============================================================================

void ConnectionTracker::closeConnection(
    const FiveTuple& tuple
) {
    auto it =
        connections_.find(tuple);

    if (it == connections_.end()) {

        const FiveTuple reverse =
            tuple.reverse();

        it =
            connections_.find(reverse);
    }

    if (it != connections_.end()) {
        it->second.state =
            ConnectionState::CLOSED;
    }
}

// ============================================================================
// Cleanup stale connections
// ============================================================================

size_t ConnectionTracker::cleanupStale(
    std::chrono::seconds timeout
) {
    const auto now =
        std::chrono::steady_clock::now();

    size_t removed = 0;

    for (auto it = connections_.begin();
         it != connections_.end();) {

        const bool stale =
            (now - it->second.last_seen) >= timeout;

        const bool closed =
            it->second.state ==
            ConnectionState::CLOSED;

        if (stale || closed) {

            it =
                connections_.erase(it);

            ++removed;

        } else {

            ++it;
        }
    }

    return removed;
}

// ============================================================================
// Snapshot
// ============================================================================

std::vector<Connection>
ConnectionTracker::getAllConnections() const {
    std::vector<Connection> result;

    result.reserve(
        connections_.size()
    );

    for (const auto& entry :
         connections_) {

        result.push_back(
            entry.second
        );
    }

    return result;
}

// ============================================================================
// Active count
// ============================================================================

size_t ConnectionTracker::getActiveCount() const {
    return connections_.size();
}

// ============================================================================
// Statistics
// ============================================================================

ConnectionTracker::TrackerStats
ConnectionTracker::getStats() const {
    TrackerStats stats;

    stats.active_connections =
        connections_.size();

    stats.total_connections_seen =
        total_seen_;

    stats.classified_connections =
        classified_count_;

    stats.blocked_connections =
        blocked_count_;

    return stats;
}

// ============================================================================
// Clear
// ============================================================================

void ConnectionTracker::clear() {
    connections_.clear();

    total_seen_ = 0;
    classified_count_ = 0;
    blocked_count_ = 0;
}

// ============================================================================
// Iterate
// ============================================================================

void ConnectionTracker::forEach(
    std::function<void(const Connection&)> callback
) const {
    if (!callback) {
        return;
    }

    for (const auto& entry :
         connections_) {

        callback(entry.second);
    }
}

// ============================================================================
// Evict oldest
// ============================================================================

void ConnectionTracker::evictOldest() {
    if (connections_.empty()) {
        return;
    }

    auto oldest =
        connections_.begin();

    for (auto it = connections_.begin();
         it != connections_.end();
         ++it) {

        if (it->second.last_seen <
            oldest->second.last_seen) {

            oldest = it;
        }
    }

    connections_.erase(oldest);
}

// ============================================================================
// GlobalConnectionTable
// ============================================================================

GlobalConnectionTable::GlobalConnectionTable(
    size_t num_fps
) {
    trackers_.resize(
        num_fps,
        nullptr
    );
}

// ============================================================================
// Register tracker
// ============================================================================

void GlobalConnectionTable::registerTracker(
    int fp_id,
    ConnectionTracker* tracker
) {
    std::unique_lock<
        std::shared_mutex
    > lock(mutex_);

    if (fp_id < 0 ||
        fp_id >=
            static_cast<int>(trackers_.size())) {

        return;
    }

    trackers_[fp_id] = tracker;
}

// ============================================================================
// Global statistics
// ============================================================================

GlobalConnectionTable::GlobalStats
GlobalConnectionTable::getGlobalStats() const {
    std::shared_lock<
        std::shared_mutex
    > lock(mutex_);

    GlobalStats stats;

    std::unordered_map<
        std::string,
        size_t
    > domain_counts;

    for (const auto* tracker :
         trackers_) {

        if (!tracker) {
            continue;
        }

        const auto tracker_stats =
            tracker->getStats();

        stats.total_active_connections +=
            tracker_stats.active_connections;

        stats.total_connections_seen +=
            tracker_stats.total_connections_seen;

        tracker->forEach(
            [&](const Connection& conn) {

                ++stats.app_distribution[
                    conn.app_type
                ];

                if (!conn.sni.empty()) {

                    ++domain_counts[
                        conn.sni
                    ];
                }
            }
        );
    }

    std::vector<
        std::pair<std::string, size_t>
    > domain_vector(
        domain_counts.begin(),
        domain_counts.end()
    );

    std::sort(
        domain_vector.begin(),
        domain_vector.end(),
        [](const auto& a, const auto& b) {

            if (a.second != b.second) {
                return a.second > b.second;
            }

            return a.first < b.first;
        }
    );

    const size_t top_count =
        std::min(
            domain_vector.size(),
            static_cast<size_t>(20)
        );

    stats.top_domains.assign(
        domain_vector.begin(),
        domain_vector.begin() + top_count
    );

    return stats;
}

// ============================================================================
// Generate report
// ============================================================================

std::string
GlobalConnectionTable::generateReport() const {
    const GlobalStats stats =
        getGlobalStats();

    std::ostringstream ss;

    ss << "\n"
       << "============================================================\n"
       << "              CONNECTION STATISTICS REPORT\n"
       << "============================================================\n";

    ss << "Active Connections:     "
       << stats.total_active_connections
       << "\n";

    ss << "Total Connections Seen: "
       << stats.total_connections_seen
       << "\n";

    // ========================================================================
    // Application breakdown
    // ========================================================================

    ss << "\n"
       << "============================================================\n"
       << "                    APPLICATION BREAKDOWN\n"
       << "============================================================\n";

    std::vector<
        std::pair<std::string, size_t>
    > applications;

    for (const auto& entry :
         stats.app_distribution) {

        std::string app_name =
            appTypeToString(entry.first);

        // Convert application name to uppercase
        // for the human-readable global report.
        std::transform(
            app_name.begin(),
            app_name.end(),
            app_name.begin(),
            [](unsigned char c) {
                return static_cast<char>(
                    std::toupper(c)
                );
            }
        );

        applications.emplace_back(
            app_name,
            entry.second
        );
    }

    std::sort(
        applications.begin(),
        applications.end(),
        [](const auto& a, const auto& b) {

            if (a.second != b.second) {
                return a.second > b.second;
            }

            return a.first < b.first;
        }
    );

    for (const auto& entry :
         applications) {

        ss << std::left
           << std::setw(25)
           << entry.first
           << " : "
           << entry.second
           << "\n";
    }

    // ========================================================================
    // Top domains
    // ========================================================================

    ss << "\n"
       << "============================================================\n"
       << "                       TOP DOMAINS\n"
       << "============================================================\n";

    for (const auto& entry :
         stats.top_domains) {

        ss << std::left
           << std::setw(40)
           << entry.first
           << " : "
           << entry.second
           << "\n";
    }

    ss << "============================================================\n";

    return ss.str();
}