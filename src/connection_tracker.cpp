#include "connection_tracker.h"

#include <algorithm>
#include <iomanip>
#include <mutex>
#include <sstream>

namespace DPI {

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

    Connection conn;

    conn.tuple = tuple;
    conn.state = ConnectionState::NEW;

    conn.first_seen =
        std::chrono::steady_clock::now();

    conn.last_seen =
        conn.first_seen;

    auto result =
        connections_.emplace(
            tuple,
            std::move(conn)
        );

    if (!result.second) {
        return nullptr;
    }

    ++total_seen_;

    return &result.first->second;
}

Connection* ConnectionTracker::getConnection(
    const FiveTuple& tuple
) {
    auto it = connections_.find(tuple);

    if (it != connections_.end()) {
        return &it->second;
    }

    // Check the reverse direction of the flow.
    FiveTuple reverse_tuple =
        tuple.reverse();

    auto reverse_it =
        connections_.find(reverse_tuple);

    if (reverse_it != connections_.end()) {
        return &reverse_it->second;
    }

    return nullptr;
}

void ConnectionTracker::updateConnection(
    Connection* conn,
    size_t packet_size,
    bool is_outbound
) {
    if (!conn) {
        return;
    }

    conn->last_seen =
        std::chrono::steady_clock::now();

    if (is_outbound) {
        ++conn->packets_out;
        conn->bytes_out += packet_size;
    } else {
        ++conn->packets_in;
        conn->bytes_in += packet_size;
    }

    // A new flow becomes established once traffic is observed.
    if (conn->state == ConnectionState::NEW) {
        conn->state =
            ConnectionState::ESTABLISHED;
    }
}

void ConnectionTracker::classifyConnection(
    Connection* conn,
    AppType app,
    const std::string& sni
) {
    if (!conn) {
        return;
    }

    if (conn->state != ConnectionState::CLASSIFIED) {
        conn->app_type = app;
        conn->sni = sni;

        conn->state =
            ConnectionState::CLASSIFIED;

        ++classified_count_;
    }
}

void ConnectionTracker::blockConnection(
    Connection* conn
) {
    if (!conn) {
        return;
    }

    conn->state =
        ConnectionState::BLOCKED;

    conn->action =
        PacketAction::DROP;

    ++blocked_count_;
}

void ConnectionTracker::closeConnection(
    const FiveTuple& tuple
) {
    auto it = connections_.find(tuple);

    if (it != connections_.end()) {
        it->second.state =
            ConnectionState::CLOSED;

        return;
    }

    // Also support closing using the reverse direction.
    FiveTuple reverse_tuple =
        tuple.reverse();

    auto reverse_it =
        connections_.find(reverse_tuple);

    if (reverse_it != connections_.end()) {
        reverse_it->second.state =
            ConnectionState::CLOSED;
    }
}

size_t ConnectionTracker::cleanupStale(
    std::chrono::seconds timeout
) {
    const auto now =
        std::chrono::steady_clock::now();

    size_t removed = 0;

    for (auto it = connections_.begin();
         it != connections_.end();) {

        const auto age =
            std::chrono::duration_cast<
                std::chrono::seconds
            >(
                now - it->second.last_seen
            );

        if (age > timeout ||
            it->second.state ==
                ConnectionState::CLOSED) {

            it = connections_.erase(it);
            ++removed;

        } else {
            ++it;
        }
    }

    return removed;
}

std::vector<Connection>
ConnectionTracker::getAllConnections() const {
    std::vector<Connection> result;

    result.reserve(
        connections_.size()
    );

    for (const auto& pair : connections_) {
        result.push_back(pair.second);
    }

    return result;
}

size_t ConnectionTracker::getActiveCount() const {
    return connections_.size();
}

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

void ConnectionTracker::clear() {
    connections_.clear();
}

void ConnectionTracker::forEach(
    std::function<void(const Connection&)> callback
) const {
    if (!callback) {
        return;
    }

    for (const auto& pair : connections_) {
        callback(pair.second);
    }
}

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

void GlobalConnectionTable::registerTracker(
    int fp_id,
    ConnectionTracker* tracker
) {
    std::unique_lock<
        std::shared_mutex
    > lock(mutex_);

    if (fp_id < 0 ||
        fp_id >= static_cast<int>(trackers_.size())) {
        return;
    }

    trackers_[fp_id] = tracker;
}

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

    for (const auto* tracker : trackers_) {
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
            return a.second > b.second;
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

std::string
GlobalConnectionTable::generateReport() const {
    const GlobalStats stats =
        getGlobalStats();

    std::ostringstream ss;

    ss << "\n"
       << "╔══════════════════════════════════════════════════════════════╗\n"
       << "║               CONNECTION STATISTICS REPORT                 ║\n"
       << "╠══════════════════════════════════════════════════════════════╣\n";

    ss << "║ Active Connections:     "
       << std::setw(10)
       << stats.total_active_connections
       << "                          ║\n";

    ss << "║ Total Connections Seen: "
       << std::setw(10)
       << stats.total_connections_seen
       << "                          ║\n";

    ss << "╠══════════════════════════════════════════════════════════════╣\n"
       << "║                    APPLICATION BREAKDOWN                   ║\n"
       << "╠══════════════════════════════════════════════════════════════╣\n";

    size_t total_applications = 0;

    for (const auto& pair :
         stats.app_distribution) {

        total_applications +=
            pair.second;
    }

    std::vector<
        std::pair<AppType, size_t>
    > sorted_apps(
        stats.app_distribution.begin(),
        stats.app_distribution.end()
    );

    std::sort(
        sorted_apps.begin(),
        sorted_apps.end(),
        [](const auto& a, const auto& b) {
            return a.second > b.second;
        }
    );

    for (const auto& pair :
         sorted_apps) {

        const double percentage =
            total_applications > 0
                ? 100.0 *
                      pair.second /
                      total_applications
                : 0.0;

        ss << "║ "
           << std::setw(20)
           << std::left
           << appTypeToString(pair.first)
           << std::setw(10)
           << std::right
           << pair.second
           << " ("
           << std::fixed
           << std::setprecision(1)
           << std::setw(5)
           << percentage
           << "%)           ║\n";
    }

    if (!stats.top_domains.empty()) {
        ss << "╠══════════════════════════════════════════════════════════════╣\n"
           << "║                      TOP DOMAINS                            ║\n"
           << "╠══════════════════════════════════════════════════════════════╣\n";

        for (const auto& pair :
             stats.top_domains) {

            std::string domain =
                pair.first;

            if (domain.length() > 35) {
                domain =
                    domain.substr(0, 32)
                    + "...";
            }

            ss << "║ "
               << std::setw(40)
               << std::left
               << domain
               << std::setw(10)
               << std::right
               << pair.second
               << "           ║\n";
        }
    }

    ss << "╚══════════════════════════════════════════════════════════════╝\n";

    return ss.str();
}

} // namespace DPI