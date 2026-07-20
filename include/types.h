#ifndef DPI_TYPES_H
#define DPI_TYPES_H

#include <cstdint>
#include <string>
#include <functional>
#include <chrono>
#include <atomic>

namespace DPI {

// ============================================================================
// Five-Tuple: Uniquely identifies a connection/flow
// ============================================================================
struct FiveTuple {
    uint32_t src_ip = 0;
    uint32_t dst_ip = 0;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    uint8_t protocol = 0;

    bool operator==(const FiveTuple& other) const {
        return src_ip == other.src_ip &&
               dst_ip == other.dst_ip &&
               src_port == other.src_port &&
               dst_port == other.dst_port &&
               protocol == other.protocol;
    }

    FiveTuple reverse() const {
        return {dst_ip, src_ip, dst_port, src_port, protocol};
    }

    std::string toString() const;
};

// Hash function for FiveTuple
struct FiveTupleHash {
    size_t operator()(const FiveTuple& tuple) const {
        size_t h = 0;

        h ^= std::hash<uint32_t>{}(tuple.src_ip)
             + 0x9e3779b9 + (h << 6) + (h >> 2);

        h ^= std::hash<uint32_t>{}(tuple.dst_ip)
             + 0x9e3779b9 + (h << 6) + (h >> 2);

        h ^= std::hash<uint16_t>{}(tuple.src_port)
             + 0x9e3779b9 + (h << 6) + (h >> 2);

        h ^= std::hash<uint16_t>{}(tuple.dst_port)
             + 0x9e3779b9 + (h << 6) + (h >> 2);

        h ^= std::hash<uint8_t>{}(tuple.protocol)
             + 0x9e3779b9 + (h << 6) + (h >> 2);

        return h;
    }
};

// ============================================================================
// Application Classification
// ============================================================================
enum class AppType {
    UNKNOWN = 0,
    HTTP,
    HTTPS,
    DNS,
    TLS,
    QUIC,

    GOOGLE,
    FACEBOOK,
    YOUTUBE,
    TWITTER,
    INSTAGRAM,
    NETFLIX,
    AMAZON,
    MICROSOFT,
    APPLE,
    WHATSAPP,
    TELEGRAM,
    TIKTOK,
    SPOTIFY,
    ZOOM,
    DISCORD,
    GITHUB,
    CLOUDFLARE,

    APP_COUNT
};

std::string appTypeToString(AppType type);
AppType sniToAppType(const std::string& sni);

// ============================================================================
// Connection State
// ============================================================================
enum class ConnectionState {
    NEW,
    ESTABLISHED,
    CLASSIFIED,
    BLOCKED,
    CLOSED
};

// ============================================================================
// Packet Action
// ============================================================================
enum class PacketAction {
    FORWARD,
    DROP,
    INSPECT,
    LOG_ONLY
};

// ============================================================================
// Connection Entry
// ============================================================================
struct Connection {
    FiveTuple tuple;

    ConnectionState state = ConnectionState::NEW;

    AppType app_type = AppType::UNKNOWN;

    std::string sni;

    uint64_t packets_in = 0;
    uint64_t packets_out = 0;

    uint64_t bytes_in = 0;
    uint64_t bytes_out = 0;

    std::chrono::steady_clock::time_point first_seen;
    std::chrono::steady_clock::time_point last_seen;

    PacketAction action = PacketAction::FORWARD;

    bool syn_seen = false;
    bool syn_ack_seen = false;
    bool fin_seen = false;
};

// ============================================================================
// DPI Statistics
// ============================================================================
struct DPIStats {
    std::atomic<uint64_t> total_packets{0};
    std::atomic<uint64_t> total_bytes{0};

    std::atomic<uint64_t> forwarded_packets{0};
    std::atomic<uint64_t> dropped_packets{0};

    std::atomic<uint64_t> tcp_packets{0};
    std::atomic<uint64_t> udp_packets{0};
    std::atomic<uint64_t> other_packets{0};

    std::atomic<uint64_t> active_connections{0};

    DPIStats() = default;

    DPIStats(const DPIStats&) = delete;
    DPIStats& operator=(const DPIStats&) = delete;
};

} // namespace DPI

#endif // DPI_TYPES_H