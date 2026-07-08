#pragma once

#include <cstdint>
#include <string>

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
};

enum class AppType {
    UNKNOWN,
    HTTP,
    HTTPS,
    DNS,
    QUIC,
    GOOGLE,
    YOUTUBE,
    FACEBOOK,
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
    CLOUDFLARE
};

enum class ConnectionState {
    NEW,
    ESTABLISHED,
    CLOSED
};

enum class PacketAction {
    FORWARD,
    DROP
};

struct Connection {
    FiveTuple tuple;
    AppType app = AppType::UNKNOWN;
    ConnectionState state = ConnectionState::NEW;

    uint64_t packets = 0;
    uint64_t bytes = 0;

    bool blocked = false;
};

struct PacketJob {
    FiveTuple tuple;
    const uint8_t* data = nullptr;
    size_t length = 0;
    uint64_t timestamp_sec = 0;
    uint32_t timestamp_usec = 0;
};

struct DPIStats {
    uint64_t packets_seen = 0;
    uint64_t packets_forwarded = 0;
    uint64_t packets_dropped = 0;
    uint64_t bytes_processed = 0;
};