#include "fast_path.h"

#include <chrono>
#include <iostream>
#include <thread>

int main() {
    // ============================================================
    // FastPath owns its own input queue.
    // ============================================================

    DPI::FastPath fast_path(
        0
    );

    // ============================================================
    // Create two packets belonging to the same direction.
    // ============================================================

    DPI::PacketJob packet1;

    packet1.packet_id = 1;

    packet1.tuple.src_ip =
        0x6401A8C0;

    packet1.tuple.dst_ip =
        0x08080808;

    packet1.tuple.src_port = 50000;
    packet1.tuple.dst_port = 443;
    packet1.tuple.protocol = 6;

    packet1.data.resize(100);

    DPI::PacketJob packet2 =
        packet1;

    packet2.packet_id = 2;
    packet2.data.resize(200);

    // ============================================================
    // Reverse-direction packet.
    //
    // The current ConnectionTracker implementation creates a
    // separate entry when getOrCreateConnection() receives the
    // reverse FiveTuple.
    // ============================================================

    DPI::PacketJob packet3;

    packet3.packet_id = 3;

    packet3.tuple =
        packet1.tuple.reverse();

    packet3.data.resize(150);

    // ============================================================
    // Start FastPath worker.
    // ============================================================

    fast_path.start();

    auto& queue =
        fast_path.getInputQueue();

    queue.push(packet1);
    queue.push(packet2);
    queue.push(packet3);

    // Give worker time to process.
    std::this_thread::sleep_for(
        std::chrono::milliseconds(300)
    );

    // ============================================================
    // Stop worker.
    // ============================================================

    fast_path.stop();

    // ============================================================
    // Read statistics.
    // ============================================================

    const auto stats =
        fast_path.getStats();

    std::cout
        << "\n================================\n"
        << "Fast Path Test\n"
        << "================================\n";

    std::cout
        << "Packets processed: "
        << stats.packets_processed
        << '\n';

    std::cout
        << "Bytes processed:   "
        << stats.bytes_processed
        << '\n';

    std::cout
        << "Connections seen:  "
        << stats.connections_created
        << '\n';

    std::cout
        << "Active connections:"
        << ' '
        << stats.active_connections
        << '\n';

    // ============================================================
    // Verify packet processing.
    // ============================================================

    if (stats.packets_processed != 3) {
        std::cerr
            << "ERROR: Expected 3 processed packets, got "
            << stats.packets_processed
            << '\n';

        return 1;
    }

    if (stats.bytes_processed != 450) {
        std::cerr
            << "ERROR: Expected 450 processed bytes, got "
            << stats.bytes_processed
            << '\n';

        return 1;
    }

    // Two unique FiveTuples are inserted:
    //
    // 1. A -> B
    // 2. B -> A
    //
    // packet1 and packet2 share the first tuple.
    if (stats.connections_created != 2) {
        std::cerr
            << "ERROR: Expected 2 connections, got "
            << stats.connections_created
            << '\n';

        return 1;
    }

    if (stats.active_connections != 2) {
        std::cerr
            << "ERROR: Expected 2 active connections, got "
            << stats.active_connections
            << '\n';

        return 1;
    }

    std::cout
        << "Fast path test passed\n";

    return 0;
}