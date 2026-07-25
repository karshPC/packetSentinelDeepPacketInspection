#include "fast_path.h"

#include <chrono>
#include <iostream>
#include <thread>

int main() {
    DPI::ThreadSafeQueue<DPI::PacketJob> queue(100);

    DPI::FastPath fast_path(
        0,
        queue
    );

    // ============================================================
    // Create two packets belonging to the same connection.
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

    // Reverse-direction packet.
    DPI::PacketJob packet3;

    packet3.packet_id = 3;

    packet3.tuple =
        packet1.tuple.reverse();

    packet3.data.resize(150);

    // ============================================================
    // Start Fast Path.
    // ============================================================

    fast_path.start();

    queue.push(packet1);
    queue.push(packet2);
    queue.push(packet3);

    // Give the worker time to process the packets.
    std::this_thread::sleep_for(
        std::chrono::milliseconds(200)
    );

    fast_path.stop();

    // ============================================================
    // Verify statistics.
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
    // Assertions.
    // ============================================================

    if (stats.packets_processed != 3) {
        std::cerr
            << "ERROR: Expected 3 processed packets\n";

        return 1;
    }

    if (stats.bytes_processed != 450) {
        std::cerr
            << "ERROR: Expected 450 processed bytes\n";

        return 1;
    }

    // packet1 and packet2 are the same flow.
    // packet3 is the reverse direction of that flow.
    // ConnectionTracker should recognize all three as one connection.
    if (stats.connections_created != 1) {
        std::cerr
            << "ERROR: Expected exactly 1 connection\n";

        return 1;
    }

    if (stats.active_connections != 1) {
        std::cerr
            << "ERROR: Expected 1 active connection\n";

        return 1;
    }

    std::cout
        << "Fast path test passed\n";

    return 0;
}