#include "fast_path.h"

#include <iostream>
#include <string>

int main() {

    DPI::RuleManager rules;

    DPI::FastPath fp(
        0,
        100,
        &rules,
        nullptr
    );

    // ------------------------------------------------------------
    // Helper to create a packet
    // ------------------------------------------------------------

    auto makePacket =
        [](
            uint32_t src_ip,
            uint32_t dst_ip,
            uint16_t src_port,
            uint16_t dst_port
        ) {

            DPI::PacketJob job;

            job.packet_id = 1;

            job.tuple = {
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                6
            };

            job.data.resize(100, 0);

            job.payload_offset = 0;
            job.payload_length = 0;

            return job;
        };

    // 192.168.1.100 -> 8.8.8.8:443
    const uint32_t client_ip = 0xC0A80164;
    const uint32_t server_ip = 0x08080808;

    // ============================================================
    // 1. Packet should be accepted with no rules
    // ============================================================

    auto packet =
        makePacket(
            client_ip,
            server_ip,
            50000,
            443
        );

    if (!fp.processPacket(packet)) {

        std::cerr
            << "FAIL: packet was dropped with no rules\n";

        return 1;
    }

    std::cout
        << "No-rule acceptance: PASS\n";

    // ============================================================
    // 2. IP blocking
    // ============================================================

    rules.blockIP(client_ip);

    if (fp.processPacket(packet)) {

        std::cerr
            << "FAIL: IP-blocked packet was accepted\n";

        return 1;
    }

    std::cout
        << "IP blocking: PASS\n";

    rules.unblockIP(client_ip);

    // ============================================================
    // 3. Port blocking
    // ============================================================

    rules.blockPort(443);

    if (fp.processPacket(packet)) {

        std::cerr
            << "FAIL: port-blocked packet was accepted\n";

        return 1;
    }

    std::cout
        << "Port blocking: PASS\n";

    rules.unblockPort(443);

    // ============================================================
    // 4. Application blocking
    //
    // We directly classify the connection to test the
    // RuleManager/AppType integration.
    // ============================================================

    DPI::Connection* connection =
        fp.getConnectionTracker()
            .getOrCreateConnection(
                packet.tuple
            );

    if (!connection) {

        std::cerr
            << "FAIL: could not create connection\n";

        return 1;
    }

    fp.getConnectionTracker()
        .classifyConnection(
            connection,
            DPI::AppType::GOOGLE,
            "www.google.com"
        );

    rules.blockApp(
        DPI::AppType::GOOGLE
    );

    if (fp.processPacket(packet)) {

        std::cerr
            << "FAIL: application-blocked packet was accepted\n";

        return 1;
    }

    std::cout
        << "Application blocking: PASS\n";

    rules.unblockApp(
        DPI::AppType::GOOGLE
    );

    // ============================================================
    // 5. Domain blocking
    // ============================================================

    rules.blockDomain(
        "*.google.com"
    );

    if (fp.processPacket(packet)) {

        std::cerr
            << "FAIL: domain-blocked packet was accepted\n";

        return 1;
    }

    std::cout
        << "Domain blocking: PASS\n";

    rules.unblockDomain(
        "*.google.com"
    );

    // ============================================================
    // 6. Packet should work again after removing rules
    // ============================================================

    DPI::PacketJob allowed_packet =
        makePacket(
            0x0A000001,
            server_ip,
            50001,
            443
        );

    if (!fp.processPacket(allowed_packet)) {

        std::cerr
            << "FAIL: allowed packet was dropped\n";

        return 1;
    }

    std::cout
        << "Allowed packet: PASS\n";

    // ============================================================
    // Final result
    // ============================================================

    std::cout
        << "\n================================\n"
        << "Fast Path Rule Test\n"
        << "================================\n"
        << "All rule tests passed\n";

    return 0;
}