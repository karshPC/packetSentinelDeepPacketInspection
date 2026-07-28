#include "dpi_engine.h"

#include <iostream>
#include <string>

int main(int argc, char* argv[]) {

    if (argc < 2) {
        std::cerr
            << "Usage: "
            << argv[0]
            << " <pcap_file>\n";

        return 1;
    }

    const std::string input_file =
        argv[1];

    const std::string output_file =
        "tests/dpi_engine_output.pcap";

    // ============================================================
    // Configuration
    // ============================================================

    DPI::DPIEngine::Config config;

    config.num_load_balancers = 2;
    config.fps_per_lb = 2;
    config.queue_size = 10000;
    config.verbose = true;

    // ============================================================
    // Create Engine
    // ============================================================

    DPI::DPIEngine engine(config);

    std::cout
        << "\n========================================\n"
        << "DPI Engine Test\n"
        << "========================================\n";

    // ============================================================
    // Initialize
    // ============================================================

    if (!engine.initialize()) {

        std::cerr
            << "ERROR: DPI Engine initialization failed\n";

        return 1;
    }

    std::cout
        << "DPI Engine initialized successfully\n";

    // ============================================================
    // Process PCAP
    // ============================================================

    std::cout
        << "\nProcessing PCAP:\n"
        << "  Input:  "
        << input_file
        << "\n"
        << "  Output: "
        << output_file
        << "\n";

    if (!engine.processFile(
            input_file,
            output_file
        )) {

        std::cerr
            << "ERROR: DPI Engine failed to process PCAP\n";

        return 1;
    }

    // ============================================================
    // Statistics
    // ============================================================

    const DPI::DPIStats& stats =
        engine.getStats();

    std::cout
        << "\n========================================\n"
        << "DPI Engine Statistics\n"
        << "========================================\n";

    std::cout
        << "Packets read:       "
        << stats.total_packets.load()
        << "\n";

    std::cout
        << "Bytes read:         "
        << stats.total_bytes.load()
        << "\n";

    std::cout
        << "TCP packets:        "
        << stats.tcp_packets.load()
        << "\n";

    std::cout
        << "UDP packets:        "
        << stats.udp_packets.load()
        << "\n";

    std::cout
        << "Other packets:      "
        << stats.other_packets.load()
        << "\n";

    std::cout
        << "Forwarded packets:  "
        << stats.forwarded_packets.load()
        << "\n";

    std::cout
        << "Dropped packets:    "
        << stats.dropped_packets.load()
        << "\n";

    std::cout
        << "Active connections: "
        << stats.active_connections.load()
        << "\n";

    // ============================================================
    // Basic Validation
    // ============================================================

    bool passed = true;

    if (stats.total_packets.load() == 0) {

        std::cerr
            << "ERROR: No packets were processed\n";

        passed = false;
    }

    if (stats.total_bytes.load() == 0) {

        std::cerr
            << "ERROR: No packet bytes were processed\n";

        passed = false;
    }

    if (
        stats.tcp_packets.load() +
        stats.udp_packets.load() +
        stats.other_packets.load()
        !=
        stats.total_packets.load()
    ) {

        std::cerr
            << "ERROR: Protocol packet counts do not "
            << "match total packet count\n";

        passed = false;
    }

    // ============================================================
    // Print Engine Report
    // ============================================================

    std::cout
        << engine.generateReport();

    // ============================================================
    // Final Result
    // ============================================================

    std::cout
        << "\n========================================\n";

    if (passed) {

        std::cout
            << "DPI Engine test passed\n";

        std::cout
            << "========================================\n";

        return 0;
    }

    std::cout
        << "DPI Engine test FAILED\n";

    std::cout
        << "========================================\n";

    return 1;
}