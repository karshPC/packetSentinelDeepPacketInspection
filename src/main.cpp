#include "dpi_engine.h"

#include <iostream>
#include <string>
#include <vector>
#include <cstdint>

namespace {

void printUsage(const char* program) {

    std::cout
        << "\n"
        << "===========================================\n"
        << "       DPI Engine - Deep Packet Inspection\n"
        << "===========================================\n"
        << "\n"
        << "Usage:\n"
        << "  " << program
        << " <input.pcap> <output.pcap> [options]\n"
        << "\n"
        << "Options:\n"
        << "  --block-ip <ip>\n"
        << "      Block traffic from a source IP.\n"
        << "\n"
        << "  --block-app <app>\n"
        << "      Block an application.\n"
        << "\n"
        << "  --block-domain <domain>\n"
        << "      Block traffic matching a domain.\n"
        << "\n"
        << "  --block-port <port>\n"
        << "      Block traffic matching a TCP/UDP port.\n"
        << "\n"
        << "  --lbs <n>\n"
        << "      Number of load balancers.\n"
        << "      Default: 2\n"
        << "\n"
        << "  --fps <n>\n"
        << "      Number of fast paths per load balancer.\n"
        << "      Default: 2\n"
        << "\n"
        << "  --verbose\n"
        << "      Enable verbose processing output.\n"
        << "\n"
        << "  --help\n"
        << "      Display this help message.\n"
        << "\n"
        << "Examples:\n"
        << "  " << program
        << " capture.pcap filtered.pcap\n"
        << "\n"
        << "  " << program
        << " capture.pcap filtered.pcap"
        << " --block-ip 192.168.1.50"
        << " --block-app YouTube"
        << " --block-domain google.com"
        << " --block-port 443\n"
        << "\n"
        << "  " << program
        << " capture.pcap filtered.pcap"
        << " --lbs 4"
        << " --fps 4\n"
        << "\n"
        << "===========================================\n"
        << std::endl;
}

bool parsePositiveInteger(
    const std::string& value,
    int& result
) {

    try {

        size_t processed = 0;

        const int parsed =
            std::stoi(
                value,
                &processed
            );

        if (
            processed != value.size() ||
            parsed <= 0
        ) {
            return false;
        }

        result = parsed;

        return true;

    } catch (...) {

        return false;
    }
}

} // namespace

int main(
    int argc,
    char* argv[]
) {

    // ============================================================
    // Argument validation
    // ============================================================

    if (argc < 2) {

        printUsage(argv[0]);

        return 1;
    }

    for (int i = 1; i < argc; ++i) {

        const std::string argument =
            argv[i];

        if (
            argument == "--help" ||
            argument == "-h"
        ) {

            printUsage(argv[0]);

            return 0;
        }
    }

    if (argc < 3) {

        std::cerr
            << "Error: input and output PCAP files are required.\n";

        printUsage(argv[0]);

        return 1;
    }

    // ============================================================
    // Input / output files
    // ============================================================

    const std::string input_file =
        argv[1];

    const std::string output_file =
        argv[2];

    // ============================================================
    // Engine configuration
    // ============================================================

    DPI::DPIEngine::Config config;

    std::vector<std::string> blocked_ips;
    std::vector<std::string> blocked_apps;
    std::vector<std::string> blocked_domains;
    std::vector<uint16_t> blocked_ports;

    // ============================================================
    // Parse command-line options
    // ============================================================

    for (
        int i = 3;
        i < argc;
        ++i
    ) {

        const std::string argument =
            argv[i];

        // --------------------------------------------------------
        // Block IP
        // --------------------------------------------------------

        if (argument == "--block-ip") {

            if (i + 1 >= argc) {

                std::cerr
                    << "Error: --block-ip requires an IP address.\n";

                return 1;
            }

            blocked_ips.push_back(
                argv[++i]
            );

            continue;
        }

        // --------------------------------------------------------
        // Block application
        // --------------------------------------------------------

        if (argument == "--block-app") {

            if (i + 1 >= argc) {

                std::cerr
                    << "Error: --block-app requires an application name.\n";

                return 1;
            }

            blocked_apps.push_back(
                argv[++i]
            );

            continue;
        }

        // --------------------------------------------------------
        // Block domain
        // --------------------------------------------------------

        if (argument == "--block-domain") {

            if (i + 1 >= argc) {

                std::cerr
                    << "Error: --block-domain requires a domain.\n";

                return 1;
            }

            blocked_domains.push_back(
                argv[++i]
            );

            continue;
        }

        // --------------------------------------------------------
        // Block port
        // --------------------------------------------------------

        if (argument == "--block-port") {

            if (i + 1 >= argc) {

                std::cerr
                    << "Error: --block-port requires a port number.\n";

                return 1;
            }

            int port = 0;

            if (
                !parsePositiveInteger(
                    argv[++i],
                    port
                ) ||
                port > 65535
            ) {

                std::cerr
                    << "Error: invalid port for --block-port.\n";

                return 1;
            }

            blocked_ports.push_back(
                static_cast<uint16_t>(port)
            );

            continue;
        }

        // --------------------------------------------------------
        // Number of load balancers
        // --------------------------------------------------------

        if (argument == "--lbs") {

            if (i + 1 >= argc) {

                std::cerr
                    << "Error: --lbs requires a positive integer.\n";

                return 1;
            }

            int value = 0;

            if (
                !parsePositiveInteger(
                    argv[++i],
                    value
                )
            ) {

                std::cerr
                    << "Error: invalid value for --lbs.\n";

                return 1;
            }

            config.num_load_balancers =
                value;

            continue;
        }

        // --------------------------------------------------------
        // Fast paths per load balancer
        // --------------------------------------------------------

        if (argument == "--fps") {

            if (i + 1 >= argc) {

                std::cerr
                    << "Error: --fps requires a positive integer.\n";

                return 1;
            }

            int value = 0;

            if (
                !parsePositiveInteger(
                    argv[++i],
                    value
                )
            ) {

                std::cerr
                    << "Error: invalid value for --fps.\n";

                return 1;
            }

            config.fps_per_lb =
                value;

            continue;
        }

        // --------------------------------------------------------
        // Verbose
        // --------------------------------------------------------

        if (argument == "--verbose") {

            config.verbose = true;

            continue;
        }

        // --------------------------------------------------------
        // Unknown argument
        // --------------------------------------------------------

        std::cerr
            << "Error: unknown option: "
            << argument
            << "\n";

        printUsage(argv[0]);

        return 1;
    }

    // ============================================================
    // Display configuration
    // ============================================================

    std::cout
        << "\n"
        << "========================================\n"
        << "          DPI ENGINE v2.0\n"
        << "========================================\n"
        << "Input PCAP:        "
        << input_file
        << "\n"
        << "Output PCAP:       "
        << output_file
        << "\n"
        << "Load Balancers:    "
        << config.num_load_balancers
        << "\n"
        << "FPs per LB:        "
        << config.fps_per_lb
        << "\n"
        << "Total Fast Paths:  "
        << (
            config.num_load_balancers *
            config.fps_per_lb
        )
        << "\n"
        << "Verbose:           "
        << (
            config.verbose
                ? "enabled"
                : "disabled"
        )
        << "\n"
        << "========================================\n";

    // ============================================================
    // Create engine
    // ============================================================

    DPI::DPIEngine engine(config);

    // ============================================================
    // Configure blocking rules
    // ============================================================

    if (
        !blocked_ips.empty() ||
        !blocked_apps.empty() ||
        !blocked_domains.empty() ||
        !blocked_ports.empty()
    ) {

        std::cout
            << "\n"
            << "========================================\n"
            << "              ACTIVE RULES\n"
            << "========================================\n";
    }

    for (
        const auto& ip :
        blocked_ips
    ) {

        std::cout
            << "[Rules] Blocked IP: "
            << ip
            << "\n";

        engine.blockIP(ip);
    }

    for (
        const auto& app :
        blocked_apps
    ) {

        std::cout
            << "[Rules] Blocked app: "
            << app
            << "\n";

        engine.blockApp(app);
    }

    for (
        const auto& domain :
        blocked_domains
    ) {

        std::cout
            << "[Rules] Blocked domain: "
            << domain
            << "\n";

        engine.blockDomain(domain);
    }

    for (
        const auto& port :
        blocked_ports
    ) {

        std::cout
            << "[Rules] Blocked port: "
            << port
            << "\n";

        engine.blockPort(port);
    }

    if (
        !blocked_ips.empty() ||
        !blocked_apps.empty() ||
        !blocked_domains.empty() ||
        !blocked_ports.empty()
    ) {

        std::cout
            << "========================================\n";
    }

    // ============================================================
    // Start processing
    // ============================================================

    std::cout
        << "\n"
        << "[Reader] Processing packets...\n";

    const bool success =
        engine.processFile(
            input_file,
            output_file
        );

    if (!success) {

        std::cerr
            << "\n"
            << "[DPI CLI] Processing failed.\n";

        return 1;
    }

    // ============================================================
    // Processing report
    // ============================================================

    std::cout
        << "\n"
        << "========================================\n"
        << "          PROCESSING REPORT\n"
        << "========================================\n";

    std::cout
        << engine.generateReport();

    // ============================================================
    // Final result
    // ============================================================

    std::cout
        << "\n"
        << "========================================\n"
        << "[DPI CLI] Processing completed successfully.\n"
        << "[DPI CLI] Output written to: "
        << output_file
        << "\n"
        << "========================================\n";

    return 0;
}