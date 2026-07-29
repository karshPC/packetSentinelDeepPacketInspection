#include "dpi_engine.h"

#include <iostream>
#include <string>
#include <vector>

namespace {

void printUsage(const char* program) {

    std::cout
        << "\n"
        << "DPI Engine - Deep Packet Inspection System\n"
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
        << "Example:\n"
        << "  " << program
        << " capture.pcap filtered.pcap\n"
        << "\n"
        << "Example with blocking:\n"
        << "  " << program
        << " capture.pcap filtered.pcap"
        << " --block-ip 192.168.1.50"
        << " --block-app YouTube"
        << " --block-domain facebook\n"
        << "\n"
        << "Example with custom pipeline:\n"
        << "  " << program
        << " capture.pcap filtered.pcap"
        << " --lbs 4 --fps 4\n"
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

        if (
            std::string(argv[i]) == "--help" ||
            std::string(argv[i]) == "-h"
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
        // Verbose mode
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
        << "\n========================================\n"
        << "DPI Engine\n"
        << "========================================\n"
        << "Input PCAP:  "
        << input_file
        << "\n"
        << "Output PCAP: "
        << output_file
        << "\n"
        << "Load balancers: "
        << config.num_load_balancers
        << "\n"
        << "Fast paths per LB: "
        << config.fps_per_lb
        << "\n"
        << "Total fast paths: "
        << (
            config.num_load_balancers *
            config.fps_per_lb
        )
        << "\n"
        << "Verbose: "
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

    for (
        const auto& ip :
        blocked_ips
    ) {

        std::cout
            << "[CLI] Blocking IP: "
            << ip
            << "\n";

        engine.blockIP(ip);
    }

    for (
        const auto& app :
        blocked_apps
    ) {

        std::cout
            << "[CLI] Blocking application: "
            << app
            << "\n";

        engine.blockApp(app);
    }

    for (
        const auto& domain :
        blocked_domains
    ) {

        std::cout
            << "[CLI] Blocking domain: "
            << domain
            << "\n";

        engine.blockDomain(domain);
    }

    // ============================================================
    // Process PCAP
    // ============================================================

    std::cout
        << "\n[DPI CLI] Starting packet inspection...\n";

    const bool success =
        engine.processFile(
            input_file,
            output_file
        );

    if (!success) {

        std::cerr
            << "\n[DPI CLI] Processing failed.\n";

        return 1;
    }

    // ============================================================
    // Final result
    // ============================================================

    std::cout
        << "\n[DPI CLI] Processing completed successfully.\n"
        << "[DPI CLI] Output written to: "
        << output_file
        << "\n";

    return 0;
}