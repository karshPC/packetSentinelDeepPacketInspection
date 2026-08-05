#include "dpi_engine.h"

#include <iostream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <thread>
#include <algorithm>
#include <vector>
#include <string>

namespace DPI {

// ============================================================================
// DPIEngine
// ============================================================================

DPIEngine::DPIEngine(
    const Config& config
)
    : config_(config),
      output_queue_(config.queue_size) {
}

// ============================================================================
// Destructor
// ============================================================================

DPIEngine::~DPIEngine() {
    stop();
}

// ============================================================================
// Initialization
// ============================================================================

bool DPIEngine::initialize() {

    if (rule_manager_) {
        return true;
    }

    rule_manager_ =
        std::make_unique<RuleManager>();

    if (!config_.rules_file.empty()) {

        if (!rule_manager_->loadRules(
                config_.rules_file)) {

            std::cerr
                << "[DPIEngine] Warning: "
                << "Could not load rules file: "
                << config_.rules_file
                << "\n";
        }
    }

    const int total_fps =
        config_.num_load_balancers *
        config_.fps_per_lb;

    // ------------------------------------------------------------
    // Fast Path Manager
    // ------------------------------------------------------------

    fp_manager_ =
        std::make_unique<FPManager>(
            total_fps,
            100000,
            rule_manager_.get(),
            &output_queue_
        );

    // ------------------------------------------------------------
    // Load Balancer Manager
    // ------------------------------------------------------------

    lb_manager_ =
        std::make_unique<LBManager>(
            config_.num_load_balancers,
            config_.fps_per_lb,
            fp_manager_->getQueuePtrs()
        );

    // ------------------------------------------------------------
    // Global Connection Table
    // ------------------------------------------------------------

    global_conn_table_ =
        std::make_unique<GlobalConnectionTable>(
            static_cast<size_t>(total_fps)
        );

    for (int i = 0; i < total_fps; ++i) {

        global_conn_table_->registerTracker(
            i,
            &fp_manager_
                ->getFP(i)
                .getConnectionTracker()
        );
    }

    std::cout
        << "[DPIEngine] Initialized with "
        << config_.num_load_balancers
        << " load balancers and "
        << total_fps
        << " fast paths\n";

    return true;
}

// ============================================================================
// Start
// ============================================================================

void DPIEngine::start() {

    if (running_.load()) {
        return;
    }

    if (!rule_manager_) {

        if (!initialize()) {
            return;
        }
    }

    running_.store(true);
    processing_complete_.store(false);

    // ------------------------------------------------------------
    // Start output writer.
    // ------------------------------------------------------------

    output_thread_ =
        std::thread(
            &DPIEngine::outputThreadFunc,
            this
        );

    // ------------------------------------------------------------
    // Start Fast Paths first.
    // ------------------------------------------------------------

    fp_manager_->startAll();

    // ------------------------------------------------------------
    // Then start Load Balancers.
    // ------------------------------------------------------------

    lb_manager_->startAll();

    std::cout
        << "[DPIEngine] Processing pipeline started\n";
}

// ============================================================================
// Stop
// ============================================================================

void DPIEngine::stop() {

    if (!running_.load()) {
        return;
    }

    // ------------------------------------------------------------
    // Stop accepting new work.
    // ------------------------------------------------------------

    running_.store(false);

    // ------------------------------------------------------------
    // Stop reader first.
    // ------------------------------------------------------------

    if (reader_thread_.joinable()) {
        reader_thread_.join();
    }

    // ------------------------------------------------------------
    // Stop load balancers.
    // ------------------------------------------------------------

    if (lb_manager_) {
        lb_manager_->stopAll();
    }

    // ------------------------------------------------------------
    // Stop fast paths.
    // ------------------------------------------------------------

    if (fp_manager_) {
        fp_manager_->stopAll();
    }

    // ------------------------------------------------------------
    // Stop output queue.
    // ------------------------------------------------------------

    output_queue_.shutdown();

    // ------------------------------------------------------------
    // Stop output writer.
    // ------------------------------------------------------------

    if (output_thread_.joinable()) {
        output_thread_.join();
    }

    processing_complete_.store(true);

    std::cout
        << "[DPIEngine] Processing pipeline stopped\n";
}

// ============================================================================
// Process PCAP
// ============================================================================

bool DPIEngine::processFile(
    const std::string& input_file,
    const std::string& output_file
) {

    if (!initialize()) {
        return false;
    }

    // ------------------------------------------------------------
    // Open output file.
    // ------------------------------------------------------------

    output_file_.open(
        output_file,
        std::ios::binary
    );

    if (!output_file_.is_open()) {

        std::cerr
            << "[DPIEngine] Cannot open output file: "
            << output_file
            << "\n";

        return false;
    }

    // ------------------------------------------------------------
    // Start pipeline.
    // ------------------------------------------------------------

    start();

    // ------------------------------------------------------------
    // Start reader thread.
    // ------------------------------------------------------------

    reader_thread_ =
        std::thread(
            &DPIEngine::readerThreadFunc,
            this,
            input_file
        );

    // ------------------------------------------------------------
    // Wait for reader.
    // ------------------------------------------------------------

    waitForCompletion();

    // ------------------------------------------------------------
    // Allow downstream queues to drain.
    // ------------------------------------------------------------

    std::this_thread::sleep_for(
        std::chrono::milliseconds(500)
    );

    // ------------------------------------------------------------
    // Stop pipeline.
    // ------------------------------------------------------------

    stop();

    if (output_file_.is_open()) {
        output_file_.close();
    }

    return true;
}

// ============================================================================
// Wait for completion
// ============================================================================

void DPIEngine::waitForCompletion() {

    if (reader_thread_.joinable()) {
        reader_thread_.join();
    }

    processing_complete_.store(true);
}

// ============================================================================
// Reader Thread
// ============================================================================

void DPIEngine::readerThreadFunc(
    const std::string& input_file
) {

    PacketAnalyzer::PcapReader reader;

    if (!reader.open(input_file)) {

        std::cerr
            << "[DPIEngine] Failed to open input PCAP: "
            << input_file
            << "\n";

        return;
    }

    // ------------------------------------------------------------
    // Write output PCAP header.
    // ------------------------------------------------------------

    writeOutputHeader(
        reader.getGlobalHeader()
    );

    PacketAnalyzer::RawPacket raw;

    uint32_t packet_id = 0;

    if (config_.verbose) {

        std::cout
            << "[Reader] Processing: "
            << input_file
            << "\n";
    }

    while (
        reader.readNextPacket(raw)
    ) {

        // --------------------------------------------------------
        // Parse packet.
        // --------------------------------------------------------

        PacketAnalyzer::ParsedPacket parsed =
            PacketAnalyzer::PacketParser::parse(
                raw.data.data(),
                raw.data.size()
            );

        if (!parsed.valid) {
            continue;
        }

        // --------------------------------------------------------
        // Current parser represents protocol presence through
        // the header pointers.
        // --------------------------------------------------------

        const bool has_ip =
            parsed.ipv4 != nullptr;

        const bool has_tcp =
            parsed.tcp != nullptr;

        const bool has_udp =
            parsed.udp != nullptr;

        // --------------------------------------------------------
        // We only send IPv4 TCP/UDP packets into the pipeline.
        // --------------------------------------------------------

        if (!has_ip) {
            continue;
        }

        if (!has_tcp && !has_udp) {
            continue;
        }

        // --------------------------------------------------------
        // Create PacketJob.
        // --------------------------------------------------------

        PacketJob job =
            createPacketJob(
                raw,
                parsed,
                packet_id++
            );

        // --------------------------------------------------------
        // Global statistics.
        // --------------------------------------------------------

        stats_.total_packets++;

        stats_.total_bytes +=
            raw.data.size();

        if (has_tcp) {

            stats_.tcp_packets++;

        }
        else if (has_udp) {

            stats_.udp_packets++;

        }
        else {

            stats_.other_packets++;
        }

        // --------------------------------------------------------
        // Send packet ONLY to Load Balancer.
        //
        // Reader -> LB -> FastPath -> RuleManager
        //                          |
        //                     DROP / ACCEPT
        //                          |
        //                       Output
        // --------------------------------------------------------

        LoadBalancer& lb =
            lb_manager_->getLBForPacket(
                job.tuple
            );

        lb.getInputQueue().push(
            std::move(job)
        );
    }

    reader.close();

    if (config_.verbose) {

        std::cout
            << "[Reader] Finished. Packets submitted: "
            << packet_id
            << "\n";
    }
}

// ============================================================================
// PacketJob Creation
// ============================================================================

PacketJob DPIEngine::createPacketJob(
    const PacketAnalyzer::RawPacket& raw,
    const PacketAnalyzer::ParsedPacket& parsed,
    uint32_t packet_id
) {

    PacketJob job;

    job.packet_id =
        packet_id;

    job.ts_sec =
        raw.header.ts_sec;

    job.ts_usec =
        raw.header.ts_usec;

    // ------------------------------------------------------------
    // Five Tuple
    // ------------------------------------------------------------

    job.tuple =
        PacketAnalyzer::PacketParser::extractFiveTuple(
            parsed
        );

    // ------------------------------------------------------------
    // Packet data.
    // ------------------------------------------------------------

    job.data =
        raw.data;

    // ------------------------------------------------------------
    // Parser offsets.
    // ------------------------------------------------------------

    job.eth_offset =
        parsed.eth_offset;

    job.ip_offset =
        parsed.ip_offset;

    job.transport_offset =
        parsed.transport_offset;

    job.payload_offset =
        parsed.payload_offset;

    job.payload_length =
        parsed.payload_length;

    job.tcp_flags =
        parsed.tcp_flags;

    // ------------------------------------------------------------
    // Payload information.
    //
    // PacketJob owns its own copy of the packet data.
    // ------------------------------------------------------------

    if (
        job.payload_offset <
        job.data.size()
    ) {

        job.payload_length =
            job.data.size() -
            job.payload_offset;

    }
    else {

        job.payload_length = 0;
    }

    return job;
}

// ============================================================================
// Output Thread
// ============================================================================

void DPIEngine::outputThreadFunc() {

    while (
        running_.load() ||
        !output_queue_.empty()
    ) {

        PacketJob job;

        const bool received =
            output_queue_.pop(job);

        if (!received) {
            continue;
        }

        writeOutputPacket(job);

        // Every packet reaching the output queue has already
        // passed FastPath rule checking.
        stats_.forwarded_packets++;
    }
}

// ============================================================================
// Output Handler
// ============================================================================

void DPIEngine::handleOutput(
    const PacketJob& job,
    PacketAction action
) {

    if (action == PacketAction::DROP) {

        stats_.dropped_packets++;

        return;
    }

    output_queue_.push(
        job
    );
}

// ============================================================================
// Write PCAP Header
// ============================================================================

bool DPIEngine::writeOutputHeader(
    const PacketAnalyzer::PcapGlobalHeader& header
) {

    std::lock_guard<std::mutex>
        lock(output_mutex_);

    if (!output_file_.is_open()) {
        return false;
    }

    output_file_.write(
        reinterpret_cast<const char*>(&header),
        sizeof(header)
    );

    return output_file_.good();
}

// ============================================================================
// Write Packet
// ============================================================================

void DPIEngine::writeOutputPacket(
    const PacketJob& job
) {

    std::lock_guard<std::mutex>
        lock(output_mutex_);

    if (!output_file_.is_open()) {
        return;
    }

    PacketAnalyzer::PcapPacketHeader header;

    header.ts_sec =
        job.ts_sec;

    header.ts_usec =
        job.ts_usec;

    header.incl_len =
        static_cast<uint32_t>(
            job.data.size()
        );

    header.orig_len =
        static_cast<uint32_t>(
            job.data.size()
        );

    output_file_.write(
        reinterpret_cast<const char*>(&header),
        sizeof(header)
    );

    if (!job.data.empty()) {

        output_file_.write(
            reinterpret_cast<const char*>(
                job.data.data()
            ),
            static_cast<std::streamsize>(
                job.data.size()
            )
        );
    }
}

// ============================================================================
// Rule Management
// ============================================================================

void DPIEngine::blockIP(
    const std::string& ip
) {

    if (!rule_manager_) {

        if (!initialize()) {
            return;
        }
    }

    rule_manager_->blockIP(ip);
}

void DPIEngine::unblockIP(
    const std::string& ip
) {

    if (!rule_manager_) {

        if (!initialize()) {
            return;
        }
    }

    rule_manager_->unblockIP(ip);
}

void DPIEngine::blockApp(
    AppType app
) {

    if (!rule_manager_) {

        if (!initialize()) {
            return;
        }
    }

    rule_manager_->blockApp(app);
}

void DPIEngine::blockApp(
    const std::string& app_name
) {

    if (!rule_manager_) {

        if (!initialize()) {
            return;
        }
    }

    for (
        int i = 0;
        i < static_cast<int>(
            AppType::APP_COUNT
        );
        ++i
    ) {

        AppType app =
            static_cast<AppType>(i);

        if (
            appTypeToString(app) ==
            app_name
        ) {

            rule_manager_->blockApp(
                app
            );

            return;
        }
    }
}

void DPIEngine::unblockApp(
    AppType app
) {

    if (!rule_manager_) {

        if (!initialize()) {
            return;
        }
    }

    rule_manager_->unblockApp(app);
}

void DPIEngine::unblockApp(
    const std::string& app_name
) {

    if (!rule_manager_) {

        if (!initialize()) {
            return;
        }
    }

    for (
        int i = 0;
        i < static_cast<int>(
            AppType::APP_COUNT
        );
        ++i
    ) {

        AppType app =
            static_cast<AppType>(i);

        if (
            appTypeToString(app) ==
            app_name
        ) {

            rule_manager_->unblockApp(
                app
            );

            return;
        }
    }
}

void DPIEngine::blockDomain(
    const std::string& domain
) {

    if (!rule_manager_) {

        if (!initialize()) {
            return;
        }
    }

    rule_manager_->blockDomain(domain);
}

void DPIEngine::unblockDomain(
    const std::string& domain
) {

    if (!rule_manager_) {

        if (!initialize()) {
            return;
        }
    }

    rule_manager_->unblockDomain(domain);
}

// ============================================================================
// Port Blocking
// ============================================================================

void DPIEngine::blockPort(
    uint16_t port
) {

    if (!rule_manager_) {

        if (!initialize()) {
            return;
        }
    }

    rule_manager_->blockPort(port);
}

void DPIEngine::unblockPort(
    uint16_t port
) {

    if (!rule_manager_) {

        if (!initialize()) {
            return;
        }
    }

    rule_manager_->unblockPort(port);
}

bool DPIEngine::loadRules(
    const std::string& filename
) {

    if (!rule_manager_) {

        if (!initialize()) {
            return false;
        }
    }

    return rule_manager_->loadRules(
        filename
    );
}

bool DPIEngine::saveRules(
    const std::string& filename
) {

    if (!rule_manager_) {

        if (!initialize()) {
            return false;
        }
    }

    return rule_manager_->saveRules(
        filename
    );
}

// ============================================================================
// Statistics Report
// ============================================================================

namespace {

constexpr size_t REPORT_WIDTH = 60;

std::string reportBorder(
    const std::string& left,
    const std::string& fill,
    const std::string& right
) {
    std::string line = left;

    for (size_t i = 0; i < REPORT_WIDTH; ++i) {
        line += fill;
    }

    line += right;
    line += "\n";

    return line;
}

std::string reportRow(const std::string& content) {
    std::string row = content;

    if (row.size() > REPORT_WIDTH) {
        row.resize(REPORT_WIDTH);
    } else if (row.size() < REPORT_WIDTH) {
        row.append(REPORT_WIDTH - row.size(), ' ');
    }

    return "║" + row + "║\n";
}

std::string reportCentered(const std::string& content) {
    if (content.size() >= REPORT_WIDTH) {
        return reportRow(content.substr(0, REPORT_WIDTH));
    }

    const size_t total_padding = REPORT_WIDTH - content.size();
    const size_t left_padding = total_padding / 2;
    const size_t right_padding = total_padding - left_padding;

    return "║" +
           std::string(left_padding, ' ') +
           content +
           std::string(right_padding, ' ') +
           "║\n";
}

std::string reportLabelValue(const std::string& label,
                             uint64_t value) {
    std::ostringstream line;
    line << "  " << std::left << std::setw(29) << label
         << value;
    return line.str();
}

} // namespace

// ============================================================================
// Statistics Report
// ============================================================================

std::string DPIEngine::generateReport() const {

    std::ostringstream ss;

    FPManager::AggregatedStats fp_stats{};
    if (fp_manager_) {
        fp_stats = fp_manager_->getAggregatedStats();
    }

    LBManager::AggregatedStats lb_stats{};
    if (lb_manager_) {
        lb_stats = lb_manager_->getAggregatedStats();
    }

    RuleManager::RuleStats rule_stats{};
    if (rule_manager_) {
        rule_stats = rule_manager_->getStats();
    }

    const uint64_t packets_read = stats_.total_packets.load();
    const uint64_t bytes_read = stats_.total_bytes.load();
    const uint64_t tcp_packets = stats_.tcp_packets.load();
    const uint64_t udp_packets = stats_.udp_packets.load();
    const uint64_t other_packets = stats_.other_packets.load();
    const uint64_t forwarded_packets = stats_.forwarded_packets.load();
    const uint64_t dropped_packets = fp_stats.total_dropped;

    auto percentage = [](uint64_t part, uint64_t total) -> double {
        if (total == 0) {
            return 0.0;
        }
        return (static_cast<double>(part) * 100.0) /
               static_cast<double>(total);
    };

    // ------------------------------------------------------------------------
    // Header
    // ------------------------------------------------------------------------

    ss << "\n"
       << reportBorder("╔", "═", "╗")
       << reportCentered("DPI ENGINE v2.0 (Multi-threaded)")
       << reportBorder("╠", "═", "╣");

    {
        std::ostringstream line;
        line << "  Load Balancers: " << std::left << std::setw(4)
             << (lb_manager_ ? lb_manager_->getNumLBs() : 0)
             << "  FPs per LB: " << std::setw(4)
             << config_.fps_per_lb
             << "  Total FPs: "
             << (fp_manager_ ? fp_manager_->getNumFPs() : 0);
        ss << reportRow(line.str());
    }

    ss << reportBorder("╚", "═", "╝");

    // ------------------------------------------------------------------------
    // Active rules
    // ------------------------------------------------------------------------

    ss << "\n"
       << reportBorder("╔", "═", "╗")
       << reportCentered("ACTIVE RULES")
       << reportBorder("╠", "═", "╣");

    if (rule_manager_) {
        std::ostringstream line;
        line << "  IP rules: " << rule_stats.blocked_ips
             << "   App rules: " << rule_stats.blocked_apps
             << "   Domain rules: " << rule_stats.blocked_domains
             << "   Port rules: " << rule_stats.blocked_ports;
        ss << reportRow(line.str());
    } else {
        ss << reportRow("  No rule manager initialized.");
    }

    ss << reportBorder("╚", "═", "╝");

    // ------------------------------------------------------------------------
    // Processing report
    // ------------------------------------------------------------------------

    ss << "\n"
       << reportBorder("╔", "═", "╗")
       << reportCentered("PROCESSING REPORT")
       << reportBorder("╠", "═", "╣");

    ss << reportRow(reportLabelValue("Total Packets:", packets_read));
    ss << reportRow(reportLabelValue("Total Bytes:", bytes_read));
    ss << reportRow(reportLabelValue("TCP Packets:", tcp_packets));
    ss << reportRow(reportLabelValue("UDP Packets:", udp_packets));
    ss << reportRow(reportLabelValue("Other Packets:", other_packets));
    ss << reportBorder("╠", "═", "╣");
    ss << reportRow(reportLabelValue("Forwarded:", forwarded_packets));
    ss << reportRow(reportLabelValue("Dropped:", dropped_packets));

    {
        std::ostringstream line;
        line << "  Forward Rate: " << std::fixed << std::setprecision(1)
             << percentage(forwarded_packets, packets_read) << "%";
        ss << reportRow(line.str());
    }

    {
        std::ostringstream line;
        line << "  Drop Rate: " << std::fixed << std::setprecision(1)
             << percentage(dropped_packets, packets_read) << "%";
        ss << reportRow(line.str());
    }

    ss << reportBorder("╠", "═", "╣");

    // ------------------------------------------------------------------------
    // Thread statistics
    // ------------------------------------------------------------------------

    ss << reportCentered("THREAD STATISTICS")
       << reportBorder("╠", "═", "╣");

    if (lb_manager_) {
        for (int i = 0; i < lb_manager_->getNumLBs(); ++i) {
            const auto lb = lb_manager_->getLB(i).getStats();

            std::ostringstream line;
            line << "  LB" << i << " dispatched:"
                 << std::right << std::setw(24)
                 << lb.packets_dispatched;
            ss << reportRow(line.str());
        }
    }

    if (fp_manager_) {
        for (int i = 0; i < fp_manager_->getNumFPs(); ++i) {
            const auto fp = fp_manager_->getFP(i).getStats();

            std::ostringstream line;
            line << "  FP" << i << " processed:"
                 << std::right << std::setw(25)
                 << fp.packets_processed;
            ss << reportRow(line.str());
        }
    }

    ss << reportBorder("╚", "═", "╝");

    // ------------------------------------------------------------------------
    // Application breakdown
    // ------------------------------------------------------------------------

    ss << "\n"
       << reportBorder("╔", "═", "╗")
       << reportCentered("APPLICATION BREAKDOWN")
       << reportBorder("╠", "═", "╣");

    if (global_conn_table_) {
        const auto global_stats =
            global_conn_table_->getGlobalStats();

        std::vector<std::pair<std::string, size_t>> applications;
        applications.reserve(global_stats.app_distribution.size());

        for (const auto& entry : global_stats.app_distribution) {
            applications.emplace_back(
                appTypeToString(entry.first),
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

        const size_t display_count =
            std::min<size_t>(applications.size(), 8);

        const size_t total_classified =
            global_stats.total_connections_seen;

        for (size_t i = 0; i < display_count; ++i) {
            const auto& entry = applications[i];

            std::ostringstream line;
            line << "  " << std::left << std::setw(20)
                 << entry.first
                 << std::right << std::setw(6)
                 << entry.second
                 << "  " << std::fixed << std::setprecision(1)
                 << percentage(entry.second, total_classified)
                 << "%  ";

            const size_t bar_length =
                total_classified == 0
                    ? 0
                    : static_cast<size_t>(
                          (static_cast<double>(entry.second) /
                           static_cast<double>(total_classified)) * 20.0
                      );

            line << std::string(bar_length, '#');

            ss << reportRow(line.str());
        }

        if (applications.size() > display_count) {
            ss << reportRow("  ...");
        }
    } else {
        ss << reportRow("  Classification data unavailable.");
    }

    ss << reportBorder("╚", "═", "╝");

    // ------------------------------------------------------------------------
    // Detected domains / SNI
    // ------------------------------------------------------------------------

    ss << "\n"
       << "[DETECTED DOMAINS / SNI]\n\n";

    if (global_conn_table_) {
        const auto global_stats =
            global_conn_table_->getGlobalStats();

        size_t displayed = 0;
        for (const auto& entry : global_stats.top_domains) {
            ss << "  - " << entry.first
               << " -> " << entry.second << "\n";

            if (++displayed >= 10) {
                break;
            }
        }

        if (displayed == 0) {
            ss << "  - None detected\n";
        } else if (global_stats.top_domains.size() > displayed) {
            ss << "  ...\n";
        }
    } else {
        ss << "  - Classification data unavailable\n";
    }

    // ------------------------------------------------------------------------
    // Connection summary
    // ------------------------------------------------------------------------

    ss << "\n"
       << reportBorder("╔", "═", "╗")
       << reportCentered("CONNECTION SUMMARY")
       << reportBorder("╠", "═", "╣");

    uint64_t classified_connections = 0;
    uint64_t blocked_connections = 0;

    if (fp_manager_) {
        for (int i = 0; i < fp_manager_->getNumFPs(); ++i) {
            const auto tracker_stats =
                fp_manager_->getFP(i)
                    .getConnectionTracker()
                    .getStats();

            classified_connections +=
                tracker_stats.classified_connections;
            blocked_connections +=
                tracker_stats.blocked_connections;
        }
    }

    const size_t active_connections =
        global_conn_table_
            ? global_conn_table_->getGlobalStats().total_active_connections
            : 0;

    const size_t total_connections_seen =
        global_conn_table_
            ? global_conn_table_->getGlobalStats().total_connections_seen
            : 0;

    ss << reportRow(reportLabelValue("Total Connections Seen:", total_connections_seen));
    ss << reportRow(reportLabelValue("Active Connections:", active_connections));
    ss << reportRow(reportLabelValue("Classified Connections:", classified_connections));
    ss << reportRow(reportLabelValue("Blocked Connections:", blocked_connections));

    ss << reportBorder("╚", "═", "╝");

    // ------------------------------------------------------------------------
    // Rule summary
    // ------------------------------------------------------------------------

    ss << "\n"
       << reportBorder("╔", "═", "╗")
       << reportCentered("RULE SUMMARY")
       << reportBorder("╠", "═", "╣");

    ss << reportRow(reportLabelValue("Blocked IP Rules:", rule_stats.blocked_ips));
    ss << reportRow(reportLabelValue("Blocked App Rules:", rule_stats.blocked_apps));
    ss << reportRow(reportLabelValue("Blocked Domain Rules:", rule_stats.blocked_domains));
    ss << reportRow(reportLabelValue("Blocked Port Rules:", rule_stats.blocked_ports));

    ss << reportBorder("╚", "═", "╝");

    return ss.str();
}

// ============================================================================
// Classification Report
// ============================================================================

std::string DPIEngine::generateClassificationReport() const {

    // Classification is now included in generateReport().
    // Keep this public API for compatibility with the existing CLI/tests.
    if (!global_conn_table_) {
        return "\nClassification data unavailable.\n";
    }

    return "";
}

// ============================================================================
// Statistics Accessor
// ============================================================================

const DPIStats& DPIEngine::getStats() const {
    return stats_;
}

// ============================================================================
// Live Status
// ============================================================================

void DPIEngine::printStatus() const {

    std::cout
        << "\n--- DPI Engine Status ---\n";

    std::cout
        << "Running: "
        << (running_.load() ? "YES" : "NO")
        << "\n";

    std::cout
        << "Packets: "
        << stats_.total_packets.load()
        << "\n";

    std::cout
        << "Bytes: "
        << stats_.total_bytes.load()
        << "\n";

    // ------------------------------------------------------------
    // Get authoritative FastPath statistics.
    // ------------------------------------------------------------

    uint64_t forwarded = 0;
    uint64_t dropped = 0;

    if (fp_manager_) {

        const auto fp_stats =
            fp_manager_->getAggregatedStats();

        forwarded =
            fp_stats.total_processed;

        dropped =
            fp_stats.total_dropped;

        std::cout
            << "FP processed: "
            << fp_stats.total_processed
            << "\n";

        std::cout
            << "FP dropped: "
            << fp_stats.total_dropped
            << "\n";

        std::cout
            << "Connections: "
            << fp_stats.total_connections
            << "\n";

        std::cout
            << "Active connections: "
            << fp_stats.total_active_connections
            << "\n";
    }

    std::cout
        << "Forwarded: "
        << forwarded
        << "\n";

    std::cout
        << "Dropped: "
        << dropped
        << "\n";
}

} // namespace DPI