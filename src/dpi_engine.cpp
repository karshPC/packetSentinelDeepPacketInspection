#include "dpi_engine.h"

#include <iostream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <thread>

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

    uint64_t packets_read = stats_.total_packets.load();
    uint64_t bytes_read = stats_.total_bytes.load();
    uint64_t tcp_packets = stats_.tcp_packets.load();
    uint64_t udp_packets = stats_.udp_packets.load();
    uint64_t other_packets = stats_.other_packets.load();
    uint64_t forwarded_packets = stats_.forwarded_packets.load();
    uint64_t dropped_packets = fp_stats.total_dropped;

    auto percentage = [](uint64_t part, uint64_t total) -> double {
        if (total == 0) {
            return 0.0;
        }

        return (static_cast<double>(part) * 100.0) /
               static_cast<double>(total);
    };

    ss
        << "\n"
        << "============================================================\n"
        << "                    DPI ENGINE REPORT\n"
        << "============================================================\n";

    // ========================================================================
    // Packet Summary
    // ========================================================================

    ss
        << "\n"
        << "PACKET SUMMARY\n"
        << "------------------------------------------------------------\n";

    ss
        << std::left
        << std::setw(30)
        << "Packets read"
        << ": "
        << packets_read
        << "\n";

    ss
        << std::setw(30)
        << "Bytes read"
        << ": "
        << bytes_read
        << "\n";

    ss
        << std::setw(30)
        << "TCP packets"
        << ": "
        << tcp_packets
        << " ("
        << std::fixed
        << std::setprecision(2)
        << percentage(tcp_packets, packets_read)
        << "%)\n";

    ss
        << std::setw(30)
        << "UDP packets"
        << ": "
        << udp_packets
        << " ("
        << std::fixed
        << std::setprecision(2)
        << percentage(udp_packets, packets_read)
        << "%)\n";

    ss
        << std::setw(30)
        << "Other packets"
        << ": "
        << other_packets
        << " ("
        << std::fixed
        << std::setprecision(2)
        << percentage(other_packets, packets_read)
        << "%)\n";

    ss
        << std::setw(30)
        << "Forwarded packets"
        << ": "
        << forwarded_packets
        << " ("
        << std::fixed
        << std::setprecision(2)
        << percentage(forwarded_packets, packets_read)
        << "%)\n";

    ss
        << std::setw(30)
        << "Dropped packets"
        << ": "
        << dropped_packets
        << " ("
        << std::fixed
        << std::setprecision(2)
        << percentage(dropped_packets, packets_read)
        << "%)\n";

    // ========================================================================
    // Pipeline Summary
    // ========================================================================

    ss
        << "\n"
        << "PIPELINE SUMMARY\n"
        << "------------------------------------------------------------\n";

    ss
        << std::setw(30)
        << "Load balancers"
        << ": "
        << (lb_manager_ ? lb_manager_->getNumLBs() : 0)
        << "\n";

    ss
        << std::setw(30)
        << "Fast paths"
        << ": "
        << (fp_manager_ ? fp_manager_->getNumFPs() : 0)
        << "\n";

    ss
        << std::setw(30)
        << "LB packets received"
        << ": "
        << lb_stats.total_received
        << "\n";

    ss
        << std::setw(30)
        << "LB packets dispatched"
        << ": "
        << lb_stats.total_dispatched
        << "\n";

    ss
        << std::setw(30)
        << "FP packets processed"
        << ": "
        << fp_stats.total_processed
        << "\n";

    ss
        << std::setw(30)
        << "FP bytes processed"
        << ": "
        << fp_stats.total_bytes
        << "\n";

    // ========================================================================
    // Load Balancer Details
    // ========================================================================

    if (lb_manager_) {

        ss
            << "\n"
            << "LOAD BALANCER DETAILS\n"
            << "------------------------------------------------------------\n";

        for (int i = 0;
             i < lb_manager_->getNumLBs();
             ++i) {

            const auto stats =
                lb_manager_->getLB(i).getStats();

            ss
                << "LB"
                << i
                << ": received="
                << stats.packets_received
                << ", dispatched="
                << stats.packets_dispatched
                << "\n";

            for (size_t fp = 0;
                 fp < stats.per_fp_packets.size();
                 ++fp) {

                ss
                    << "  FP"
                    << (i * static_cast<int>(stats.per_fp_packets.size()) +
                        static_cast<int>(fp))
                    << " packets="
                    << stats.per_fp_packets[fp]
                    << "\n";
            }
        }
    }

    // ========================================================================
    // Fast Path Details
    // ========================================================================

    if (fp_manager_) {

        ss
            << "\n"
            << "FAST PATH DETAILS\n"
            << "------------------------------------------------------------\n";

        for (int i = 0;
             i < fp_manager_->getNumFPs();
             ++i) {

            const auto stats =
                fp_manager_->getFP(i).getStats();

            ss
                << "FP"
                << i
                << ": processed="
                << stats.packets_processed
                << ", dropped="
                << stats.packets_dropped
                << ", bytes="
                << stats.bytes_processed
                << ", connections="
                << stats.connections_created
                << ", active="
                << stats.active_connections
                << "\n";
        }
    }

    // ========================================================================
    // Connection Summary
    // ========================================================================

    ss
        << "\n"
        << "CONNECTION SUMMARY\n"
        << "------------------------------------------------------------\n";

    uint64_t classified_connections = 0;
    uint64_t blocked_connections = 0;

    if (fp_manager_) {

        for (int i = 0;
             i < fp_manager_->getNumFPs();
             ++i) {

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

    size_t active_connections =
        global_conn_table_
            ? global_conn_table_->getGlobalStats().total_active_connections
            : 0;

    size_t total_connections_seen =
        global_conn_table_
            ? global_conn_table_->getGlobalStats().total_connections_seen
            : 0;

    ss
        << std::setw(30)
        << "Total connections seen"
        << ": "
        << total_connections_seen
        << "\n";

    ss
        << std::setw(30)
        << "Active connections"
        << ": "
        << active_connections
        << "\n";

    ss
        << std::setw(30)
        << "Classified connections"
        << ": "
        << classified_connections
        << "\n";

    ss
        << std::setw(30)
        << "Blocked connections"
        << ": "
        << blocked_connections
        << "\n";

    // ========================================================================
    // Rule Summary
    // ========================================================================

    ss
        << "\n"
        << "RULE SUMMARY\n"
        << "------------------------------------------------------------\n";

    ss
        << std::setw(30)
        << "Blocked IP rules"
        << ": "
        << rule_stats.blocked_ips
        << "\n";

    ss
        << std::setw(30)
        << "Blocked application rules"
        << ": "
        << rule_stats.blocked_apps
        << "\n";

    ss
        << std::setw(30)
        << "Blocked domain rules"
        << ": "
        << rule_stats.blocked_domains
        << "\n";

    ss
        << std::setw(30)
        << "Blocked port rules"
        << ": "
        << rule_stats.blocked_ports
        << "\n";

    ss
        << "\n"
        << "============================================================\n";

    return ss.str();
}

// ============================================================================
// Classification Report
// ============================================================================


std::string DPIEngine::generateClassificationReport() const {

    std::ostringstream ss;

    if (!global_conn_table_) {
        return "\nClassification data unavailable.\n";
    }

    const auto stats =
        global_conn_table_->getGlobalStats();

    ss
        << "\n"
        << "========================================\n"
        << "        APPLICATION CLASSIFICATION\n"
        << "========================================\n";

    std::vector<
        std::pair<std::string, size_t>
    > applications;

    for (const auto& entry :
         stats.app_distribution) {

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

    if (applications.empty()) {
        ss << "No classified applications.\n";
    } else {
        for (const auto& entry :
             applications) {

            ss
                << std::left
                << std::setw(25)
                << entry.first
                << " : "
                << entry.second
                << "\n";
        }
    }

    ss
        << "\n"
        << "========================================\n"
        << "              TOP DOMAINS\n"
        << "========================================\n";

    if (stats.top_domains.empty()) {
        ss << "No domains observed.\n";
    } else {
        size_t rank = 1;

        for (const auto& entry :
             stats.top_domains) {

            ss
                << std::setw(3)
                << rank++
                << ". "
                << std::setw(40)
                << entry.first
                << " : "
                << entry.second
                << "\n";
        }
    }

    ss
        << "========================================\n";

    return ss.str();
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