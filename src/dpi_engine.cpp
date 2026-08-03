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

    // ------------------------------------------------------------
    // Get FastPath statistics ONCE.
    //
    // FastPath is the authoritative source for:
    //   - accepted packets
    //   - dropped packets
    // ------------------------------------------------------------

    FPManager::AggregatedStats fp_stats{};

    if (fp_manager_) {
        fp_stats =
            fp_manager_->getAggregatedStats();
    }

    ss
        << "\n"
        << "========================================\n"
        << "DPI Engine Report\n"
        << "========================================\n";

    ss
        << "Packets read:       "
        << stats_.total_packets.load()
        << "\n";

    ss
        << "Bytes read:         "
        << stats_.total_bytes.load()
        << "\n";

    ss
        << "TCP packets:        "
        << stats_.tcp_packets.load()
        << "\n";

    ss
        << "UDP packets:        "
        << stats_.udp_packets.load()
        << "\n";

    ss
        << "Other packets:      "
        << stats_.other_packets.load()
        << "\n";

    // ------------------------------------------------------------
    // Forwarded packets
    // ------------------------------------------------------------

    ss
        << "Forwarded packets:  "
        << stats_.forwarded_packets.load()
        << "\n";

    // ------------------------------------------------------------
    // Dropped packets
    // ------------------------------------------------------------

    ss
        << "Dropped packets:    "
        << fp_stats.total_dropped
        << "\n";

    // ------------------------------------------------------------
    // Load Balancer statistics.
    // ------------------------------------------------------------

    if (lb_manager_) {

        auto lb_stats =
            lb_manager_->getAggregatedStats();

        ss
            << "\nLoad Balancer:\n";

        ss
            << "  Received:         "
            << lb_stats.total_received
            << "\n";

        ss
            << "  Dispatched:       "
            << lb_stats.total_dispatched
            << "\n";
    }

    // ------------------------------------------------------------
    // Fast Path statistics.
    // ------------------------------------------------------------

    if (fp_manager_) {

        ss
            << "\nFast Paths:\n";

        ss
            << "  Packets processed: "
            << fp_stats.total_processed
            << "\n";

        ss
            << "  Packets dropped:   "
            << fp_stats.total_dropped
            << "\n";

        ss
            << "  Bytes processed:   "
            << fp_stats.total_bytes
            << "\n";

        ss
            << "  Connections seen:  "
            << fp_stats.total_connections
            << "\n";

        ss
            << "  Active connections: "
            << fp_stats.total_active_connections
            << "\n";
    }

    // ------------------------------------------------------------
    // Global connection table.
    // ------------------------------------------------------------

    if (global_conn_table_) {

        auto global_stats =
            global_conn_table_->getGlobalStats();

        ss
            << "\nGlobal Connections:\n";

        ss
            << "  Active:            "
            << global_stats.total_active_connections
            << "\n";

        ss
            << "  Total seen:        "
            << global_stats.total_connections_seen
            << "\n";
    }

    ss
        << "========================================\n";

    return ss.str();
}

// ============================================================================
// Classification Report
// ============================================================================

std::string DPIEngine::generateClassificationReport() const {

    std::ostringstream ss;

    ss
        << "\n"
        << "========================================\n"
        << "Classification Report\n"
        << "========================================\n"
        << "Application classification is not yet\n"
        << "enabled in the current FastPath implementation.\n"
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