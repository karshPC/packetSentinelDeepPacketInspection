#ifndef DPI_ENGINE_H
#define DPI_ENGINE_H

#include "types.h"
#include "pcap_reader.h"
#include "packet_parser.h"
#include "packet_job_builder.h"
#include "load_balancer.h"
#include "fp_manager.h"
#include "fast_path.h"
#include "rule_manager.h"
#include "connection_tracker.h"

#include <atomic>
#include <fstream>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

namespace DPI {

// ============================================================================
// DPI Engine - Main Orchestrator
// ============================================================================
//
//
//   PCAP Reader
//        |
//        v
//   Load Balancers
//     LB0   LB1
//      |     |
//      v     v
//   Fast Paths
//   FP0 FP1 FP2 FP3
//        |
//        v
//   Output Queue
//        |
//        v
//   Output Writer
//
// ============================================================================

class DPIEngine {
public:

    struct Config {
        int num_load_balancers = 2;
        int fps_per_lb = 2;
        size_t queue_size = 10000;
        std::string rules_file;
        bool verbose = false;
    };

    DPIEngine(const Config& config);

    ~DPIEngine();

    // Initialize the engine.
    bool initialize();

    // Process a PCAP file.
    bool processFile(
        const std::string& input_file,
        const std::string& output_file
    );

    // Start all processing threads.
    void start();

    // Stop all processing threads.
    void stop();

    // Wait for the reader and processing pipeline.
    void waitForCompletion();

    // ================================================================
    // Rule Management
    // ================================================================

    void blockIP(
        const std::string& ip
    );

    void unblockIP(
        const std::string& ip
    );

    void blockApp(
        AppType app
    );

    void blockApp(
        const std::string& app_name
    );

    void unblockApp(
        AppType app
    );

    void unblockApp(
        const std::string& app_name
    );

    void blockDomain(
        const std::string& domain
    );

    void unblockDomain(
        const std::string& domain
    );

    void blockPort(
        uint16_t port
    );

    void unblockPort(
        uint16_t port
    );

    bool loadRules(
        const std::string& filename
    );

    bool saveRules(
        const std::string& filename
    );

    // ================================================================
    // Reporting
    // ================================================================

    std::string generateReport() const;

    std::string generateClassificationReport() const;

    const DPIStats& getStats() const;

    void printStatus() const;

    // ================================================================
    // Accessors
    // ================================================================

    RuleManager& getRuleManager() {
        return *rule_manager_;
    }

    const Config& getConfig() const {
        return config_;
    }

    bool isRunning() const {
        return running_.load();
    }

private:

    Config config_;

    // ================================================================
    // Shared Components
    // ================================================================

    std::unique_ptr<RuleManager> rule_manager_;

    std::unique_ptr<GlobalConnectionTable>
        global_conn_table_;

    // ================================================================
    // Processing Pipeline
    // ================================================================

    std::unique_ptr<FPManager>
        fp_manager_;

    std::unique_ptr<LBManager>
        lb_manager_;

    // ================================================================
    // Output
    // ================================================================

    ThreadSafeQueue<PacketJob>
        output_queue_;

    std::thread output_thread_;

    std::ofstream output_file_;

    std::mutex output_mutex_;

    // ================================================================
    // Statistics
    // ================================================================

    DPIStats stats_;

    // ================================================================
    // Control
    // ================================================================

    std::atomic<bool>
        running_{false};

    std::atomic<bool>
        processing_complete_{false};

    // ================================================================
    // Reader
    // ================================================================

    std::thread reader_thread_;

    // ================================================================
    // Output Functions
    // ================================================================

    void outputThreadFunc();

    void handleOutput(
        const PacketJob& job,
        PacketAction action
    );

    bool writeOutputHeader(
        const PacketAnalyzer::PcapGlobalHeader& header
    );

    void writeOutputPacket(
        const PacketJob& job
    );

    // ================================================================
    // Reader
    // ================================================================

    void readerThreadFunc(
        const std::string& input_file
    );

    // ================================================================
    // Packet Conversion
    // ================================================================

    PacketJob createPacketJob(
        const PacketAnalyzer::RawPacket& raw,
        const PacketAnalyzer::ParsedPacket& parsed,
        uint32_t packet_id
    );
};

} // namespace DPI

#endif // DPI_ENGINE_H