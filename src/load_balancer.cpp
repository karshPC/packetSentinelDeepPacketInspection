#include "load_balancer.h"

#include <chrono>
#include <iostream>
#include <stdexcept>

namespace DPI {

// ============================================================================
// LoadBalancer
// ============================================================================

LoadBalancer::LoadBalancer(
    int lb_id,
    std::vector<ThreadSafeQueue<PacketJob>*> fp_queues,
    int fp_start_id
)
    : lb_id_(lb_id),
      fp_start_id_(fp_start_id),
      num_fps_(
          static_cast<int>(fp_queues.size())
      ),
      input_queue_(10000),
      fp_queues_(std::move(fp_queues)),
      per_fp_counts_(
          fp_queues_.size(),
          0
      ) {
}

LoadBalancer::~LoadBalancer() {
    stop();
}

void LoadBalancer::start() {
    if (running_.load()) {
        return;
    }

    if (fp_queues_.empty()) {
        throw std::runtime_error(
            "LoadBalancer requires at least one FP queue"
        );
    }

    running_.store(true);

    thread_ =
        std::thread(
            &LoadBalancer::run,
            this
        );

    std::cout
        << "[LB"
        << lb_id_
        << "] Started (serving FP"
        << fp_start_id_
        << "-FP"
        << (fp_start_id_ + num_fps_ - 1)
        << ")\n";
}

void LoadBalancer::stop() {
    if (!running_.load()) {
        return;
    }

    running_.store(false);

    input_queue_.shutdown();

    if (thread_.joinable()) {
        thread_.join();
    }

    std::cout
        << "[LB"
        << lb_id_
        << "] Stopped\n";
}

void LoadBalancer::run() {
    while (running_.load()) {

        PacketJob job;

        const bool received =
            input_queue_.tryPop(
                job,
                std::chrono::milliseconds(100)
            );

        if (!received) {
            continue;
        }

        ++packets_received_;

        const int fp_index =
            selectFP(job.tuple);

        fp_queues_[fp_index]->push(
            std::move(job)
        );

        ++packets_dispatched_;
        ++per_fp_counts_[fp_index];
    }
}

int LoadBalancer::selectFP(
    const FiveTuple& tuple
) const {
    if (num_fps_ <= 0) {
        return 0;
    }

    FiveTupleHash hasher;

    const size_t hash =
        hasher(tuple);

    return static_cast<int>(
        hash %
        static_cast<size_t>(num_fps_)
    );
}

LoadBalancer::LBStats
LoadBalancer::getStats() const {
    LBStats stats;

    stats.packets_received =
        packets_received_.load();

    stats.packets_dispatched =
        packets_dispatched_.load();

    stats.per_fp_packets =
        per_fp_counts_;

    return stats;
}

// ============================================================================
// LBManager
// ============================================================================

LBManager::LBManager(
    int num_lbs,
    int fps_per_lb,
    std::vector<ThreadSafeQueue<PacketJob>*> fp_queues
)
    : fps_per_lb_(fps_per_lb) {

    if (num_lbs <= 0) {
        throw std::invalid_argument(
            "num_lbs must be greater than zero"
        );
    }

    if (fps_per_lb <= 0) {
        throw std::invalid_argument(
            "fps_per_lb must be greater than zero"
        );
    }

    const size_t required_fps =
        static_cast<size_t>(
            num_lbs * fps_per_lb
        );

    if (fp_queues.size() < required_fps) {
        throw std::invalid_argument(
            "Not enough FP queues for requested LB configuration"
        );
    }

    for (int lb_id = 0;
         lb_id < num_lbs;
         ++lb_id) {

        std::vector<
            ThreadSafeQueue<PacketJob>*
        > lb_fp_queues;

        const int fp_start =
            lb_id * fps_per_lb_;

        for (int i = 0;
             i < fps_per_lb_;
             ++i) {

            lb_fp_queues.push_back(
                fp_queues[
                    fp_start + i
                ]
            );
        }

        lbs_.push_back(
            std::make_unique<LoadBalancer>(
                lb_id,
                std::move(lb_fp_queues),
                fp_start
            )
        );
    }

    std::cout
        << "[LBManager] Created "
        << num_lbs
        << " load balancers, "
        << fps_per_lb
        << " FPs each\n";
}

LBManager::~LBManager() {
    stopAll();
}

void LBManager::startAll() {
    for (auto& lb : lbs_) {
        lb->start();
    }
}

void LBManager::stopAll() {
    for (auto& lb : lbs_) {
        lb->stop();
    }
}

LoadBalancer& LBManager::getLBForPacket(
    const FiveTuple& tuple
) {
    if (lbs_.empty()) {
        throw std::runtime_error(
            "LBManager contains no load balancers"
        );
    }

    FiveTupleHash hasher;

    const size_t hash =
        hasher(tuple);

    const size_t lb_index =
        hash % lbs_.size();

    return *lbs_[lb_index];
}

LBManager::AggregatedStats
LBManager::getAggregatedStats() const {
    AggregatedStats stats;

    for (const auto& lb : lbs_) {
        const auto lb_stats =
            lb->getStats();

        stats.total_received +=
            lb_stats.packets_received;

        stats.total_dispatched +=
            lb_stats.packets_dispatched;
    }

    return stats;
}

} // namespace DPI