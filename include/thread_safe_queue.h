#ifndef THREAD_SAFE_QUEUE_H
#define THREAD_SAFE_QUEUE_H

#include <condition_variable>
#include <cstddef>
#include <mutex>
#include <queue>
#include <chrono>

namespace DPI {

template <typename T>
class ThreadSafeQueue {
public:
    explicit ThreadSafeQueue(size_t max_size = 10000)
        : max_size_(max_size),
          shutdown_(false) {
    }

    ~ThreadSafeQueue() {
        shutdown();
    }

    void push(const T& item) {
        std::unique_lock<std::mutex> lock(mutex_);

        not_full_.wait(lock, [this]() {
            return queue_.size() < max_size_ || shutdown_;
        });

        if (shutdown_) {
            return;
        }

        queue_.push(item);

        not_empty_.notify_one();
    }

    bool pop(T& item) {
        std::unique_lock<std::mutex> lock(mutex_);

        not_empty_.wait(lock, [this]() {
            return !queue_.empty() || shutdown_;
        });

        if (queue_.empty()) {
            return false;
        }

        item = std::move(queue_.front());
        queue_.pop();

        not_full_.notify_one();

        return true;
    }

    bool tryPop(
        T& item,
        std::chrono::milliseconds timeout
    ) {
        std::unique_lock<std::mutex> lock(mutex_);

        if (!not_empty_.wait_for(
                lock,
                timeout,
                [this]() {
                    return !queue_.empty() || shutdown_;
                })) {
            return false;
        }

        if (queue_.empty()) {
            return false;
        }

        item = std::move(queue_.front());
        queue_.pop();

        not_full_.notify_one();

        return true;
    }

    void shutdown() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            shutdown_ = true;
        }

        not_empty_.notify_all();
        not_full_.notify_all();
    }

    size_t size() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.size();
    }

    bool empty() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.empty();
    }

private:
    std::queue<T> queue_;

    size_t max_size_;

    mutable std::mutex mutex_;

    std::condition_variable not_empty_;
    std::condition_variable not_full_;

    bool shutdown_;
};

} // namespace DPI

#endif // THREAD_SAFE_QUEUE_H