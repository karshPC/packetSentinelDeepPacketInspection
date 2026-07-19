#include "thread_safe_queue.h"

#include <chrono>
#include <iostream>
#include <thread>

int main() {
    DPI::ThreadSafeQueue<int> queue(2);

    queue.push(10);
    queue.push(20);

    std::cout << "Initial queue size: "
              << queue.size()
              << '\n';

    int value = 0;

    if (queue.tryPop(
            value,
            std::chrono::milliseconds(100))) {

        std::cout << "Popped: "
                  << value
                  << '\n';
    } else {
        std::cerr << "Failed to pop first value\n";
        return 1;
    }

    if (queue.tryPop(
            value,
            std::chrono::milliseconds(100))) {

        std::cout << "Popped: "
                  << value
                  << '\n';
    } else {
        std::cerr << "Failed to pop second value\n";
        return 1;
    }

    if (!queue.empty()) {
        std::cerr << "Queue should be empty\n";
        return 1;
    }

    std::thread producer([&queue]() {
        std::this_thread::sleep_for(
            std::chrono::milliseconds(100)
        );

        queue.push(42);
    });

    if (!queue.pop(value)) {
        std::cerr << "Blocking pop failed\n";

        producer.join();
        return 1;
    }

    producer.join();

    if (value != 42) {
        std::cerr << "Unexpected value: "
                  << value
                  << '\n';

        return 1;
    }

    queue.shutdown();

    if (queue.pop(value)) {
        std::cerr << "Pop should fail after shutdown\n";
        return 1;
    }

    std::cout << "Thread-safe queue test passed\n";

    return 0;
}