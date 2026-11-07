#pragma once

#include <condition_variable>
#include <functional>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>

namespace mftscan {

class ThreadPool {
public:
    explicit ThreadPool(size_t num_threads = 0);
    ~ThreadPool();

    ThreadPool(const ThreadPool&) = delete;
    ThreadPool& operator=(const ThreadPool&) = delete;

    void enqueue(std::function<void()> task);
    void wait_idle();

    size_t thread_count() const noexcept { return threads_.size(); }

private:
    std::vector<std::jthread> threads_;
    std::queue<std::function<void()>> tasks_;
    std::mutex queue_mutex_;
    std::condition_variable cv_task_;
    std::condition_variable cv_idle_;
    size_t active_tasks_{0};
    bool stop_{false};

    void worker_loop();
};

} // namespace mftscan