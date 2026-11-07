#include "mftscan/thread_pool.hpp"

namespace mftscan {

ThreadPool::ThreadPool(size_t num_threads) {
    if (num_threads == 0) {
        num_threads = std::thread::hardware_concurrency();
        if (num_threads == 0) {
            num_threads = 4;
        }
    }

    threads_.reserve(num_threads);
    for (size_t i = 0; i < num_threads; ++i) {
        threads_.emplace_back([this]() {
            worker_loop();
        });
    }
}

ThreadPool::~ThreadPool() {
    {
        std::unique_lock<std::mutex> lock(queue_mutex_);
        stop_ = true;
    }
    cv_task_.notify_all();
    // std::jthread handles joining automatically
}

void ThreadPool::enqueue(std::function<void()> task) {
    {
        std::unique_lock<std::mutex> lock(queue_mutex_);
        if (stop_) {
            return;
        }
        tasks_.push(std::move(task));
        active_tasks_++;
    }
    cv_task_.notify_one();
}

void ThreadPool::wait_idle() {
    std::unique_lock<std::mutex> lock(queue_mutex_);
    cv_idle_.wait(lock, [this]() {
        return tasks_.empty() && (active_tasks_ == 0);
    });
}

void ThreadPool::worker_loop() {
    while (true) {
        std::function<void()> task;
        {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            cv_task_.wait(lock, [this]() {
                return stop_ || !tasks_.empty();
            });

            if (stop_ && tasks_.empty()) {
                return;
            }

            task = std::move(tasks_.front());
            tasks_.pop();
        }

        task();

        {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            active_tasks_--;
            if (tasks_.empty() && active_tasks_ == 0) {
                cv_idle_.notify_all();
            }
        }
    }
}

} // namespace mftscan