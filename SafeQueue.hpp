#ifndef SAFEQUEUE_HPP
#define SAFEQUEUE_HPP

// Based on http://stackoverflow.com/questions/15278343/c11-thread-safe-queue

#include <queue>
#include <mutex>
#include <condition_variable>

template <class T>
class SafeQueue
{
public:
	void enqueue(T&& t) {
		std::lock_guard<std::mutex> lock(m);
		q.push(std::move(t));
		c.notify_one();
	}
	bool enqueue_if_below_max(T&& t, size_t max) {
		std::lock_guard<std::mutex> lock(m);
		if (!q.empty() && q.size() >= max)
			return false;
		q.push(std::move(t));
		c.notify_one();
		return true;
	}

	T dequeue(void) {
		std::unique_lock<std::mutex> lock(m);
		while(q.empty())
			c.wait(lock);
		T val;
		std::swap(q.front(), val);
		q.pop();
		return val;
	}

private:
	std::queue<T> q;
	mutable std::mutex m;
	std::condition_variable c;
};

#endif // SAVEQUEUE_HPP
