#pragma once

#include <event2/event.h>

#include <atomic>
#include <cstdint>
#include <future>
#include <memory>
#include <thread>

#include "context.hpp"
#include "crypto.hpp"
#include "utils.hpp"

namespace oxen::quic
{
    class Endpoint;

    class Network
    {
        using Job = std::function<void()>;

      public:
        Network(std::shared_ptr<::event_base> loop_ptr, std::thread::id loop_thread_id);
        Network();
        ~Network();

        template <typename... Opt>
        std::shared_ptr<Endpoint> endpoint(const Address& local_addr, Opt&&... opts)
        {
            auto [it, added] =
                    endpoint_map.emplace(std::make_shared<Endpoint>(*this, local_addr, std::forward<Opt>(opts)...));

            return *it;
        }

        void set_shutdown_immediate(bool b = true) { shutdown_immediate = b; }

        // Returns a pointer deleter that defers the actual destruction call to this network
        // object's event loop.
        template <typename T>
        auto network_deleter()
        {
            return [this](T* ptr) { call([ptr] { delete ptr; }); };
        }

        // Similar in concept to std::make_shared<T>, but it creates the shared pointer with a
        // custom deleter that dispatches actual object destruction to the network's event loop for
        // thread safety.
        template <typename T, typename... Args>
        std::shared_ptr<T> make_shared(Args&&... args)
        {
            auto* ptr = new T{std::forward<Args>(args)...};
            return std::shared_ptr<T>{ptr, network_deleter<T>()};
        }

      private:
        std::atomic<bool> running{false};
        std::atomic<bool> shutdown_immediate{false};
        std::shared_ptr<::event_base> ev_loop;
        std::optional<std::thread> loop_thread;
        std::thread::id loop_thread_id;

        std::unordered_set<std::shared_ptr<Endpoint>> endpoint_map;

        event_ptr job_waker;
        std::queue<Job> job_queue;
        std::mutex job_queue_mutex;

        friend class Endpoint;
        friend class Connection;
        friend class Stream;

        const std::shared_ptr<::event_base>& loop() const { return ev_loop; }

        void setup_job_waker();

        bool in_event_loop() const;

        /// Posts a function to the event loop, to be called when the event loop is next free.
        void call_soon(std::function<void()> f);

        /// Calls a function: if this is called from within the event loop thread, the function is
        /// called immediately; otherwise it is forwarded to `call_soon`.
        template <typename Callable>
        void call(Callable&& f)
        {
            if (in_event_loop())
                f();
            else
                call_soon(std::forward<Callable>(f));
        }

        /// Calls a function and synchronously obtains its return value.  If called from within the
        /// event loop, the function is called and returned immediately, otherwise a promise/future
        /// is used with `call_soon` to block until the event loop comes around and calls the
        /// function.
        template <typename Callable, typename Ret = decltype(std::declval<Callable>()())>
        Ret call_get(Callable&& f)
        {
            if (in_event_loop())
                return f();

            std::promise<Ret> prom;
            auto fut = prom.get_future();
            call_soon([&f, &prom] {
                try
                {
                    if constexpr (!std::is_void_v<Ret>)
                        prom.set_value(f());
                    else
                    {
                        f();
                        prom.set_value();
                    }
                }
                catch (...)
                {
                    prom.set_exception(std::current_exception());
                }
            });
            return fut.get();
        }

        void process_job_queue();

        void close_gracefully();

        void close_immediate();
    };
}  // namespace oxen::quic
