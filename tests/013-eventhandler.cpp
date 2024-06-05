#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers.hpp>
#include <future>
#include <oxen/quic.hpp>
#include <oxen/quic/gnutls_crypto.hpp>
#include <thread>

#include "utils.hpp"

namespace oxen::quic::test
{
    struct lifetime : public std::enable_shared_from_this<lifetime>
    {};

    TEST_CASE("013 - EventHandler event repeater: calling object lifetime bound", "[013][repeater][caller]")
    {
        Network test_net{};
        const int NUM_ITERATIONS{10};
        constexpr auto msg = "hello from the other siiiii-iiiiide"_bsv;

        std::promise<bool> d_promise;
        std::future<bool> d_future = d_promise.get_future();

        std::atomic<int> recv_counter{}, send_counter{};

        stream_data_callback server_data_cb = [&](Stream&, bstring_view) { recv_counter += 1; };

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        Address server_local{};
        Address client_local{};

        auto server_endpoint = test_net.endpoint(server_local);
        REQUIRE_NOTHROW(server_endpoint->listen(server_tls, server_data_cb));

        RemoteAddress client_remote{defaults::SERVER_PUBKEY, "127.0.0.1"s, server_endpoint->local().port()};

        auto client_endpoint = test_net.endpoint(client_local);
        auto conn_interface = client_endpoint->connect(client_remote, client_tls);

        // client make stream and send; message displayed by server_data_cb
        auto client_stream = conn_interface->open_stream();

        auto life = std::make_shared<lifetime>();

        test_net.call_every(10ms, life->weak_from_this(), [&]() {
            if (send_counter <= NUM_ITERATIONS)
            {
                ++send_counter;
                client_stream->send(msg);
            }
            else
                life.reset();
        });

        test_net.call_later(1s, [&]() {
            REQUIRE(recv_counter == send_counter);
            REQUIRE(!life);
            d_promise.set_value(true);
        });

        require_future(d_future, 5s);
    }

    TEST_CASE("013 - EventHandler event repeater: EventHandler managed lifetime", "[013][repeater][managed]")
    {
        Network test_net{};
        const int NUM_ITERATIONS{10};
        constexpr auto msg = "hello from the other siiiii-iiiiide"_bsv;

        std::promise<bool> prom_a, prom_b;
        std::future<bool> fut_a = prom_a.get_future(), fut_b = prom_b.get_future();

        std::atomic<int> recv_counter{}, send_counter{};
        std::atomic<bool> have_paused_handler{false};

        std::shared_ptr<EventHandler> handler;

        stream_data_callback server_data_cb = [&](Stream&, bstring_view) {
            recv_counter += 1;
            if (recv_counter == NUM_ITERATIONS)
            {
                if (not have_paused_handler)
                {
                    handler->pause();
                    have_paused_handler = true;
                }
                else
                {
                    handler->stop();
                }
            }
        };

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        Address server_local{};
        Address client_local{};

        auto server_endpoint = test_net.endpoint(server_local);
        REQUIRE_NOTHROW(server_endpoint->listen(server_tls, server_data_cb));

        RemoteAddress client_remote{defaults::SERVER_PUBKEY, "127.0.0.1"s, server_endpoint->local().port()};

        auto client_endpoint = test_net.endpoint(client_local);
        auto conn_interface = client_endpoint->connect(client_remote, client_tls);

        // client make stream and send; message displayed by server_data_cb
        auto client_stream = conn_interface->open_stream();

        handler = test_net.call_every(10ms, [&]() {
            if (send_counter <= NUM_ITERATIONS)
            {
                send_counter += 1;
                client_stream->send(msg);
            }
        });

        test_net.call_later(1s, [&]() {
            REQUIRE(recv_counter == send_counter);
            prom_a.set_value(true);
        });

        require_future(fut_a, 5s);

        REQUIRE(handler->is_paused());
        REQUIRE_FALSE(handler->is_stopped());
        REQUIRE_FALSE(handler->is_running());

        recv_counter = 0;
        send_counter = 0;

        REQUIRE(handler->start());

        test_net.call_later(1s, [&]() {
            REQUIRE(recv_counter == send_counter);
            prom_b.set_value(true);
        });

        require_future(fut_b, 5s);

        REQUIRE(handler->is_stopped());
        REQUIRE_FALSE(handler->is_running());
        REQUIRE_FALSE(handler->is_paused());
    }
}  //  namespace oxen::quic::test
