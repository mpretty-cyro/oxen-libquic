/*
    Test server binary
*/

#include <gnutls/gnutls.h>
#include <oxenc/endian.h>
#include <oxenc/hex.h>

#include <CLI/Validators.hpp>
#include <future>
#include <quic.hpp>
#include <quic/gnutls_crypto.hpp>
#include <thread>

#include "quic/connection.hpp"
#include "utils.hpp"

using namespace oxen::quic;

int main(int argc, char* argv[])
{
    CLI::App cli{"libQUIC test server"};

    std::string server_addr = "127.0.0.1:5500";

    cli.add_option("--listen", server_addr, "Server address to listen on")->type_name("IP:PORT")->capture_default_str();

    std::string log_file, log_level;
    add_log_opts(cli, log_file, log_level);

    std::string key{"./serverkey.pem"}, cert{"./servercert.pem"};

    cli.add_option("-c,--certificate", cert, "Path to server certificate to use")
            ->type_name("FILE")
            ->capture_default_str()
            ->check(CLI::ExistingFile);
    cli.add_option("-k,--key", key, "Path to server key to use")
            ->type_name("FILE")
            ->capture_default_str()
            ->check(CLI::ExistingFile);

    // optional
    std::string client_cert{"./clientcert.pem"};
    cli.add_option("-C,--clientcert", key, "Path to client certificate for client authentication")
            ->type_name("FILE")
            ->capture_default_str()
            ->check(CLI::ExistingFile);

    try
    {
        cli.parse(argc, argv);
    }
    catch (const CLI::ParseError& e)
    {
        return cli.exit(e);
    }

    setup_logging(log_file, log_level);

    Network server_net{};

    auto server_tls = GNUTLSCreds::make(key, cert, client_cert);

    auto [listen_addr, listen_port] = parse_addr(server_addr, 5500);
    opt::local_addr server_local{listen_addr, listen_port};

    stream_open_callback stream_opened = [&](Stream& s) {
        log::warning(test_cat, "Stream {} opened!", s.stream_id());
        return 0;
    };

    struct recv_info
    {
        uint64_t n_expected = 0;
        uint64_t n_received = 0;
    };

    recv_info dgram_data;

    std::promise<void> t_prom;
    std::future<void> t_fut = t_prom.get_future();

    std::shared_ptr<Endpoint> server;

    gnutls_callback outbound_tls_cb =
            [&](gnutls_session_t, unsigned int, unsigned int, unsigned int, const gnutls_datum_t*) {
                log::debug(test_cat, "Calling server TLS callback... handshake completed...");
                return 0;
            };

    server_tls->set_server_tls_hook(outbound_tls_cb);

    dgram_data_callback recv_dgram_cb = [&](dgram_interface& di, bstring_view data) {
        if (dgram_data.n_expected == 0)
        {
            // The very first packet should be 8 bytes containing the uint64_t count of total
            // packets being sent, not including this initial one.
            if (data.size() != 8)
                log::error(test_cat, "Invalid initial packet: expected 8-byte test size, got {} bytes", data.size());
            auto count = oxenc::load_little_to_host<uint64_t>(data.data());
            dgram_data.n_expected = count;
            log::warning(
                    test_cat,
                    "First data from new connection datagram channel, expecting {} datagrams!",
                    dgram_data.n_expected);
            return;
        }

        // Subsequent packets start with a \x00 until the final one; that has first byte set to \x01.
        const bool done = data[0] != std::byte{0};

        auto& info = dgram_data;
        bool need_more = info.n_received < info.n_expected;
        info.n_received += 1;

        if (info.n_received > info.n_expected)
        {
            log::critical(test_cat, "Received too many datagrams ({} > {})!", info.n_received, info.n_expected);

            if (!need_more)
                return;
        }

        if (done)
        {
            auto reception_rate = ((float)info.n_received / (float)info.n_expected) * 100;

            log::critical(
                    test_cat,
                    "Datagram test complete. Fidelity: {}\% ({} received of {} expected)",
                    reception_rate,
                    info.n_received,
                    info.n_expected);

            di.reply("DONE!"sv);
            t_prom.set_value();
        }
    };

    log::critical(test_cat, "Calling 'server_listen'...");
    auto split_dgram = opt::enable_datagrams(Splitting::ACTIVE);
    // opt::enable_datagrams split_dgram(Splitting::ACTIVE);
    server = server_net.endpoint(server_local, recv_dgram_cb, split_dgram);
    server->listen(server_tls, stream_opened);

    t_fut.get();

    log::warning(test_cat, "Shutting down test server");
}
