#include "connection.hpp"
#include "gnutls_crypto.hpp"

namespace oxen::quic
{
    extern "C"
    {
        //  Called by the client if a certificate is requested of them by the server. This will require the client to set a
        //  key retrieve function using set_key_retrieve(...).
        //
        //  Parameters:
        //      - req_ca_rdn: contains a list with the CA names that the server considers trusted (only used in X.509
        //        certificates)
        //      - pk_algos: contains a list with server’s acceptable public key algorithms
        //      - pcert: should contain a single certificate and public key or a list of them
        //      - privkey: is the private key
        //
        //  "The callback function should set the certificate list to be sent, and return 0 on success. If no certificate was
        //  selected then the number of certificates should be set to zero. The value (-1) indicates error and the handshake
        //  will be terminated. If both certificates are set in the credentials and a callback is available, the callback
        //  takes predence."
        //  https://www.gnutls.org/manual/html_node/Abstract-key-API.html#gnutls_005fcertificate_005fset_005fretrieve_005ffunction2
        //
        int cert_retrieve_callback_gnutls(
                gnutls_session_t session,
                const gnutls_datum_t* /* req_ca_rdn */,
                int /* nreqs */,
                const gnutls_pk_algorithm_t* /* pk_algos */,
                int /* pk_algos_length */,
                gnutls_pcert_st** pcert,
                unsigned int* pcert_length,
                gnutls_privkey_t* privkey)
        {
            log::warning(log_cat, "{} called", __PRETTY_FUNCTION__);
            auto* conn = get_connection_from_gnutls(session);

            log::critical(
                    log_cat,
                    "[CERT RETRIEVE CB] Local ({}) cert type:{} \t Peer expecting cert type:{}",
                    conn->is_outbound() ? "CLIENT" : "SERVER",
                    get_cert_type(session, GNUTLS_CTYPE_OURS),
                    get_cert_type(session, GNUTLS_CTYPE_PEERS));

            // Servers do not retrieve! We should NOT be here
            assert(conn->is_outbound());

            GNUTLSSession* tls_session = dynamic_cast<GNUTLSSession*>(conn->get_session());
            assert(tls_session);

            auto& creds = tls_session->creds;
            log::critical(
                    log_cat,
                    "{} providing type:{}",
                    conn->is_outbound() ? "CLIENT" : "SERVER",
                    translate_cert_type(creds.pcrt.type));

            *pcert_length = 1;
            *pcert = const_cast<gnutls_pcert_st*>(&creds.pcrt);
            *privkey = creds.pkey;

            conn->set_validated();

            return 0;
        }

        // Return value: 0 is pass, negative is fail
        int cert_verify_callback_gnutls(gnutls_session_t session)
        {
            log::warning(log_cat, "{} called", __PRETTY_FUNCTION__);
            auto* conn = get_connection_from_gnutls(session);

            // Clients do not verify! We should NOT be here
            // assert(conn->is_inbound());

            GNUTLSSession* tls_session = dynamic_cast<GNUTLSSession*>(conn->get_session());
            assert(tls_session);

            //  1: Client provided a valid cert, connection accepted and marked validated
            //  0: Client did not provide a cert, connection accepted but not marked validated
            //  -1: Client provided an invalid cert, connection rejected
            auto rv = tls_session->validate_remote_key();

            if (rv < 0)
                return -1;

            if (rv > 0)
                conn->set_validated();

            return 0;
        }
    }

    GNUTLSCreds::GNUTLSCreds(std::string local_key, std::string local_cert, std::string remote_cert, std::string ca_arg)
    {
        if (local_key.empty() || local_cert.empty())
            throw std::runtime_error{
                    "Must initialize GNUTLS credentials using local private key and certificate at minimum"};

        x509_loader lkey{local_key}, lcert{local_cert}, rcert, ca;

        if (not remote_cert.empty())
            rcert = {remote_cert};

        if (not ca_arg.empty())
            ca = {ca};

        if (auto rv = gnutls_certificate_allocate_credentials(&cred); rv < 0)
        {
            log::warning(log_cat, "gnutls_certificate_allocate_credentials failed: {}", gnutls_strerror(rv));
            throw std::runtime_error("gnutls credential allocation failed");
        }

        if (ca)
        {
            if (auto rv = (ca.from_mem()) ? gnutls_certificate_set_x509_trust_mem(cred, ca, ca.format)
                                          : gnutls_certificate_set_x509_trust_file(cred, ca, ca.format);
                rv < 0)
            {
                log::warning(log_cat, "Set x509 trust failed with code {}", gnutls_strerror(rv));
                throw std::invalid_argument("gnutls didn't like a specified trust file/memblock");
            }
        }

        if (auto rv = (lcert.from_mem()) ? gnutls_certificate_set_x509_key_mem(cred, lcert, lkey, lkey.format)
                                         : gnutls_certificate_set_x509_key_file(cred, lcert, lkey, lkey.format);
            rv < 0)
        {
            log::warning(log_cat, "Set x509 key failed with code {}", gnutls_strerror(rv));
            throw std::invalid_argument("gnutls didn't like a specified key file/memblock");
        }

        log::info(log_cat, "Completed credential initialization");
    }

    void GNUTLSCreds::load_keys(x509_loader& s, x509_loader& pk)
    {
        log::warning(log_cat, "{} called", __PRETTY_FUNCTION__);
        int rv = 0;
        // if (rv = gnutls_pcert_import_x509_raw(&pcrt, &pk.mem, pk.format, 0); rv != 0)
        if (rv = gnutls_pcert_import_rawpk_raw(&pcrt, &pk.mem, pk.format, 0, 0); rv != 0)
            log::critical(log_cat, "Pcert import failed!");
        log::critical(log_cat, "(original) pcrt.type:{}", translate_cert_type(pcrt.type));
        // pcrt.type = GNUTLS_CRT_X509;
        log::critical(log_cat, "(after set) pcrt.type:{}", translate_cert_type(pcrt.type));

        if (rv |= gnutls_privkey_init(&pkey); rv != 0)
            log::critical(log_cat, "Privkey init failed!");
        if (rv |= gnutls_privkey_import_x509_raw(pkey, &s.mem, s.format, NULL, 0); rv != 0)
            log::critical(log_cat, "Privkey import failed!");
        log::warning(log_cat, "Exiting {}", __PRETTY_FUNCTION__);
    }

    GNUTLSCreds::GNUTLSCreds(std::string ed_seed, std::string ed_pubkey) : using_raw_pk{true}
    {
        log::trace(log_cat, "Initializing GNUTLSCreds from Ed25519 keypair");

        constexpr auto pem_fmt = "-----BEGIN {0} KEY-----\n{1}\n-----END {0} KEY-----\n"sv;

        auto seed = x509_loader{fmt::format(pem_fmt, "PRIVATE", oxenc::to_base64(ASN_ED25519_SEED_PREFIX + ed_seed))};

        auto pubkey = x509_loader{fmt::format(pem_fmt, "PUBLIC", oxenc::to_base64(ASN_ED25519_PUBKEY_PREFIX + ed_pubkey))};

        assert(seed.from_mem() && pubkey.from_mem());
        assert(seed.format == pubkey.format);

        log::critical(log_cat, "Seed and pubkey format: {}", translate_key_format(pubkey.format));

        // LOAD KEYS HERE
        load_keys(seed, pubkey);

        if (auto rv = gnutls_certificate_allocate_credentials(&cred); rv < 0)
        {
            log::warning(log_cat, "gnutls_certificate_allocate_credentials failed: {}", gnutls_strerror(rv));
            throw std::runtime_error("gnutls credential allocation failed");
        }

        [[maybe_unused]] constexpr auto usage_flags = GNUTLS_KEY_DIGITAL_SIGNATURE | GNUTLS_KEY_NON_REPUDIATION |
                                                      GNUTLS_KEY_KEY_ENCIPHERMENT | GNUTLS_KEY_DATA_ENCIPHERMENT |
                                                      GNUTLS_KEY_KEY_AGREEMENT | GNUTLS_KEY_KEY_CERT_SIGN;

        if (auto rv = gnutls_certificate_set_key(cred, NULL, 0, &pcrt, 1, pkey); rv < 0)
        // if (auto rv = gnutls_certificate_set_rawpk_key_mem(
        //             cred, pubkey, seed, seed.format, nullptr, usage_flags, nullptr, 0, 0);
        //     rv < 0)
        {
            log::warning(log_cat, "gnutls import of raw Ed keys failed: {}", gnutls_strerror(rv));
            throw std::runtime_error("gnutls import of raw Ed keys failed");
        }

        // clang format keeps changing this arbitrarily, so disable for this line
        // clang-format off
        constexpr auto* priority = "NORMAL:+ECDHE-PSK:+PSK:+ECDHE-ECDSA:+AES-128-CCM-8:+CTYPE-CLI-ALL:+CTYPE-SRV-ALL:+SHA256";
        // clang-format on

        const char* err{nullptr};
        if (auto rv = gnutls_priority_init(&priority_cache, priority, &err); rv < 0)
        {
            if (rv == GNUTLS_E_INVALID_REQUEST)
                log::error(log_cat, "gnutls_priority_init error: {}", err);
            else
                log::error(log_cat, "gnutls_priority_init error: {}", gnutls_strerror(rv));

            throw std::runtime_error("gnutls key exchange algorithm priority setup failed");
        }

        // NOTE: the original place this was called
        // gnutls_certificate_set_verify_function(cred, cert_verify_callback_gnutls);
    }

    GNUTLSCreds::~GNUTLSCreds()
    {
        log::info(log_cat, "Entered {}", __PRETTY_FUNCTION__);
        gnutls_certificate_free_credentials(cred);
    }

    std::shared_ptr<GNUTLSCreds> GNUTLSCreds::make(
            std::string remote_key, std::string remote_cert, std::string local_cert, std::string ca)
    {
        // would use make_shared, but I want GNUTLSCreds' constructor to be private
        std::shared_ptr<GNUTLSCreds> p{new GNUTLSCreds(remote_key, remote_cert, local_cert, ca)};
        return p;
    }

    std::shared_ptr<GNUTLSCreds> GNUTLSCreds::make_from_ed_keys(std::string seed, std::string pubkey)
    {
        // would use make_shared, but I want GNUTLSCreds' constructor to be private
        std::shared_ptr<GNUTLSCreds> p{new GNUTLSCreds(seed, pubkey)};
        return p;
    }

    std::shared_ptr<GNUTLSCreds> GNUTLSCreds::make_from_ed_seckey(std::string sk)
    {
        if (sk.size() != GNUTLS_SECRET_KEY_SIZE)
            throw std::invalid_argument("Ed25519 secret key is invalid length!");

        auto pk = sk.substr(GNUTLS_KEY_SIZE);
        sk = sk.substr(0, GNUTLS_KEY_SIZE);

        std::shared_ptr<GNUTLSCreds> p{new GNUTLSCreds(std::move(sk), std::move(pk))};
        return p;
    }

    std::unique_ptr<TLSSession> GNUTLSCreds::make_session(bool is_client, const std::vector<std::string>& alpns)
    {
        // NOTE: I put this here (rather than just the raw_pk constructor) to test the server requesting certs every time,
        // but not requiring them. By doing the check here, we can ensure that requesting is only done by servers, while
        // retrieval is only done by clients
        if (using_raw_pk)
        {
            // if (is_client)
            //     gnutls_certificate_set_retrieve_function2(cred, cert_retrieve_callback_gnutls);
            // else
            gnutls_certificate_set_verify_function(cred, cert_verify_callback_gnutls);
        }

        return std::make_unique<GNUTLSSession>(*this, is_client, alpns);
    }

    void GNUTLSCreds::set_client_tls_hook(gnutls_callback func, unsigned int htype, unsigned int when, unsigned int incoming)
    {
        client_tls_hook.cb = std::move(func);
        client_tls_hook.htype = htype;
        client_tls_hook.when = when;
        client_tls_hook.incoming = incoming;
    }

    void GNUTLSCreds::set_server_tls_hook(gnutls_callback func, unsigned int htype, unsigned int when, unsigned int incoming)
    {
        server_tls_hook.cb = std::move(func);
        server_tls_hook.htype = htype;
        server_tls_hook.when = when;
        server_tls_hook.incoming = incoming;
    }

}  // namespace oxen::quic
