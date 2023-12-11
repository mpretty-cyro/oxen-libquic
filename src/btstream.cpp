#include "btstream.hpp"

#include <stdexcept>

namespace oxen::quic
{
    message::message(BTRequestStream& bp, bstring req, bool is_error) :
            data{std::move(req)}, return_sender{bp.weak_from_this()}, cid{bp.conn_id()}, timed_out{is_error}
    {
        oxenc::bt_list_consumer btlc(data);

        req_type = btlc.consume_string_view();
        req_id = btlc.consume_integer<int64_t>();

        if (req_type == "C")
            ep = btlc.consume_string_view();
        else if (req_type == "E")
            is_error = true;

        req_body = btlc.consume_string_view();
    }

    static std::pair<size_t, size_t> get_sv_pos(const bstring& source, std::string_view view)
    {
        std::pair<size_t, size_t> result;
        auto& [off, len] = result;
        off = view.data() - reinterpret_cast<const char*>(source.data());
        len = view.size();
        return result;
    }
    static void fixup_view(bstring& new_source, std::string_view& new_view, std::pair<size_t, size_t> off_len)
    {
        new_view = {reinterpret_cast<const char*>(new_source.data()) + off_len.first, off_len.second};
    }

    message& message::operator=(message&& m)
    {
        if (this != &m)
        {
            req_id = m.req_id;
            return_sender = std::move(m.return_sender);
            cid = std::move(m.cid);
            auto type_pos = get_sv_pos(m.data, m.req_type);
            auto ep_pos = get_sv_pos(m.data, m.ep);
            auto body_pos = get_sv_pos(m.data, m.req_body);
            data = std::move(m.data);
            fixup_view(data, req_type, type_pos);
            fixup_view(data, ep, ep_pos);
            fixup_view(data, req_body, body_pos);
        }
        return *this;
    }

    message& message::operator=(const message& m)
    {
        if (this != &m)
        {
            req_id = m.req_id;
            return_sender = m.return_sender;
            cid = m.cid;
            auto type_pos = get_sv_pos(m.data, m.req_type);
            auto ep_pos = get_sv_pos(m.data, m.ep);
            auto body_pos = get_sv_pos(m.data, m.req_body);
            data = m.data;
            fixup_view(data, req_type, type_pos);
            fixup_view(data, ep, ep_pos);
            fixup_view(data, req_body, body_pos);
        }
        return *this;
    }

    message::message(message&& m)
    {
        *this = std::move(m);
    }

    message::message(const message& m)
    {
        *this = m;
    }

    void message::respond(bstring_view body, bool error)
    {
        log::trace(bp_cat, "{} called", __PRETTY_FUNCTION__);

        if (auto ptr = return_sender.lock())
            ptr->respond(req_id, body, error);
    }

    void BTRequestStream::respond(int64_t rid, bstring_view body, bool error)
    {
        log::trace(bp_cat, "{} called", __PRETTY_FUNCTION__);

        send(sent_request{*this, encode_response(rid, body, error), rid}.payload());
    }

    void BTRequestStream::check_timeouts()
    {
        const auto now = get_time();

        do
        {
            auto& f = sent_reqs.front();

            if (f->is_expired(now))
            {
                f->cb(std::move(*f).to_timeout());
                sent_reqs.pop_front();
            }
            else
                return;

        } while (not sent_reqs.empty());
    }

    void BTRequestStream::receive(bstring_view data)
    {
        log::trace(bp_cat, "bparser recv data callback called!");

        if (is_closing())
            return;

        try
        {
            process_incoming(to_sv(data));
        }
        catch (const std::exception& e)
        {
            log::error(bp_cat, "Exception caught: {}", e.what());
            close(BPARSER_ERROR_EXCEPTION);
        }
    }

    void BTRequestStream::closed(uint64_t app_code)
    {
        log::info(bp_cat, "bparser close callback called with {}", quic_strerror(app_code));
        close_callback(*this, app_code);
    }

    void BTRequestStream::register_command(std::string ep, std::function<void(message)> func)
    {
        endpoint.call([&]() { func_map[std::move(ep)] = std::move(func); });
    }

    void BTRequestStream::handle_input(message msg)
    {
        log::trace(bp_cat, "{} called to handle {} input", __PRETTY_FUNCTION__, msg.req_type);

        if (msg.req_type == "R" || msg.req_type == "E")
        {
            log::trace(log_cat, "Looking for request with req_id={}", msg.req_id);
            // Iterate using forward iterators, s.t. we go highest (newest) rids to lowest (oldest) rids.
            // As a result, our comparator checks if the sent request ID is greater thanthan the target rid
            auto itr = std::lower_bound(
                    sent_reqs.begin(),
                    sent_reqs.end(),
                    msg.req_id,
                    [](const std::shared_ptr<sent_request>& sr, int64_t rid) { return sr->req_id < rid; });

            if (itr != sent_reqs.end())
            {
                log::debug(bp_cat, "Successfully matched response to sent request!");
                itr->get()->cb(std::move(msg));
                sent_reqs.erase(itr);
                return;
            }
        }

        if (auto itr = func_map.find(msg.endpoint_str()); itr != func_map.end())
        {
            log::debug(bp_cat, "Executing request endpoint {}", msg.endpoint());
            itr->second(std::move(msg));
        }
    }

    void BTRequestStream::process_incoming(std::string_view req)
    {
        log::trace(bp_cat, "{} called", __PRETTY_FUNCTION__);

        while (not req.empty())
        {
            if (current_len == 0)
            {
                size_t consumed = 0;

                if (not size_buf.empty())
                {
                    size_t prev_len = size_buf.size();
                    size_buf += req.substr(0, MAX_REQ_LEN_ENCODED);

                    consumed = parse_length(size_buf);

                    if (consumed == 0)
                        return;

                    size_buf.clear();
                    req.remove_prefix(consumed - prev_len);
                }
                else
                {
                    consumed = parse_length(convert_sv<char>(req));
                    if (consumed == 0)
                    {
                        size_buf += req;
                        return;
                    }

                    req.remove_prefix(consumed);
                }
            }

            assert(current_len > 0);  // We shouldn't get out of the above without knowing this

            if (auto r_size = req.size() + buf.size(); r_size >= current_len)
            {
                // We have enough data for a complete request, so copy whatever we need to
                // complete the current request into buf and process it, leaving behind the
                // potential start of the next request:
                if (buf.size() < current_len)
                {
                    size_t need = current_len - buf.size();
                    buf += convert_sv<std::byte>(req.substr(0, need));
                    req.remove_prefix(need);
                }

                handle_input(message{*this, std::move(buf)});

                // Back to the top to try processing another request that might have arrived in
                // the same stream buffer
                current_len = 0;
                continue;
            }

            // Otherwise we don't have enough data on hand for a complete request, so move what we
            // got to the buffer to be processed when the next incoming chunk of data arrives.
            buf.reserve(current_len);
            buf += convert_sv<std::byte>(req);
            return;
        }
    }

    std::string BTRequestStream::encode_command(std::string_view endpoint, int64_t rid, bstring_view body)
    {
        oxenc::bt_list_producer btlp;

        btlp.append("C");
        btlp.append(rid);
        btlp.append(endpoint);
        btlp.append(body);

        return std::move(btlp).str();
    }

    std::string BTRequestStream::encode_response(int64_t rid, bstring_view body, bool error)
    {
        oxenc::bt_list_producer btlp;

        btlp.append(error ? "E" : "R");
        btlp.append(rid);
        btlp.append(body);

        return std::move(btlp).str();
    }

    /** Returns:
            0: length was incomplete
            >0: number of characters (including colon) parsed from front of req

        Error:
            throws on invalid value
    */
    size_t BTRequestStream::parse_length(std::string_view req)
    {
        auto pos = req.find_first_of(':');

        // request is incomplete with no readable request length
        if (pos == std::string_view::npos)
        {
            if (req.size() >= MAX_REQ_LEN_ENCODED)
                // we didn't find a valid length, but do have enough consumed for the maximum valid
                // length, so something is clearly wrong with this input.
                throw std::invalid_argument{"Invalid incoming request; invalid encoding or request too large"};

            return 0;
        }

        auto [ptr, ec] = std::from_chars(req.data(), req.data() + pos, current_len);

        const char* bad = nullptr;
        if (ec != std::errc())
            bad = "Invalid incoming request encoding!";
        else if (current_len == 0)
            bad = "Invalid empty bt request!";
        else if (current_len > MAX_REQ_LEN)
            bad = "Request exceeds maximum size!";

        if (bad)
        {
            close(BPARSER_ERROR_EXCEPTION);
            throw std::invalid_argument{bad};
        }

        return pos + 1;
    }
}  // namespace oxen::quic
