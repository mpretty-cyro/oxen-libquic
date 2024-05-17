#include "ip.hpp"

#include <bit>

#include "internal.hpp"

namespace oxen::quic
{
    const std::string ipv4::to_string() const
    {
        uint32_t net = oxenc::load_host_to_big<uint32_t>(&addr);
        char buf[INET_ADDRSTRLEN] = {};
        inet_ntop(AF_INET, &net, buf, sizeof(buf));

        return "{}"_format(buf);
    }

    ipv4 ipv4_net::max_ip()
    {
        auto b = base.to_base(mask);

        if (mask < 32)
            b.addr |= (1 << (32 - mask)) - 1;

        return b;
    }

    in6_addr ipv6::to_in6() const
    {
        in6_addr ret;

        oxenc::write_host_as_big(hi, &ret.s6_addr[0]);
        oxenc::write_host_as_big(lo, &ret.s6_addr[8]);

        return ret;
    }

    const std::string ipv6::to_string() const
    {
        char buf[INET6_ADDRSTRLEN] = {};

        std::array<uint8_t, 16> addr;
        oxenc::write_host_as_big(hi, &addr[0]);
        oxenc::write_host_as_big(lo, &addr[8]);

        inet_ntop(AF_INET6, &addr, buf, sizeof(buf));

        return "{}"_format(buf);
    }

    ipv6 ipv6_net::max_ip()
    {
        auto b = base.to_base(mask);

        if (mask > 64)
        {
            b.hi = base.hi;
            b.lo |= (1 << (128 - mask)) - 1;
        }
        else
        {
            b.hi |= (1 << (64 - mask)) - 1;
            b.lo = ~uint64_t{0};
        }

        return b;
    }

}  //  namespace oxen::quic
