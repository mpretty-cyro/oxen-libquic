#pragma once

#include <array>

#include "formattable.hpp"
#include "utils.hpp"

namespace oxen::quic
{
    struct ipv4
    {
        // host order
        uint32_t addr;

        constexpr ipv4() = default;

        constexpr ipv4(uint32_t a) : addr{a} {}
        constexpr ipv4(uint8_t a, uint8_t b, uint8_t c, uint8_t d) :
                ipv4{uint32_t{a} << 24 | uint32_t{b} << 16 | uint32_t{c} << 8 | uint32_t{d}}
        {}

        constexpr std::optional<ipv4> next_ip() const
        {
            std::optional<ipv4> ret = std::nullopt;

            if (not increment_will_overflow(addr))
                ret = ipv4{addr + 1};

            return ret;
        }

        const std::string to_string() const;

        explicit operator in_addr() const
        {
            in_addr a;
            a.s_addr = oxenc::host_to_big(addr);
            return a;
        }

        constexpr auto operator<=>(const ipv4& a) const { return addr <=> a.addr; }

        constexpr bool operator==(const ipv4& a) const { return (addr <=> a.addr) == 0; }

        constexpr bool operator==(const in_addr& a) const { return (addr <=> a.s_addr) == 0; }

        constexpr ipv4 to_base(uint8_t mask) const { return mask < 32 ? ipv4{(addr >> (32 - mask)) << (32 - mask)} : *this; }
    };

    struct ipv4_net
    {
        ipv4 base;
        uint8_t mask;

        constexpr ipv4 max_ip() const
        {
            auto b = base.to_base(mask);

            if (mask < 32)
                b.addr |= (uint32_t{1} << (32 - mask)) - 1;

            return b;
        }

        constexpr ipv4_net() = default;

        constexpr ipv4_net(ipv4 b, uint8_t m) : base{b.to_base(m)}, mask{m} {}

        const std::string to_string() const;

        constexpr bool operator==(const ipv4_net& a) const { return std::tie(base, mask) == std::tie(a.base, a.mask); }

        constexpr bool contains(const ipv4& addr) const { return addr.to_base(mask) == base; }
    };

    inline constexpr ipv4_net operator/(const ipv4& a, uint8_t mask)
    {
        return ipv4_net{a.to_base(mask), mask};
    }

    struct ipv6
    {
      private:
        // Network order constructor using no length checking of any kind; as a result, it is a foot shotgun,
        // but a useful one for internal usage
        ipv6(const uint8_t* addr) :
                hi{oxenc::load_big_to_host<uint64_t>(addr)}, lo{oxenc::load_big_to_host<uint64_t>(addr + 8)}
        {}

      public:
        // Host order
        uint64_t hi, lo;

        constexpr ipv6() = default;

        constexpr std::optional<ipv6> next_ip() const
        {
            // If lo will not overflow, increment and return
            if (not increment_will_overflow(lo))
                return ipv6{{hi, lo + 1}};

            // If lo is INT_MAX, then:
            //  - if hi can be incremented, ++hi and set lo to all 0's
            //  - else, return nullopt
            if (not increment_will_overflow(hi))
                return ipv6{{hi + 1, uint64_t{0}}};

            return std::nullopt;
        }

        // Network order in6_addr constructor (calls private constructor)
        ipv6(const struct in6_addr* addr) : ipv6{addr->s6_addr} {}

        constexpr ipv6(std::pair<uint64_t, uint64_t> hilo) : hi{hilo.first}, lo{hilo.second} {}

        explicit constexpr ipv6(
                uint16_t a,
                uint16_t b = 0x0000,
                uint16_t c = 0x0000,
                uint16_t d = 0x0000,
                uint16_t e = 0x0000,
                uint16_t f = 0x0000,
                uint16_t g = 0x0000,
                uint16_t h = 0x0000) :
                hi{uint64_t{a} << 48 | uint64_t{b} << 32 | uint64_t{c} << 16 | uint64_t{d}},
                lo{uint64_t{e} << 48 | uint64_t{f} << 32 | uint64_t{g} << 16 | uint64_t{h}}
        {}

        in6_addr to_in6() const;

        const std::string to_string() const;

        constexpr auto operator<=>(const ipv6& a) const { return std::tie(hi, lo) <=> std::tie(a.hi, a.lo); }

        constexpr bool operator==(const ipv6& a) const { return (*this <=> a) == 0; }

        constexpr ipv6 to_base(uint8_t mask) const
        {
            ipv6 b;
            if (mask > 64)
            {
                b.hi = hi;
                b.lo = mask < 128 ? (lo >> (128 - mask)) << (128 - mask) : lo;
            }
            else
            {
                b.hi = (hi >> (64 - mask)) << (64 - mask);
                b.lo = uint64_t{0};
            }
            return b;
        }
    };

    struct ipv6_net
    {
        ipv6 base;
        uint8_t mask;

        constexpr ipv6 max_ip() const
        {
            auto b = base.to_base(mask);

            if (mask > 64)
            {
                b.hi = base.hi;
                b.lo |= (uint64_t{1} << (128 - mask)) - 1;
            }
            else
            {
                b.hi |= (uint64_t{1} << (64 - mask)) - 1;
                b.lo = ~uint64_t{0};
            }

            return b;
        }

        constexpr ipv6_net() = default;

        constexpr ipv6_net(ipv6 b, uint8_t m) : base{b.to_base(m)}, mask{m} {}

        const std::string to_string() const;

        constexpr bool operator==(const ipv6_net& a) const { return std::tie(base, mask) == std::tie(a.base, a.mask); }

        constexpr bool contains(const ipv6& addr) const { return addr.to_base(mask) == base; }
    };

    inline constexpr ipv6_net operator/(const ipv6& a, uint8_t mask)
    {
        return {a.to_base(mask), mask};
    }

    inline constexpr ipv4_net ipv4_loopback = ipv4(127, 0, 0, 1) / 8;
    inline constexpr ipv6 ipv6_loopback(0, 0, 0, 0, 0, 0, 0, 1);

    inline constexpr std::array ipv4_nonpublic = {
            ipv4(0, 0, 0, 0) / 8,        // Special purpose for current/local/this network
            ipv4(10, 0, 0, 0) / 8,       // Private range
            ipv4(100, 64, 0, 0) / 10,    // Carrier grade NAT private range
            ipv4_loopback,               // Loopback
            ipv4(169, 254, 0, 0) / 16,   // Link-local addresses
            ipv4(172, 16, 0, 0) / 12,    // Private range
            ipv4(192, 0, 0, 0) / 24,     // DS-Lite
            ipv4(192, 0, 2, 0) / 24,     // Test range 1 for docs/examples
            ipv4(192, 88, 99, 0) / 24,   // Reserved; deprecated IPv6-to-IPv4 relay
            ipv4(192, 168, 0, 0) / 16,   // Private range
            ipv4(198, 18, 0, 0) / 15,    // Multi-subnmet benchmark testing range
            ipv4(198, 51, 100, 0) / 24,  // Test range 2 for docs/examples
            ipv4(203, 0, 113, 0) / 24,   // Test range 3 for docs/examples
            ipv4(224, 0, 0, 0) / 4,      // Multicast
            ipv4(240, 0, 0, 0) / 4,      // Multicast
    };

    inline constexpr std::array ipv6_nonpublic = {
            ipv6() / 128,                      // unspecified addr
            ipv6_loopback / 128,               // loopback
            ipv6(0, 0, 0, 0, 0, 0xffff) / 96,  // IPv4-mapped address
            ipv6(0, 0, 0, 0, 0xffff) / 96,     // IPv4 translated addr
            ipv6(0x64, 0xff9b) / 96,           // IPv4/IPv6 translation
            ipv6(0x64, 0xff9b, 1) / 48,        // IPv4/IPv6 translation
            ipv6(0x100) / 64,                  // Discard
            ipv6(0x200) / 7,                   // Deprecated NSPA-mapped IPv6; Yggdrasil
            ipv6(0x2001, 0x0) / 32,            // Toredo
            ipv6(0x2001, 0x20) / 28,           // ORCHIDv2
            ipv6(0x2001, 0xdb8) / 32,          // Documentation/example
            ipv6(0x2002) / 16,                 // Deprecated 6to4 addressing scheme
            ipv6(0xfc00) / 7,                  // Unique local address
            ipv6(0xfe80) / 10,                 // link-local unicast addressing
            ipv6(0xff00) / 8,                  // Multicast
    };
}  //  namespace oxen::quic
