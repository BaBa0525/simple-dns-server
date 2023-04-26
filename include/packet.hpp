#ifndef PACKET_HPP_
#define PACKET_HPP_

#include <cinttypes>
#include <memory>
#include <string>
#include <vector>

constexpr int PACKET_SIZE = 1024;

struct Header {
    uint16_t dns_id;
#if __BYTE_ORDER == __LITTLE_ENDIAN
    uint8_t dns_rd : 1;
    uint8_t dns_tc : 1;
    uint8_t dns_aa : 1;
    uint8_t dns_opcode : 4;
    uint8_t dns_qr : 1;
    uint8_t dns_rcode : 4;
    uint8_t dns_z : 3;
    uint8_t dns_ra : 1;
#elif __BYTE_ORDER == __BIG_ENDIAN
    uint8_t dns_qr : 1;
    uint8_t dns_opcode : 4;
    uint8_t dns_aa : 1;
    uint8_t dns_tc : 1;
    uint8_t dns_rd : 1;
    uint8_t dns_ra : 1;
    uint8_t dns_z : 3;
    uint8_t dns_rcode : 4;
#else
#error "unsupported endian."
#endif
    uint16_t dns_qdcount;
    uint16_t dns_ancount;
    uint16_t dns_nscount;
    uint16_t dns_arcount;

    static auto from_network(void* data) -> Header;
    static auto to_response(const Header& header) -> Header;
} __attribute__((packed));

class Packet {
  public:
    Header header;
    std::unique_ptr<uint8_t[]> payload;
    size_t plen;

    static auto from_binary(void* data, size_t nbytes) -> Packet;
    auto raw() const -> std::unique_ptr<uint8_t[]>;
    auto raw_size() const -> size_t;
};

struct Query {
    std::string qname;
    uint16_t qtype;
    uint16_t qclass;

    static auto from_binary(const std::unique_ptr<uint8_t[]>& payload, size_t plen) -> Query;
};

#endif // PACKET_HPP_