#include <cinttypes>
#include <memory>
#include <string>
#include <vector>

constexpr int PACKET_SIZE = 1000;

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
} __attribute__((packed));

struct Packet {
    Header header;
    std::unique_ptr<uint8_t[]> data;
    uint16_t dlen;

    static auto from_binary(void* data, size_t dlen) -> Packet;
};

struct Question {
    std::string dns_qname;
    uint16_t dns_qtype;
    uint16_t dns_qclass;
};