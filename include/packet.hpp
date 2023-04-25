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

class HeaderBuilder {
  public:
    HeaderBuilder() {}
    HeaderBuilder(const Header& header) : header(header) {}

    auto from_network(void* data) -> HeaderBuilder&;
    auto to_response() -> HeaderBuilder&;
    auto set_ancount() -> HeaderBuilder&;
    auto set_nscount() -> HeaderBuilder&;
    auto set_arcount() -> HeaderBuilder&;
    auto create() -> Header;

  private:
    Header header;
};

class Packet {
  public:
    Header header;
    std::unique_ptr<uint8_t[]> payload;
    size_t plen;

    auto raw() const -> std::unique_ptr<uint8_t[]>;
    auto raw_size() const -> size_t;
};

class PacketBuilder {
  public:
    auto from_binary(void* data, size_t plen) -> PacketBuilder&;
    auto write(void* data, size_t dlen) -> PacketBuilder&;
    auto create() -> Packet;

  private:
    Packet packet;
    uint8_t buffer[PACKET_SIZE];
};

struct Query {
    std::string qname;
    uint16_t qtype;
    uint16_t qclass;

    static auto from_binary(const std::unique_ptr<uint8_t[]>& payload,
                            size_t plen) -> Query;
};

struct Buffer {
    uint8_t data[512];
} __attribute__((packed));

class BufferBuilder {
  public:
    BufferBuilder() : buf{}, nbytes(0) {}
    BufferBuilder(Packet pkt);

    auto write(void* data, size_t dlen) -> BufferBuilder&;
    auto create() -> std::pair<Buffer, size_t>;

  private:
    Buffer buf;
    size_t nbytes;
};