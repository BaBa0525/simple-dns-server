#include "packet.hpp"

#include "spdlog/spdlog.h"
#include "util.hpp"

auto Header::from_network(void* data) -> Header {
    Header header = *reinterpret_cast<Header*>(data);
    header.dns_id = ntohs(header.dns_id);
    header.dns_qdcount = ntohs(header.dns_qdcount);
    header.dns_ancount = ntohs(header.dns_ancount);
    header.dns_nscount = ntohs(header.dns_nscount);
    header.dns_arcount = ntohs(header.dns_arcount);

    return header;
}

auto Header::to_response(const Header& header) -> Header {
    Header response = header;
    response.dns_id = htons(header.dns_id);
    response.dns_qdcount = htons(header.dns_qdcount);
    response.dns_ancount = htons(header.dns_ancount);
    response.dns_nscount = htons(header.dns_nscount);
    response.dns_arcount = htons(header.dns_arcount);

    return response;
}

auto Query::from_binary(const std::unique_ptr<uint8_t[]>& payload, size_t plen)
    -> Query {
    uint16_t cursor = 0, label_len = payload[cursor++];
    std::string qname;

    while (true) {
        if (label_len <= 0 || plen < cursor) {
            break;
        }

        qname.append(reinterpret_cast<char*>(&payload[cursor]), label_len);
        qname.push_back('.');
        cursor += label_len;
        label_len = payload[cursor++];
    }

    uint16_t qtype = ntohs(*reinterpret_cast<uint16_t*>(&payload[cursor]));
    cursor += sizeof(qtype);

    uint16_t qclass = ntohs(*reinterpret_cast<uint16_t*>(&payload[cursor]));
    cursor += sizeof(qclass);

    return Query{qname, qtype, qclass};
}

auto Query::raw() const -> std::unique_ptr<uint8_t[]> {
    size_t size =
        sizeof(this->qname) + sizeof(this->qtype) + sizeof(this->qclass);

    auto raw = std::make_unique<uint8_t[]>(size);
    std::vector<uint8_t> compressed = compress_domain(this->qname);

    uint8_t* cursor = raw.get();
    cursor = std::copy_n(compressed.data(), compressed.size(), cursor);

    uint16_t qtype = htons(this->qtype);
    std::copy_n(reinterpret_cast<uint8_t*>(&qtype), sizeof(qtype), cursor);
    cursor += sizeof(qtype);

    uint16_t qclass = htons(this->qclass);
    std::copy_n(reinterpret_cast<uint8_t*>(&qclass), sizeof(qclass), cursor);

    return std::move(raw);
}

auto Query::raw_size() const -> size_t {
    return sizeof(this->qname) + sizeof(this->qtype) + sizeof(this->qclass);
}

auto Packet::raw() const -> std::unique_ptr<uint8_t[]> {
    size_t size = sizeof(this->header) + this->plen;
    auto raw = std::make_unique<uint8_t[]>(size);

    Header header = Header::to_response(this->header);
    std::copy_n(reinterpret_cast<uint8_t*>(&header), sizeof(header), raw.get());
    std::copy_n(this->payload.get(), this->plen, raw.get() + sizeof(header));

    return std::move(raw);
}

auto Packet::raw_size() const -> size_t {
    return sizeof(this->header) + this->plen;
}

auto Packet::from_binary(void* data, size_t dlen) -> Packet {
    Packet packet{};
    packet.header = Header::from_network(data);

    packet.plen = dlen - sizeof(packet.header);

    packet.payload = std::make_unique<uint8_t[]>(packet.plen);
    std::copy_n(reinterpret_cast<uint8_t*>(data) + sizeof(packet.header),
                packet.plen, packet.payload.get());

    return packet;
}
