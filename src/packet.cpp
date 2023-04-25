#include "packet.hpp"

auto PacketBuilder::from_binary(void* data, size_t plen) -> PacketBuilder& {
    this->packet.header = Header::from_network(data);
    this->packet.plen = plen - sizeof(this->packet.header);

    this->packet.payload = std::make_unique<uint8_t[]>(this->packet.plen);
    std::copy_n(reinterpret_cast<uint8_t*>(data) + sizeof(this->packet.header),
                this->packet.plen, this->packet.payload.get());

    return *this;
}

auto Header::from_network(void* data) -> Header {
    Header header = *reinterpret_cast<Header*>(data);
    header.dns_id = ntohs(header.dns_id);
    header.dns_qdcount = ntohs(header.dns_qdcount);
    header.dns_ancount = ntohs(header.dns_ancount);
    header.dns_nscount = ntohs(header.dns_nscount);
    header.dns_arcount = ntohs(header.dns_arcount);

    return header;
}

auto Query::from_binary(const std::unique_ptr<uint8_t[]>& payload, size_t plen)
    -> Query {
    uint16_t cursor = 0, label_len = payload[cursor++];
    std::string qname;

    while (true) {
        if (label_len <= 0 || plen < cursor)
            break;
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

BufferBuilder::BufferBuilder() : buf{}, nbytes(0) {
    this->write(reinterpret_cast<void*>(&pkt->header), sizeof(pkt->header))
        .write(reinterpret_cast<void*>(pkt->payload.get()), pkt->plen);
}

auto Packet::raw() const -> std::unique_ptr<uint8_t[]> {
    return std::unique_ptr<uint8_t[]>();
}
