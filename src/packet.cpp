#include "packet.hpp"

auto Packet::from_binary(void* data, size_t dlen) -> Packet {
    Packet packet;
    packet.header = Header::from_network(data);
    packet.dlen = dlen - sizeof(packet.header);
    packet.data = std::make_unique<uint8_t[]>(packet.dlen);
    std::copy_n(reinterpret_cast<uint8_t*>(data) + sizeof(packet.header),
                packet.dlen, packet.data.get());

    return packet;
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