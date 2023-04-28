#include "strategy.hpp"

#include <arpa/inet.h>

#include "builder.hpp"
#include "spdlog/spdlog.h"
#include "util.hpp"

auto NotFoundResponder::response(const Collection& collection,
                                 const Packet& packet)
    -> std::optional<Packet> {
    // Header
    Header header = packet.header;
    header.dns_ancount = 1;
    header.dns_arcount = 0;
    header.dns_qr = 1;
    header = Header::to_response(header);

    // Question
    auto query = Query::from_binary(packet.payload, packet.plen);
    auto query_raw = query.raw();

    // Answer
    auto domain_raw = collection.search_domain(query.qname);

    auto SOA_records =
        collection.search_records(domain_raw.value(), Record::SOA, Record::IN);

    if (SOA_records.empty()) {
        spdlog::warn("No SOA record found in {}", domain_raw.value());
        return {};
    }

    Record SOA_record = SOA_records[0];
    std::vector<uint8_t> domain = compress_domain(domain_raw.value());
    std::vector<uint8_t> mname = compress_domain(SOA_record.r_rdata[0]);
    std::vector<uint8_t> rname = compress_domain(SOA_record.r_rdata[1]);

    RecordParmas record_params = {
        .r_type = htons(SOA_record.r_type),
        .r_class = htons(SOA_record.r_class),
        .r_ttl = htonl(SOA_record.r_ttl),
        .r_rdlength = htons(mname.size() + rname.size() + 20),
        // 20 is the size of the rest of the rdata
    };

    // Build the packet
    PacketBuilder builder{};

    builder.write(&header, sizeof(header))
        .write(query_raw.get(), query.raw_size())
        .write(domain.data(), domain.size())
        .write(&record_params, sizeof(record_params))
        .write(mname.data(), mname.size())
        .write(rname.data(), rname.size());

    for (int i = 2; i < SOA_record.r_rdata.size(); i++) {
        uint32_t data = htonl(std::stoi(SOA_record.r_rdata[i]));
        builder.write(&data, sizeof(data));
    }

    return builder.create();
}

auto ARecordResponder::response(const Collection& collection,
                                const Packet& packet) -> std::optional<Packet> {
    auto query = Query::from_binary(packet.payload, packet.plen);

    auto domain_raw = collection.search_domain(query.qname);

    auto A_Records =
        collection.search_records(query.qname, Record::A, Record::IN);

    auto NS_Records =
        collection.search_records(domain_raw.value(), Record::NS, Record::IN);

    Header header = packet.header;
    header.dns_ancount = A_Records.size();
    header.dns_nscount = NS_Records.size();
    header.dns_qr = 1;
    header = Header::to_response(header);

    auto query_raw = query.raw();

    PacketBuilder builder{};

    builder.write(&header, sizeof(header))
        .write(query_raw.get(), query.raw_size());

    for (auto record : A_Records) {
        std::vector<uint8_t> domain = compress_domain(query.qname);
        in_addr_t address = inet_addr(record.r_rdata[0].c_str());

        RecordParmas record_params = {
            .r_type = htons(record.r_type),
            .r_class = htons(record.r_class),
            .r_ttl = htonl(record.r_ttl),
            .r_rdlength = htons(sizeof(address)),
        };

        builder.write(domain.data(), domain.size())
            .write(&record_params, sizeof(record_params))
            .write(&address, sizeof(address));
    }

    for (auto record : NS_Records) {
        std::vector<uint8_t> domain = compress_domain(domain_raw.value());
        std::vector<uint8_t> ns = compress_domain(record.r_rdata[0]);

        RecordParmas record_params = {
            .r_type = htons(record.r_type),
            .r_class = htons(record.r_class),
            .r_ttl = htonl(record.r_ttl),
            .r_rdlength = htons(ns.size()),
        };

        builder.write(domain.data(), domain.size())
            .write(&record_params, sizeof(record_params))
            .write(ns.data(), ns.size());
    }

    return builder.create();
}
