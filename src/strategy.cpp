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
    std::vector<uint8_t> ns = compress_domain(SOA_record.r_rdata[0]);
    std::vector<uint8_t> mbox = compress_domain(SOA_record.r_rdata[1]);

    RecordParmas record_params = {
        .r_type = htons(SOA_record.r_type),
        .r_class = htons(SOA_record.r_class),
        .r_ttl = htonl(SOA_record.r_ttl),
        .r_rdlength = htons(ns.size() + mbox.size() + 20),
        // 20 is the size of the rest of the rdata
    };

    // Build the packet
    PacketBuilder builder{};

    builder.write(&header, sizeof(header))
        .write(query_raw.get(), query.raw_size())
        .write(domain.data(), domain.size())
        .write(&record_params, sizeof(record_params))
        .write(ns.data(), ns.size())
        .write(mbox.data(), mbox.size());

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

    auto A_records =
        collection.search_records(query.qname, Record::A, Record::IN);

    auto NS_records =
        collection.search_records(domain_raw.value(), Record::NS, Record::IN);

    Header header = packet.header;
    header.dns_ancount = A_records.size();
    header.dns_nscount = NS_records.size();
    header.dns_arcount = 0;
    header.dns_qr = 1;
    header = Header::to_response(header);

    auto query_raw = query.raw();

    PacketBuilder builder{};

    builder.write(&header, sizeof(header))
        .write(query_raw.get(), query.raw_size());

    for (auto record : A_records) {
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

    for (auto record : NS_records) {
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

auto NSRecordResponder::response(const Collection& collection,
                                 const Packet& packet)
    -> std::optional<Packet> {
    auto query = Query::from_binary(packet.payload, packet.plen);

    auto NS_records =
        collection.search_records(query.qname, Record::NS, Record::IN);

    Header header = packet.header;
    header.dns_ancount = NS_records.size();
    header.dns_arcount = NS_records.size();
    header.dns_qr = 1;
    header = Header::to_response(header);

    auto query_raw = query.raw();

    PacketBuilder builder{};

    builder.write(&header, sizeof(header))
        .write(query_raw.get(), query.raw_size());

    for (auto record : NS_records) {
        std::vector<uint8_t> domain = compress_domain(query.qname);
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

    for (auto NS_record : NS_records) {
        auto ns_name = NS_record.r_rdata[0];
        auto A_records =
            collection.search_records(ns_name, Record::A, Record::IN);

        if (A_records.size() == 0) {
            continue;
        }

        auto record = A_records[0];

        std::vector<uint8_t> domain = compress_domain(ns_name);
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

    return builder.create();
}

auto MXRecordResponder::response(const Collection& collection,
                                 const Packet& packet)
    -> std::optional<Packet> {
    auto query = Query::from_binary(packet.payload, packet.plen);

    auto MX_records =
        collection.search_records(query.qname, Record::MX, Record::IN);

    auto NS_records =
        collection.search_records(query.qname, Record::NS, Record::IN);

    Header header = packet.header;
    header.dns_ancount = MX_records.size();
    header.dns_arcount = MX_records.size();
    header.dns_nscount = NS_records.size();
    header.dns_qr = 1;
    header = Header::to_response(header);

    auto query_raw = query.raw();

    PacketBuilder builder{};

    builder.write(&header, sizeof(header))
        .write(query_raw.get(), query.raw_size());

    for (auto record : MX_records) {
        std::vector<uint8_t> domain = compress_domain(query.qname);
        std::vector<uint8_t> mx = compress_domain(record.r_rdata[1]);

        RecordParmas record_params = {
            .r_type = htons(record.r_type),
            .r_class = htons(record.r_class),
            .r_ttl = htonl(record.r_ttl),
            .r_rdlength = htons(mx.size() + sizeof(uint16_t)),
        };

        uint16_t preference = htons(std::stoi(record.r_rdata[0]));

        builder.write(domain.data(), domain.size())
            .write(&record_params, sizeof(record_params))
            .write(&preference, sizeof(preference))
            .write(mx.data(), mx.size());
    }

    for (auto record : NS_records) {
        std::vector<uint8_t> domain = compress_domain(query.qname);
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

    for (auto MX_record : MX_records) {
        auto mx_name = MX_record.r_rdata[1];
        auto A_records =
            collection.search_records(mx_name, Record::A, Record::IN);

        if (A_records.size() == 0) {
            continue;
        }

        auto record = A_records[0];

        std::vector<uint8_t> domain = compress_domain(mx_name);
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

    return builder.create();
}

auto SOARecordResponder::response(const Collection& collection,
                                  const Packet& packet)
    -> std::optional<Packet> {
    auto query = Query::from_binary(packet.payload, packet.plen);

    auto SOA_records =
        collection.search_records(query.qname, Record::SOA, Record::IN);

    auto NS_records =
        collection.search_records(query.qname, Record::NS, Record::IN);

    Header header = packet.header;
    header.dns_ancount = SOA_records.size();
    header.dns_nscount = NS_records.size();
    header.dns_arcount = 0;
    header.dns_qr = 1;
    header = Header::to_response(header);

    auto query_raw = query.raw();

    PacketBuilder builder{};

    builder.write(&header, sizeof(header))
        .write(query_raw.get(), query.raw_size());

    for (auto record : SOA_records) {
        std::vector<uint8_t> domain = compress_domain(query.qname);
        std::vector<uint8_t> ns = compress_domain(record.r_rdata[0]);
        std::vector<uint8_t> mbox = compress_domain(record.r_rdata[1]);

        RecordParmas record_params = {
            .r_type = htons(record.r_type),
            .r_class = htons(record.r_class),
            .r_ttl = htonl(record.r_ttl),
            .r_rdlength = htons(ns.size() + mbox.size() + 20),
        };

        builder.write(domain.data(), domain.size())
            .write(&record_params, sizeof(record_params))
            .write(ns.data(), ns.size())
            .write(mbox.data(), mbox.size());

        for (int i = 2; i < record.r_rdata.size(); i++) {
            uint32_t data = htonl(std::stoi(record.r_rdata[i]));
            builder.write(&data, sizeof(data));
        }
    }

    for (auto record : NS_records) {
        std::vector<uint8_t> domain = compress_domain(query.qname);
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

auto TXTRecordResponder::response(const Collection& collection,
                                  const Packet& packet)
    -> std::optional<Packet> {
    auto query = Query::from_binary(packet.payload, packet.plen);

    auto TXT_records =
        collection.search_records(query.qname, Record::TXT, Record::IN);

    Header header = packet.header;
    header.dns_ancount = TXT_records.size();
    header.dns_arcount = 0;
    header.dns_qr = 1;
    header = Header::to_response(header);

    auto query_raw = query.raw();

    PacketBuilder builder{};

    builder.write(&header, sizeof(header))
        .write(query_raw.get(), query.raw_size());

    for (auto record : TXT_records) {
        std::vector<uint8_t> domain = compress_domain(query.qname);
        std::string txt = record.r_rdata[0];
        uint8_t txtlen = txt.size();

        RecordParmas record_params = {
            .r_type = htons(record.r_type),
            .r_class = htons(record.r_class),
            .r_ttl = htonl(record.r_ttl),
            .r_rdlength = htons(txt.size() + 1),
        };

        builder.write(domain.data(), domain.size())
            .write(&record_params, sizeof(record_params))
            .write(&txtlen, sizeof(txtlen))
            .write(txt.data(), txt.size());
    }

    return builder.create();
}

auto AAAARecordResponder::response(const Collection& collection,
                                   const Packet& packet)
    -> std::optional<Packet> {
    auto query = Query::from_binary(packet.payload, packet.plen);

    auto domain_raw = collection.search_domain(query.qname);

    auto AAAA_records =
        collection.search_records(query.qname, Record::AAAA, Record::IN);

    auto NS_records =
        collection.search_records(domain_raw.value(), Record::NS, Record::IN);

    Header header = packet.header;
    header.dns_ancount = AAAA_records.size();
    header.dns_nscount = NS_records.size();
    header.dns_arcount = 0;
    header.dns_qr = 1;
    header = Header::to_response(header);

    auto query_raw = query.raw();

    PacketBuilder builder{};

    builder.write(&header, sizeof(header))
        .write(query_raw.get(), query.raw_size());

    for (auto record : AAAA_records) {
        std::vector<uint8_t> domain = compress_domain(query.qname);
        sockaddr_in6 sin6{};

        if (inet_pton(AF_INET6, record.r_rdata[0].c_str(), &sin6.sin6_addr) <=
            0) {
            err_quit("IPv6 fail");
        }

        auto& address = sin6.sin6_addr.__u6_addr.__u6_addr8;

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

    for (auto record : NS_records) {
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

auto CNAMERecordResponder::response(const Collection& collection,
                                    const Packet& packet)
    -> std::optional<Packet> {
    auto query = Query::from_binary(packet.payload, packet.plen);
    auto CNAME_records =
        collection.search_records(query.qname, Record::CNAME, Record::IN);

    auto domain_raw = collection.search_domain(query.qname);

    auto NS_records =
        collection.search_records(query.qname, Record::NS, Record::IN);

    Header header = packet.header;
    header.dns_ancount = CNAME_records.size();
    header.dns_nscount = NS_records.size();
    header.dns_arcount = 0;
    header.dns_qr = 1;
    header = Header::to_response(header);

    auto query_raw = query.raw();

    PacketBuilder builder{};

    builder.write(&header, sizeof(header))
        .write(query_raw.get(), query.raw_size());

    for (auto record : CNAME_records) {
        std::vector<uint8_t> domain = compress_domain(query.qname);
        std::vector<uint8_t> cname = compress_domain(record.r_rdata[0]);

        RecordParmas record_params = {
            .r_type = htons(record.r_type),
            .r_class = htons(record.r_class),
            .r_ttl = htonl(record.r_ttl),
            .r_rdlength = htons(cname.size()),
        };

        builder.write(domain.data(), domain.size())
            .write(&record_params, sizeof(record_params))
            .write(cname.data(), cname.size());
    }

    for (auto record : NS_records) {
        std::vector<uint8_t> domain = compress_domain(query.qname);
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