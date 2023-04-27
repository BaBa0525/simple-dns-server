#include "strategy.hpp"

#include "builder.hpp"
#include "spdlog/spdlog.h"
#include "util.hpp"

auto NotFoundResponder::response(const std::vector<Record>& records,
                                 const Packet& packet) -> Packet {
    Header header = packet.header;
    header.dns_ancount = 1;
    header.dns_arcount = 0;
    header.dns_qr = 1;

    Packet ret_pkt;
    header = Header::to_response(header);
    auto query = Query::from_binary(packet.payload, packet.plen);
    auto query_raw = query.raw();

    for (auto i = 0u; i < query.raw_size(); i++) {
        std::cout << static_cast<int>(query_raw.get()[i]) << ' ';
    }
    std::cout << std::endl;

    Record SOA_record = records[0];
    std::vector<uint8_t> domain = compress_domain(SOA_record.r_name);
    std::vector<uint8_t> mname = compress_domain(SOA_record.r_rdata[0]);
    std::vector<uint8_t> rname = compress_domain(SOA_record.r_rdata[1]);

    RecordParmas record_params = {
        .r_type = htons(SOA_record.r_type),
        .r_class = htons(SOA_record.r_class),
        .r_ttl = htonl(SOA_record.r_ttl),
        .r_rdlength = htons(mname.size() + rname.size() + 20),
        // 20 is the size of the rest of the rdata
    };

    PacketBuilder builder{};

    spdlog::debug("sizeof(record_params) {}", sizeof(record_params));

    builder.write(&header, sizeof(header))
        .write(query_raw.get(), query.raw_size())
        .write(domain.data(), domain.size())
        .write(&record_params, sizeof(record_params))
        .write(mname.data(), mname.size())
        .write(rname.data(), rname.size());

    for (int i = 2; i < SOA_record.r_rdata.size(); i++) {
        spdlog::debug("SOA record rdata {}", SOA_record.r_rdata[i]);
        uint32_t data = htonl(std::stoi(SOA_record.r_rdata[i]));
        builder.write(&data, sizeof(data));
    }

    return builder.create();
}

auto ARecordResponder::response(const std::vector<Record>& records,
                                const Packet& packet) -> Packet {
    if (records.empty()) {
        spdlog::warn("No record found");
        return Packet{};
    }
    return Packet{};
}