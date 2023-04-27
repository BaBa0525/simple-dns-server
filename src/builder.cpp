#include "builder.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <fstream>
#include <iostream>

#include "spdlog/fmt/bin_to_hex.h"
#include "util.hpp"

auto ServerBuilder::bind(uint16_t port) -> Server {
    sockaddr_in client_sin{.sin_family = AF_INET, .sin_port = htons(port)};

    this->server.client_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if ((this->server.client_sock) < 0) {
        err_quit("Fail to build user socket");
    }

    int on = 1;
    setsockopt(this->server.client_sock, SOL_SOCKET, SO_REUSEADDR, &on,
               sizeof(on));

    if (::bind(this->server.client_sock, (sockaddr*)&client_sin,
               sizeof(client_sin)) < 0) {
        err_quit("Fail to bind client port");
    }

    sockaddr_in forward_sin{.sin_family = AF_INET, .sin_port = htons(port + 1)};

    this->server.forward_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if ((this->server.forward_sock) < 0) {
        err_quit("Fail to build forward socket");
    }

    on = 1;
    setsockopt(this->server.forward_sock, SOL_SOCKET, SO_REUSEADDR, &on,
               sizeof(on));

    if (::bind(this->server.forward_sock, (sockaddr*)&forward_sin,
               sizeof(forward_sin)) < 0) {
        err_quit("Fail to bind forward port");
    }

    return this->server;
}

auto ServerBuilder::load_config(const fs::path& config_path) -> ServerBuilder& {
    std::ifstream ifs(config_path);
    if (!ifs.is_open()) {
        err_quit("Fail to open config file");
    }

    spdlog::info("Reading config file {}", config_path.string());

    if (!std::getline(ifs, this->forward_ip)) {
        err_quit("Fail to get forward ip");
    }

    this->forward_ip = trim(this->forward_ip);

    std::string line;
    while (std::getline(ifs, line)) {
        auto split_line = split(line, ',');
        if (split_line.size() < 2) {
            err_quit("config file format incorrect");
        }

        std::string domain = std::move(split_line[0]);
        std::string filename = std::move(split_line[1]);

        fs::path zone_path = config_path.parent_path() / filename;
        spdlog::info("Reading zone file {}", zone_path.string());
        load_zone(zone_path);
    }
    return *this;
}

auto ServerBuilder::init() -> ServerBuilder& {
    this->server.forward_sin = {
        .sin_family = AF_INET,
        .sin_port = htons(FORWARD_PORT),
    };

    int ret = inet_pton(AF_INET, this->forward_ip.data(),
                        &this->server.forward_sin.sin_addr);

    if (ret <= 0) {
        err_quit(
            ("Can't convert IPv4 address for " + this->forward_ip).c_str());
    }

    // this->register_fn(std::make_unique<QueryHandler>(AHandler()))
    //     .register_fn(std::make_unique<QueryHandler>(AHandler()))
    //     .register_fn(std::make_unique<QueryHandler>(AHandler()));

    return *this;
}

void ServerBuilder::load_zone(const fs::path& zone_path) {
    std::ifstream ifs(zone_path);
    if (!ifs.is_open()) {
        err_quit("Fail to open zone file");
    }

    std::string domain, line;
    if (!std::getline(ifs, domain)) {
        err_quit("Fail to get domain");
    }

    domain = trim(domain);

    while (std::getline(ifs, line)) {
        spdlog::debug("{}", line);
        auto slices = split(line, ',');

        if (slices.size() < 5) {
            spdlog::warn("Invalid record: {}", line);
            continue;
        }

        auto r = RecordBuilder()
                     .set_name(slices[0])
                     .set_ttl(slices[1])
                     .set_class(slices[2])
                     .set_type(slices[3])
                     .set_rdata(split(slices[4]))
                     .build();

        this->server.records[domain].push_back(r);
    }
}

auto RecordBuilder::set_name(const std::string& name) -> RecordBuilder& {
    this->record.r_name = name;
    return *this;
}

auto RecordBuilder::set_type(const std::string& type) -> RecordBuilder& {
    static std::map<std::string, Record::Type> type_value = {
        {"A", Record::Type::A},         {"NS", Record::Type::NS},
        {"CNAME", Record::Type::CNAME}, {"SOA", Record::Type::SOA},
        {"MX", Record::Type::MX},       {"TXT", Record::Type::TXT},
        {"AAAA", Record::Type::AAAA}};

    this->record.r_type = type_value[type];
    return *this;
}

auto RecordBuilder::set_class(const std::string& r_class) -> RecordBuilder& {
    static std::map<std::string, Record::Class> class_value = {
        {"IN", Record::Class::IN},
        {"CS", Record::Class::CS},
        {"CH", Record::Class::CH},
        {"HS", Record::Class::HS}};

    this->record.r_class = class_value[r_class];
    return *this;
}

auto RecordBuilder::set_ttl(const std::string& ttl) -> RecordBuilder& {
    this->record.r_ttl = std::stoul(ttl);
    return *this;
}

auto RecordBuilder::set_rdlen(const std::string& dlen) -> RecordBuilder& {
    this->record.r_rdlength = std::stoul(dlen);
    return *this;
}

auto RecordBuilder::set_rdata(const std::vector<std::string>& data)
    -> RecordBuilder& {
    this->record.r_rdata = data;
    return *this;
}

auto RecordBuilder::build() -> Record { return this->record; }

auto PacketBuilder::write(void* data, size_t dlen) -> PacketBuilder& {
    std::copy_n(reinterpret_cast<uint8_t*>(data), dlen,
                this->buffer + this->nbytes);
    this->nbytes += dlen;
    return *this;
}

auto PacketBuilder::create() -> Packet {
    size_t header_len = sizeof(this->packet.header);
    this->packet.plen = this->nbytes - header_len;

    std::copy_n(this->buffer, header_len,
                reinterpret_cast<uint8_t*>(&this->packet.header));

    spdlog::debug("packet plen: {}", this->packet.plen);

    this->packet.payload = std::make_unique<uint8_t[]>(this->packet.plen);
    std::copy_n(this->buffer, this->packet.plen, this->packet.payload.get());

    return std::move(this->packet);
}
