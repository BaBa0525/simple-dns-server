#ifndef DNS_SERVER_HPP_
#define DNS_SERVER_HPP_

#include <filesystem>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "packet.hpp"

namespace fs = std::filesystem;

class Record {
  public:
    enum Type {
        A = 1,
        NS = 2,
        CNAME = 5,
        SOA = 6,
        MX = 15,
        TXT = 16,
        AAAA = 28
    };
    enum Class { IN = 1, CS = 2, CH = 3, HS = 4 };

    std::string r_name;
    uint16_t r_type;
    uint16_t r_class;
    uint32_t r_ttl;
    uint16_t r_rdlength;
    std::vector<std::string> r_rdata;
};

class RecordBuilder {
  public:
    Record record;

    auto set_name(const std::string& name) -> RecordBuilder&;
    auto set_type(const std::string& type) -> RecordBuilder&;
    auto set_class(const std::string& r_class) -> RecordBuilder&;
    auto set_ttl(const std::string& ttl) -> RecordBuilder&;
    auto set_rdlen(const std::string& dlen) -> RecordBuilder&;
    auto set_rdata(const std::vector<std::string>& data) -> RecordBuilder&;

    auto build() -> Record;
};

class Server {
  public:
    int sock_fd;
    std::string forward_ip;
    std::map<std::string, std::vector<Record>> records;
    auto run() -> void;

  private:
    auto receive() -> std::optional<Packet>;
};

class ServerBuilder {
  public:
    Server server;
    auto load_config(const fs::path& config_path) -> ServerBuilder&;
    auto bind(uint16_t port) -> Server;

  private:
    void load_zone(const fs::path& zone_path);
};

#endif