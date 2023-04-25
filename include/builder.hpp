#ifndef BUILDER_HPP_
#define BUILDER_HPP_

#include "server.hpp"

class ServerBuilder {
  public:
    Server server;
    auto load_config(const fs::path& config_path) -> ServerBuilder&;
    auto init() -> ServerBuilder&;
    auto bind(uint16_t port) -> Server;

  private:
    std::string forward_ip;

    auto register_fn(std::unique_ptr<QueryHandler> handler) -> ServerBuilder&;
    void load_zone(const fs::path& zone_path);
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

#endif