#ifndef BUILDER_HPP_
#define BUILDER_HPP_

#include "packet.hpp"
#include "server.hpp"

class ServerBuilder {
   public:
    Server server;
    auto load_config(const fs::path& config_path) -> ServerBuilder&;
    auto bind(uint16_t port) -> Server;
    auto register_fn(Record::Type type, std::shared_ptr<QueryResponder> handler)
        -> ServerBuilder&;

   private:
    std::string forward_ip;

    void load_zone(const fs::path& zone_path);
};

class RecordBuilder {
   public:
    Record record;

    auto set_name(const std::string& name) -> RecordBuilder&;
    auto set_type(const std::string& type) -> RecordBuilder&;
    auto set_class(const std::string& r_class) -> RecordBuilder&;
    auto set_ttl(const std::string& ttl) -> RecordBuilder&;
    auto set_rdata(const std::vector<std::string>& data) -> RecordBuilder&;

    auto build() -> Record;
};

class HeaderBuilder {
   public:
    HeaderBuilder() {}
    HeaderBuilder(const Header& header) : header(header) {}

   private:
    Header header;
};

class PacketBuilder {
   public:
    PacketBuilder() : nbytes(0) {}
    auto write(void* data, size_t nbytes) -> PacketBuilder&;
    auto create() -> Packet;

   private:
    Packet packet;
    uint8_t buffer[PACKET_SIZE];
    size_t nbytes;
};

#endif