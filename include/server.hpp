#ifndef DNS_SERVER_HPP_
#define DNS_SERVER_HPP_

#include <arpa/inet.h>
#include <filesystem>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "packet.hpp"
#include "strategy.hpp"

using ErrorMessage = std::string;
namespace fs = std::filesystem;
constexpr int FORWARD_PORT = 53;

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

class Server {
    friend class ServerBuilder;

  public:
    int client_sock, forward_sock;
    sockaddr_in forward_sin{};

    std::map<std::string, std::vector<Record>> records;
    auto run() -> void;

  private:
    // std::map<Record::Type, QueryHandler> registered_handler;

    auto create_response(std::function<void(Query)> cb) -> Packet;
    auto forward(const Packet& packet) -> std::optional<Packet>;
    auto send(int sock_fd, const std::unique_ptr<uint8_t[]>& pkt, size_t nbytes,
              sockaddr_in sin) -> std::optional<ErrorMessage>;
    auto receive(int sock_fd) -> std::optional<std::pair<Packet, sockaddr_in>>;
    auto search_domain(const std::string& qname) -> std::optional<std::string>;
    auto search_records(const std::string& qname, uint16_t qtype,
                        uint16_t qclass) -> std::vector<Record>;
};

#endif