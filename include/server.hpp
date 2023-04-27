#ifndef DNS_SERVER_HPP_
#define DNS_SERVER_HPP_

#include <arpa/inet.h>

#include <filesystem>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "packet.hpp"
#include "record.hpp"
#include "strategy.hpp"

using ErrorMessage = std::string;
namespace fs = std::filesystem;
constexpr int FORWARD_PORT = 53;

class Server {
    friend class ServerBuilder;

   public:
    int client_sock, forward_sock;
    sockaddr_in forward_sin{};

    std::map<std::string, std::vector<Record>> records;
    auto run() -> void;

   private:
    std::map<Record::Type, std::shared_ptr<QueryResponder>> registered_handler;

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