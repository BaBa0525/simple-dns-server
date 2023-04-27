#include "server.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <fstream>
#include <iostream>
#include <sstream>

#include "builder.hpp"
#include "spdlog/spdlog.h"
#include "strategy.hpp"
#include "util.hpp"

auto Server::run() -> void {
    while (true) {
        auto data = this->receive(this->client_sock);

        if (!data) {
            spdlog::warn("Receive packet failed");
            continue;
        }

        auto [pkt, sender] = std::move(data.value());
        auto [qname, qtype, qclass] = Query::from_binary(pkt.payload, pkt.plen);

        auto domain_name = search_domain(qname);

        if (!domain_name) {
            // pass to another dns server
            pkt.header = Header::to_response(pkt.header);
            auto ret_pkt = this->forward(pkt);
            if (!data) {
                spdlog::warn("forward server not response");
                continue;
            }

            ret_pkt->header = Header::to_response(ret_pkt->header);
            auto error = this->send(this->client_sock, ret_pkt->raw(),
                                    ret_pkt->raw_size(), sender);

            if (error) {
                spdlog::warn("Fail to send forward packet: {}", error.value());
            }

            continue;
        }

        auto records = search_records(qname, qtype, qclass);

        if (records.empty()) {
            auto SOA_records =
                search_records(domain_name.value(), Record::SOA, Record::IN);

            if (SOA_records.empty()) {
                spdlog::warn("No SOA record found in {}", domain_name.value());
                continue;
            }

            // Pass the domain name to the responder
            SOA_records[0].r_name = domain_name.value();

            Packet ret_pkt = NotFoundResponder().response(SOA_records, pkt);
            auto error = this->send(this->client_sock, ret_pkt.raw(),
                                    ret_pkt.raw_size(), sender);

            if (error) {
                spdlog::warn("Fail to send not found packet: {}",
                             error.value());
            }
            continue;
        }
    }

    // this->registered_handler[Record::A].response(
    //     Query{qname, qtype, qclass});
}

auto Server::receive(int sock_fd)
    -> std::optional<std::pair<Packet, sockaddr_in>> {
    sockaddr_in sin{};
    socklen_t sinlen = sizeof(sin);
    uint8_t buf[PACKET_SIZE] = {};

    int ret = recvfrom(sock_fd, buf, sizeof(buf), 0,
                       reinterpret_cast<sockaddr*>(&sin), &sinlen);

    if (ret < 0) {
        return {};
    }

    return std::pair{Packet::from_binary(buf, ret), sin};
}

auto Server::forward(const Packet& packet) -> std::optional<Packet> {
    auto error = this->send(this->forward_sock, packet.raw(), packet.raw_size(),
                            this->forward_sin);

    if (error) {
        spdlog::warn("Fail to forward to server: {}", error.value());
        return {};
    }

    auto data = this->receive(this->forward_sock);
    if (!data) {
        spdlog::warn("forward server not response");
        return {};
    }

    // return packet
    return std::move(data->first);
}

auto Server::send(int sock_fd, const std::unique_ptr<uint8_t[]>& pkt,
                  size_t nbytes, sockaddr_in sin)
    -> std::optional<ErrorMessage> {
    int ret = sendto(sock_fd, pkt.get(), nbytes, 0,
                     reinterpret_cast<sockaddr*>(&sin), sizeof(sin));

    if (ret < 0) {
        return strerror(errno);
    }

    return {};
}

auto Server::search_domain(const std::string& qname)
    -> std::optional<std::string> {
    for (const auto& [domain_name, domain_records] : this->records) {
        if (qname.find(domain_name) != std::string::npos) {
            return domain_name;
        }
    }
    return {};
}

auto Server::search_records(const std::string& qname, uint16_t qtype,
                            uint16_t qclass) -> std::vector<Record> {
    auto domain_name = search_domain(qname);
    if (!domain_name) {
        return {};
    }

    std::string subdomain;
    if (qname == *domain_name) {
        subdomain = "@";
    } else {
        size_t pos = qname.find(*domain_name);
        subdomain = qname.substr(0, pos - 1);
    }

    std::vector<Record> ret, domain_records = this->records[*domain_name];
    for (const auto& record : domain_records) {
        if (record.r_name != subdomain || record.r_type != qtype) {
            continue;
        }
        ret.push_back(record);
    }

    return filter(
        domain_records, [&subdomain, qtype, qclass](const Record& record) {
            return (record.r_name == subdomain && record.r_type == qtype &&
                    record.r_class == qclass);
        });
}
