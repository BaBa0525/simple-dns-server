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

        auto domain_name = this->collection.search_domain(qname);

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

        auto records = this->collection.search_records(qname, qtype, qclass);

        if (records.empty()) {
            auto ret_pkt = NotFoundResponder().response(this->collection, pkt);

            if (!ret_pkt) {
                spdlog::warn("Fail to build not found packet");
                continue;
            }

            auto error = this->send(this->client_sock, ret_pkt->raw(),
                                    ret_pkt->raw_size(), sender);

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