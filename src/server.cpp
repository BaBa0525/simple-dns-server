#include "server.hpp"

#include <netinet/in.h>
#include <sys/socket.h>

#include "spdlog/spdlog.h"
#include "utils.hpp"

Server& Server::bind_port(long port) {
    sockaddr_in sin{};
    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);
    printf("server: %ld\n", port);
    spdlog::info("Server bind port {}\n", port);

    if ((this->sock_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
        err_quit("Fail to build socket");
    int on = 1;
    setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    if (bind(sock_fd, (sockaddr*)&sin, sizeof(sin)) < 0)
        err_quit("Fail to bind port");

    return *this;
}