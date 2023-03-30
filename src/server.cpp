#include "server.hpp"

#include <netinet/in.h>
#include <sys/socket.h>

#include "spdlog/spdlog.h"
#include "utils.hpp"

auto Server::bind(uint16_t port) -> Server {
    sockaddr_in sin{};
    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);

    Server server;

    if ((server.sock_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
        err_quit("Fail to build socket");
    int on = 1;
    setsockopt(server.sock_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    if (::bind(server.sock_fd, (sockaddr*)&sin, sizeof(sin)) < 0)
        err_quit("Fail to bind port");

    return server;
}
