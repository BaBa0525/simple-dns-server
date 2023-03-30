#pragma once

#include <string>

class Server {
   public:
    int sock_fd;
    std::string forward_ip;

    Server& bind_port(long port);
    Server* load_config();
};