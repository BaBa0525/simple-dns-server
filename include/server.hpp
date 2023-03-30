#ifndef DNS_SERVER_HPP_
#define DNS_SERVER_HPP_

#include <string>

class Server {
   public:
    int sock_fd;
    std::string forward_ip;

    static Server bind(uint16_t port);
    Server* load_config();
};

#endif