#include "server.hpp"
#include "spdlog/spdlog.h"
#include "utils.hpp"

int main(int argc, char* argv[]) {
    spdlog::set_level(spdlog::level::debug);

    auto [port, config_path] = parse_args(argc, argv);
    auto server = ServerBuilder().load_config(config_path).bind(port);
    spdlog::info("Server bind to port {}\n", port);

    return 0;
}