#include "utils.hpp"

auto parse_args(int argc, char* argv[]) -> std::pair<uint16_t, fs::path> {
    if (argc < 3) {
        std::cerr << "usage: " << argv[0] << " <port> <config-path>\n";
        exit(EXIT_FAILURE);
    }

    uint16_t port = std::stoul(argv[1]);
    fs::path conf_path = argv[2];

    return {port, conf_path};
}