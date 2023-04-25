#include "util.hpp"

#include <sstream>

auto parse_args(int argc, char* argv[]) -> std::pair<uint16_t, fs::path> {
    if (argc < 3) {
        std::cerr << "usage: " << argv[0] << " <port> <config-path>\n";
        exit(EXIT_FAILURE);
    }

    uint16_t port = std::stoul(argv[1]);
    fs::path conf_path = argv[2];

    return {port, conf_path};
}

auto trim(const std::string& str, TrimStrategy strategy) -> std::string {
    auto left = std::find_if(str.begin(), str.end(), strategy);
    auto right = std::find_if(str.rbegin(), str.rend(), strategy);
    return std::string(left, right.base());
}

auto split(const std::string& str, char delim) -> std::vector<std::string> {
    std::stringstream ss(str);

    std::string seg;
    std::vector<std::string> result;
    while (std::getline(ss, seg, delim)) {
        result.push_back(trim(seg));
    }

    return result;
}