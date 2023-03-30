#ifndef DNS_UTILS_HPP_
#define DNS_UTILS_HPP_

#include <filesystem>
#include <iostream>
#include <string>

#include "spdlog/spdlog.h"

namespace fs = std::filesystem;

inline auto err_quit(const std::string& m) -> void {
    spdlog::error("{}: {}", m, strerror(errno));
    exit(EXIT_FAILURE);
}

auto parse_args(int argc, char* argv[]) -> std::pair<uint16_t, fs::path>;

#endif
