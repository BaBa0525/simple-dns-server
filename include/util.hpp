#ifndef DNS_UTILS_HPP_
#define DNS_UTILS_HPP_

#include <filesystem>
#include <functional>
#include <iostream>
#include <string>

#include "spdlog/spdlog.h"

namespace fs = std::filesystem;
using TrimStrategy = std::function<bool(unsigned char)>;

inline auto err_quit(const std::string& m) -> void {
    spdlog::error("{}: {}", m, strerror(errno));
    exit(EXIT_FAILURE);
}

auto parse_args(int argc, char* argv[]) -> std::pair<uint16_t, fs::path>;

auto trim(const std::string& str, TrimStrategy strategy = std::not_fn(isspace))
    -> std::string;

auto split(const std::string& str, char delim = ' ')
    -> std::vector<std::string>;

template <typename Container, typename Predicate>
auto filter(const Container& container, Predicate&& predicate) -> Container {
    Container result;
    std::copy_if(std::begin(container), std::end(container),
                 std::back_inserter(result),
                 std::forward<Predicate>(predicate));
    return result;
}

#endif
