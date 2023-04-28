#include "builder.hpp"
#include "server.hpp"
#include "spdlog/spdlog.h"
#include "util.hpp"

int main(int argc, char* argv[], char* envp[]) {
    spdlog::set_level(spdlog::level::info);
    const char* level = getenv("LOG_LEVEL");
    if (level != nullptr) {
        spdlog::set_level(spdlog::level::from_str(level));
    }

    auto [port, config_path] = parse_args(argc, argv);
    auto server =
        ServerBuilder()
            .load_config(config_path)
            .register_fn(Record::Type::A, std::make_shared<ARecordResponder>())
            .bind(port);
    spdlog::info("Server bind to port {}\n", port);

    server.run();

    return 0;
}