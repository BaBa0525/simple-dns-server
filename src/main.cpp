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
            .register_fn(Record::Type::NS,
                         std::make_shared<NSRecordResponder>())
            .register_fn(Record::Type::MX,
                         std::make_shared<MXRecordResponder>())
            .register_fn(Record::Type::SOA,
                         std::make_shared<SOARecordResponder>())
            .register_fn(Record::Type::TXT,
                         std::make_shared<TXTRecordResponder>())
            .register_fn(Record::Type::AAAA,
                         std::make_shared<AAAARecordResponder>())
            .register_fn(Record::Type::CNAME,
                         std::make_shared<CNAMERecordResponder>())

            .bind(port);
    spdlog::info("Server bind to port {}\n", port);

    server.run();

    return 0;
}