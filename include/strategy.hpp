#ifndef STRATEGY_HPP_
#define STRATEGY_HPP_

#include "packet.hpp"

class QueryHandler {
   public:
    virtual auto query_type() -> std::string = 0;
    virtual auto process(const Query& query) -> void = 0;
};

class AHandler : public QueryHandler {
   public:
    auto query_type() -> std::string override;
    auto process(const Query& query) -> void override;
};

#endif