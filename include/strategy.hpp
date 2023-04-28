#ifndef STRATEGY_HPP_
#define STRATEGY_HPP_

#include <vector>

#include "collection.hpp"
#include "packet.hpp"
#include "record.hpp"

struct RecordParmas {
    uint16_t r_type;
    uint16_t r_class;
    uint32_t r_ttl;
    uint16_t r_rdlength;
} __attribute__((packed));

class QueryResponder {
   public:
    virtual ~QueryResponder() = default;
    virtual auto response(const Collection& collection, const Packet& packet)
        -> std::optional<Packet> = 0;
};

class NotFoundResponder : public QueryResponder {
   public:
    auto response(const Collection& collection, const Packet& packet)
        -> std::optional<Packet> override;
};

class ARecordResponder : public QueryResponder {
   public:
    auto response(const Collection& collection, const Packet& packet)
        -> std::optional<Packet> override;
};

class NSRecordResponder : public QueryResponder {
   public:
    auto response(const Collection& collection, const Packet& packet)
        -> std::optional<Packet> override;
};

class MXRecordResponder : public QueryResponder {
   public:
    auto response(const Collection& collection, const Packet& packet)
        -> std::optional<Packet> override;
};

class SOARecordResponder : public QueryResponder {
   public:
    auto response(const Collection& collection, const Packet& packet)
        -> std::optional<Packet> override;
};

class AAAARecordResponder : public QueryResponder {
   public:
    auto response(const Collection& collection, const Packet& packet)
        -> std::optional<Packet> override;
};

class TXTRecordResponder : public QueryResponder {
   public:
    auto response(const Collection& collection, const Packet& packet)
        -> std::optional<Packet> override;
};

class CNAMERecordResponder : public QueryResponder {
   public:
    auto response(const Collection& collection, const Packet& packet)
        -> std::optional<Packet> override;
};

#endif