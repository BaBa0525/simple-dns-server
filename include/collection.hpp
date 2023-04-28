#ifndef COLLECTION_HPP_
#define COLLECTION_HPP_

#include <map>
#include <optional>
#include <string>
#include <vector>

#include "record.hpp"

class Collection {
   public:
    std::map<std::string, std::vector<Record>> records;

    auto add_record(const std::string& domain, const Record& record) -> void;

    auto search_domain(const std::string& qname) const
        -> std::optional<std::string>;
    auto search_records(const std::string& qname, uint16_t qtype,
                        uint16_t qclass) const -> std::vector<Record>;
};

#endif