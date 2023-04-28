#include "collection.hpp"

#include "util.hpp"

auto Collection::add_record(const std::string& domain, const Record& record)
    -> void {
    this->records[domain].push_back(record);
}

auto Collection::search_domain(const std::string& qname)
    -> std::optional<std::string> {
    for (const auto& [domain_name, domain_records] : this->records) {
        if (qname.find(domain_name) != std::string::npos) {
            return domain_name;
        }
    }
    return {};
}

auto Collection::search_records(const std::string& qname, uint16_t qtype,
                                uint16_t qclass) -> std::vector<Record> {
    auto domain_name = search_domain(qname);
    if (!domain_name) {
        return {};
    }

    std::string subdomain;
    if (qname == *domain_name) {
        subdomain = "@";
    } else {
        size_t pos = qname.find(*domain_name);
        subdomain = qname.substr(0, pos - 1);
    }

    std::vector<Record> ret, domain_records = this->records[*domain_name];
    for (const auto& record : domain_records) {
        if (record.r_name != subdomain || record.r_type != qtype) {
            continue;
        }
        ret.push_back(record);
    }

    return filter(
        domain_records, [&subdomain, qtype, qclass](const Record& record) {
            return (record.r_name == subdomain && record.r_type == qtype &&
                    record.r_class == qclass);
        });
}
