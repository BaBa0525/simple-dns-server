#ifndef RECORD_HPP_
#define RECORD_HPP_

#include <string>
#include <vector>

class Record {
   public:
    enum Type {
        A = 1,
        NS = 2,
        CNAME = 5,
        SOA = 6,
        MX = 15,
        TXT = 16,
        AAAA = 28
    };
    enum Class { IN = 1, CS = 2, CH = 3, HS = 4 };

    std::string r_name;
    uint16_t r_type;
    uint16_t r_class;
    uint32_t r_ttl;
    uint16_t r_rdlength;
    std::vector<std::string> r_rdata;
};

#endif