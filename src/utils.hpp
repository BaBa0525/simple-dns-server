#pragma once

#include <string>

inline void err_quit(const std::string &m) {
    perror(m.c_str());
    exit(1);
}

enum class LogLevel { DEBUG, INFO, WARNING, ERROR };

class Logger {
   private:
    LogLevel level;
    static Logger root_logger;

    Logger(LogLevel level = LogLevel::INFO) : level{level} {}

   public:
    Logger get() { return root_logger; };
    template <typename... Args>
    void info(const std::string &fmt, Args &&...args) {
        if (this->level > LogLevel::INFO) return;
        int size = snprintf(nullptr, 0, fmt.c_str(), args...);
    };
    void debug(const std::string &msg);
    void warning(const std::string &msg);
    void error(const std::string &msg);
};