# Copyright(c) 2019 spdlog authors Distributed under the MIT License (http://opensource.org/licenses/MIT)

cmake_minimum_required(VERSION 3.10)
project(dns_server CXX)

if(NOT TARGET spdlog)
    # Stand-alone build
    find_package(spdlog REQUIRED)
endif()

set(SRC "main.cpp")
set(TARGET "main")

add_executable(${TARGET} ${SRC})
target_link_libraries(${TARGET} PRIVATE spdlog::spdlog_header_only)