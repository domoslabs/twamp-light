cmake_minimum_required(VERSION 3.0)
project(twamp-light)
set(CMAKE_CXX_STANDARD 11)
set(
        COMMON_SOURCES
        include/utils.hpp
        include/CLI11.hpp
        src/utils.cpp
)
set(
        CLIENT_TARGET
        twamp-light-client
)
set(
        SERVER_TARGET
        twamp-light-server
)


include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

add_executable(${CLIENT_TARGET} src/Client.cpp include/Client.h src/main_client.cpp ${COMMON_SOURCES})
add_executable(${SERVER_TARGET} src/server.cpp ${COMMON_SOURCES})

install(TARGETS twamp-light-client twamp-light-server)