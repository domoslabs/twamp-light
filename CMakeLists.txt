cmake_minimum_required(VERSION 3.0)
project(twamp-light)

set(CMAKE_CXX_STANDARD 14)

add_subdirectory(qoo-c)

set(COMMON_SOURCES
        include/utils.hpp
        include/CLI11.hpp
        src/utils.cpp
        include/packets.h
        src/TimeSync.cpp
        include/TimeSync.h
        include/Counter.h
)

set(CLIENT_TARGET twamp-light-client)
set(SERVER_TARGET twamp-light-server)


include_directories(
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/qoo-c/src
        ${CMAKE_CURRENT_SOURCE_DIR}/qoo-c/t-digest-c/src
)

add_executable(${CLIENT_TARGET}
src/client/Client.cpp
include/Client.h
src/client/main_client.cpp
${COMMON_SOURCES}
)

add_executable(${SERVER_TARGET}
src/server/Server.cpp
include/Server.h
src/server/main_server.cpp
${COMMON_SOURCES}
)

target_link_libraries(${CLIENT_TARGET} PRIVATE qoo)
target_include_directories(
        ${CLIENT_TARGET} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/qoo-c/src
        ${CMAKE_CURRENT_SOURCE_DIR}/qoo-c/t-digest-c/src
)

install(TARGETS ${CLIENT_TARGET} ${SERVER_TARGET})
