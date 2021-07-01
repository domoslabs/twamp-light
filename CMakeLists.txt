cmake_minimum_required(VERSION 3.19)
project(domos_twamp_light)

# Downloads libfort and saves the source dir into the variable "libfort_SOURCE_DIR"
include(DownloadProject.cmake)
download_project(PROJ       libfort
        GIT_REPOSITORY      https://github.com/seleznevae/libfort.git
        GIT_TAG             master
        )

add_subdirectory(${libfort_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
set(CMAKE_CXX_STANDARD 14)
set(
        SOURCES
        include/twamp_light.h
        src/utils.cpp
)
add_executable(client src/client.cpp ${SOURCES})
add_executable(server src/server.cpp ${SOURCES})

# Disable building tests and examples in libfort project
set(FORT_ENABLE_TESTING OFF CACHE INTERNAL "")


target_link_libraries(client PRIVATE fort)
target_link_libraries(server PRIVATE fort)