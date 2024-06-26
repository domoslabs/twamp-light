cmake_minimum_required(VERSION 3.0)
project(twamp-light)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -Wextra -Wall -Werror")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -Wextra -Wall -Werror")
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -Wextra -Wall -O0 -g")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -Wextra -Wall -O0 -g")
# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wno-psabi" )
# set(CMAKE_CXX_FLAGS_RELEASE "-Werror -O2")
include(cmake/getversion.cmake)

option(SYSTEMD_UNIT "Include Systemd unit in install" ON)
option(USE_ASAN "Build with address-sanitizer" OFF)
option(RUN_TESTS "Build and run tests" ON)
option(USE_LEGACY_TIMESTAMP_IN_CLIENT "Build without NIC timestamping in the client" OFF)
if (USE_LEGACY_TIMESTAMP_IN_CLIENT)
  add_definitions(-DKERNEL_TIMESTAMP_DISABLED_IN_CLIENT)
endif ()

if (RUN_TESTS)
  enable_testing()
endif ()

if (USE_ASAN)
  string( TOLOWER "${CMAKE_BUILD_TYPE}" buildtype_lower)
  if (NOT buildtype_lower STREQUAL "debug" )
    message(FATAL_ERROR "USE_ASAN=ON and CMAKE_BUILD_TYPE != Debug")
  endif()
  add_definitions(-fsanitize=address -static-libasan -fno-omit-frame-pointer)
  set(EXTRA_LIBS ${EXTRA_LIBS} -fsanitize=address)
endif ()

find_package (Threads)

add_subdirectory(qoo-c)

set(COMMON_SOURCES
        include/utils.hpp
        include/CLI11.hpp
        src/utils.cpp
        include/packets.h
        src/TimeSync.cpp
        include/TimeSync.h
        include/Counter.h
        include/json.hpp
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

target_link_libraries(${CLIENT_TARGET} PRIVATE qoo_static ${EXTRA_LIBS} Threads::Threads)
target_link_libraries(${SERVER_TARGET} PRIVATE ${EXTRA_LIBS})
target_include_directories(
        ${CLIENT_TARGET} PRIVATE
)

find_program (BASH_PROGRAM bash)
if (BASH_PROGRAM)
        add_test (NAME test_output 
                COMMAND ${BASH_PROGRAM} ${CMAKE_CURRENT_SOURCE_DIR}/tests/test.sh)
        add_test (NAME test_output_ipv6 
                COMMAND ${BASH_PROGRAM} ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_ipv6.sh)        
        add_test (NAME test_memory 
                COMMAND ${BASH_PROGRAM} ${CMAKE_CURRENT_SOURCE_DIR}/tests/valgrind_test.sh)
        add_test (NAME test_memory_ipv6 
                COMMAND ${BASH_PROGRAM} ${CMAKE_CURRENT_SOURCE_DIR}/tests/valgrind_test_ipv6.sh)
endif()
        
install(TARGETS ${CLIENT_TARGET} ${SERVER_TARGET} 
        RUNTIME DESTINATION bin)

if (SYSTEMD_UNIT) 
	install(FILES systemd/twamp-light-server.service DESTINATION /lib/systemd/system) 
endif()
