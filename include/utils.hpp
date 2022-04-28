//
// Created by vladim0105 on 29.06.2021.
//

#ifndef DOMOS_TWAMP_LIGHT_TWAMP_LIGHT_HPP
#define DOMOS_TWAMP_LIGHT_TWAMP_LIGHT_HPP
#include <cstdint>
#include <sys/socket.h>
#include <fstream>
#include <random>
#include <vector>
#include <iterator>
#include <sstream>
#include "packets.h"

#define HDR_TTL		255         /* TTL=255 in TWAMP for IP Header */
#define SERVER_PORT 862
#define CHECK_TIMES 100

/* TWAMP timestamp is NTP time (RFC1305).
 * Should be in network byte order!      */
typedef struct ip_header {
    uint8_t ttl;
    uint8_t tos;
} IPHeader;


void timeval_to_timestamp(const struct timeval *tv, TWAMPTimestamp * ts);

void timestamp_to_timeval(const TWAMPTimestamp * ts, struct timeval *tv);

uint64_t timestamp_to_usec(const TWAMPTimestamp * ts);
uint64_t get_usec();
TWAMPTimestamp get_timestamp();

IPHeader get_ip_header(msghdr message);
void set_socket_options(int socket, uint8_t ip_ttl, uint8_t timeout_secs);
void set_socket_tos(int socket, uint8_t ip_tos);
template <class T>
std::string vectorToString(std::vector<T> vec, std::string sep){
    std::stringstream result;
    std::copy(vec.begin(), vec.end(), std::ostream_iterator<T>(result, sep.c_str()));
    return result.str().substr(0, result.str().size()-1);
}
template<typename Iter, typename RandomGenerator>
Iter select_randomly(Iter start, Iter end, RandomGenerator& g) {
    std::uniform_int_distribution<> dis(0, std::distance(start, end) - 1);
    std::advance(start, dis(g));
    return start;
}

template<typename Iter>
Iter select_randomly(Iter start, Iter end, uint32_t seed=0) {
    static std::random_device rd;
    static std::mt19937 gen(seed==0 ? rd() : seed);
    return select_randomly(start, end, gen);
}
uint64_t combine_uint32(uint32_t a, uint32_t b);
void split_uint64(uint64_t src, uint32_t& a, uint32_t& b);
#endif //DOMOS_TWAMP_LIGHT_TWAMP_LIGHT_HPP
