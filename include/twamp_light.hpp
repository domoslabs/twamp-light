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

#define HDR_TTL		255         /* TTL=255 in TWAMP for IP Header */
#define SERVER_PORT 862
#define CHECK_TIMES 100

/* TWAMP timestamp is NTP time (RFC1305).
 * Should be in network byte order!      */
typedef struct twamp_timestamp {
    uint32_t integer;
    uint32_t fractional;
} TWAMPTimestamp;
typedef struct ip_header {
    uint8_t ttl;
    uint8_t tos;
} IPHeader;
#define TST_PKT_SIZE 1472       //1472 (MTU 1514)
/* Session-Sender TWAMP-Test packet for Unauthenticated mode */
typedef struct test_packet {
    uint32_t seq_number;
    TWAMPTimestamp time;
    uint16_t error_estimate;
    uint8_t padding[TST_PKT_SIZE - 14];
} SenderPacket;

/* Session-Reflector TWAMP-Test packet for Unauthenticated mode */
typedef struct reflector_unauth_packet {
    uint32_t seq_number;
    TWAMPTimestamp time;
    uint16_t error_estimate;
    uint8_t mbz1[2];
    TWAMPTimestamp receive_time;
    uint32_t sender_seq_number;
    TWAMPTimestamp sender_time;
    uint16_t sender_error_estimate;
    uint8_t mbz2[2];
    uint8_t sender_ttl;
    uint8_t sender_tos;
    uint8_t padding[TST_PKT_SIZE - 42];
} ReflectorPacket;

void timeval_to_timestamp(const struct timeval *tv, TWAMPTimestamp * ts);

void timestamp_to_timeval(const TWAMPTimestamp * ts, struct timeval *tv);

uint64_t get_usec(const TWAMPTimestamp * ts);

TWAMPTimestamp get_timestamp();

IPHeader get_ip_header(msghdr message);

uint64_t
print_metrics(const char *server, uint16_t snd_port, uint16_t rcv_port, uint8_t snd_tos, uint8_t sw_ttl, uint8_t sw_tos,
              TWAMPTimestamp *recv_resp_time, const ReflectorPacket *pack, uint16_t plen, char *device_mac,
              char *radio_interface);

void print_metrics_server(const char *addr_cl, uint16_t snd_port, uint16_t rcv_port,
                          uint8_t snd_tos, uint8_t fw_tos, uint16_t plen,
                          const ReflectorPacket * pack);
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
#endif //DOMOS_TWAMP_LIGHT_TWAMP_LIGHT_HPP
