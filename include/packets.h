//
// Created by vladim0105 on 12/17/21.
//

#ifndef TWAMP_LIGHT_PACKETS_H
#define TWAMP_LIGHT_PACKETS_H

#include <cstdint>
#include "Counter.h"

#define TST_PKT_SIZE 1472       //1472 (MTU 1514)
struct TWAMPTimestamp {
    uint32_t integer = 0;
    uint32_t fractional = 0;
};

/* Session-Sender TWAMP-Test packet for Unauthenticated mode */
struct ClientPacket {
    uint32_t seq_number = 0;
    TWAMPTimestamp send_time_data = {};
    uint16_t error_estimate = 0;
    uint8_t padding[TST_PKT_SIZE - 14];
};

/* Session-Reflector TWAMP-Test packet for Unauthenticated mode */
struct ReflectorPacket {
    uint32_t seq_number = 0;
    uint16_t error_estimate = 0;
    uint8_t mbz1[2] = {};
    TWAMPTimestamp server_time_data = {};
    TWAMPTimestamp client_time_data = {};
    uint32_t sender_seq_number = 0;
    TWAMPTimestamp send_time_data = {};
    uint16_t sender_error_estimate = 0;
    uint8_t mbz2[2] = {};
    uint8_t sender_ttl = 0;
    uint8_t sender_tos = 0;

    uint8_t padding[TST_PKT_SIZE - 42];
};
#endif //TWAMP_LIGHT_PACKETS_H
