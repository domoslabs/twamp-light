//
// Created by vladim0105 on 12/17/21.
//

#ifndef TWAMP_LIGHT_PACKETS_H
#define TWAMP_LIGHT_PACKETS_H

#include <cstdint>
#include "Counter.h"

#define TST_PKT_SIZE 1472       //1472 (MTU 1514)
struct TWAMPTimestamp {
    uint32_t integer;
    uint32_t fractional;
};

/* Session-Sender TWAMP-Test packet for Unauthenticated mode */
struct ClientPacket {
    uint32_t seq_number;
    Counter24 timestamp;
    Counter24 min_delta;
    uint16_t error_estimate;
    uint8_t padding[TST_PKT_SIZE - 14 - sizeof(Counter24)];
};

/* Session-Reflector TWAMP-Test packet for Unauthenticated mode */
struct ReflectorPacket {
    uint32_t seq_number;
    uint16_t error_estimate;
    uint8_t mbz1[2];
    Counter24 server_timestamp;
    Counter24 server_min_delta;
    Counter24 client_timestamp;
    Counter24 client_min_delta;
    uint32_t sender_seq_number;
    Counter24 send_timestamp;
    Counter24 send_delta;
    uint16_t sender_error_estimate;
    uint8_t mbz2[2];
    uint8_t sender_ttl;
    uint8_t sender_tos;

    uint8_t padding[TST_PKT_SIZE - 42];
};
#endif //TWAMP_LIGHT_PACKETS_H
