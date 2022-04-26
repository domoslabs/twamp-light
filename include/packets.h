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
struct SenderPacket {
    uint32_t seq_number;
    TWAMPTimestamp time;
    uint16_t error_estimate;
    Counter24 sync_timestamp;
    uint8_t padding[TST_PKT_SIZE - 14 - sizeof(Counter24)];
};

/* Session-Reflector TWAMP-Test packet for Unauthenticated mode */
struct ReflectorPacket {
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
    Counter24 sync_timestamp;
    Counter24 sync_min_delta;
    uint8_t padding[TST_PKT_SIZE - 42 - sizeof(Counter24)*2];
};
#endif //TWAMP_LIGHT_PACKETS_H
