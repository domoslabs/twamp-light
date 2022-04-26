//
// Created by vladim0105 on 12/17/21.
//

#ifndef TWAMP_LIGHT_SERVER_H
#define TWAMP_LIGHT_SERVER_H

#include <string>
#include "utils.hpp"
#include "TimeSync.h"

struct Args{
    std::string local_host;
    std::string local_port = "443";
    uint32_t num_samples = 0;
    uint8_t timeout = 10;
};
class Server {
public:
    Server(const Args& args);
    void listen();
private:
    int fd;
    bool header_printed = false;
    TimeSynchronizer* timeSynchronizer = new TimeSynchronizer();
    Args args;
    void handleTestPacket(SenderPacket *packet, msghdr sender_msg, size_t payload_len);
    void printMetrics(const char *addr_cl, uint16_t snd_port, uint16_t rcv_port, uint8_t snd_tos, uint8_t fw_tos, uint16_t plen, const ReflectorPacket *pack);
    ReflectorPacket craftReflectorPacket(SenderPacket *sender_packet, msghdr sender_msg);
};


#endif //TWAMP_LIGHT_SERVER_H
