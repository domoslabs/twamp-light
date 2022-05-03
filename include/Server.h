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
    bool sync_time = true;
};
struct MetricData {
    std::string ip;
    uint16_t sending_port= 0;
    uint16_t receiving_port = 0;
    uint16_t payload_length = 0;
    int64_t client_server_delay = 0;
    int64_t internal_delay = 0;
    uint64_t initial_send_time = 0;
    ReflectorPacket packet;
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
    void handleTestPacket(ClientPacket *packet, msghdr sender_msg, size_t payload_len);
    void printMetrics(const MetricData& data);
    ReflectorPacket craftReflectorPacket(ClientPacket *clientPacket, msghdr sender_msg);
};


#endif //TWAMP_LIGHT_SERVER_H
