//
// Created by vladim0105 on 12/15/21.
//

#ifndef TWAMP_LIGHT_CLIENT_H
#define TWAMP_LIGHT_CLIENT_H

#include <string>
#include <vector>
#include "utils.hpp"

struct Args {
    std::string remote_host;
    std::string remote_port = "443";
    std::string local_host;
    std::string local_port = "445";
    std::vector<uint16_t> payload_lens = std::vector<uint16_t>();
    uint8_t snd_tos = 0;
    uint8_t dscp_snd = 0;
    std::vector<uint16_t> delays = std::vector<uint16_t>();;
    uint32_t num_samples = 10;
    uint8_t timeout = 10;
    uint8_t max_retries = 10;
    uint32_t seed = 0;
};
class Client {
public:
    Client(const Args& args);
    void sendPacket(int idx, size_t payload_len);
    bool awaitResponse(size_t payload_len, uint16_t packet_loss, const Args &args);

private:
    int fd = -1;
    bool header_printed = false;
    struct addrinfo* remote_address_info={};
    struct addrinfo* local_address_info= {};
    SenderPacket craftSenderPacket(int idx);

    void
    handleReflectorPacket(ReflectorPacket *reflectorPacket, msghdr msghdr, size_t payload_len, uint16_t packet_loss,
                          const Args &args);

    uint64_t
    printMetrics(const char *server, uint16_t snd_port, uint16_t rcv_port, uint8_t snd_tos, uint8_t sw_ttl,
                 uint8_t sw_tos,
                 TWAMPTimestamp *recv_resp_time, const ReflectorPacket *pack, uint16_t plen, uint16_t packets_lost);
};


#endif //TWAMP_LIGHT_CLIENT_H
