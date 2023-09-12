//
// Created by vladim0105 on 12/15/21.
//

#ifndef TWAMP_LIGHT_CLIENT_H
#define TWAMP_LIGHT_CLIENT_H

#include <string>
#include <vector>
#include "utils.hpp"
#include "TimeSync.h"
extern "C" {
#include "simple-qoo.h"
}
struct Args {
    std::vector<std::string> remote_hosts;
    std::vector<uint16_t> remote_ports;
    std::string local_host;
    std::string local_port = "0";
    std::vector<int16_t> payload_lens = {50, 250, 450, 650, 850, 1050, 1250, 1400};
    uint8_t snd_tos = 0;
    uint8_t dscp_snd = 0;
    uint32_t num_samples = 10;
    uint32_t mean_inter_packet_delay = 200;
    uint8_t timeout = 10;
    uint32_t seed = 0;
    char sep = ',';
    bool sync_time = false;
    bool print_digest = false;
    bool print_RTT_only = false;
};
struct MetricData {
    std::string ip;
    uint16_t sending_port= 0;
    uint16_t receiving_port = 0;
    uint16_t payload_length = 0;
    int64_t client_server_delay = 0;
    int64_t server_client_delay = 0;
    int64_t internal_delay = 0;
    int64_t rtt_delay = 0;
    uint16_t packet_loss = 0;
    uint64_t initial_send_time = 0;
    ReflectorPacket packet;
    IPHeader  ipHeader;
};
class Client {
public:
    Client(const Args& args);
    ~Client();
    void sendPacket(uint32_t idx, size_t payload_len);
    bool awaitResponse(uint16_t packet_loss);
    void printStats(int packets_sent);
    

private:
    int fd = -1;
    bool header_printed = false;
    std::vector<struct addrinfo*> remote_address_info={};
    struct addrinfo* local_address_info= {};
    struct sqa_stats* stats_RTT = sqa_stats_create();
    struct sqa_stats* stats_internal = sqa_stats_create();
    struct sqa_stats* stats_client_server = sqa_stats_create();
    struct sqa_stats* stats_server_client = sqa_stats_create();
    time_t first_packet_sent = 0;
    time_t last_packet_sent = 0;
    Args args;
    TimeSynchronizer* timeSynchronizer = new TimeSynchronizer();
    ClientPacket craftSenderPacket(uint32_t idx);
    void printStat(const char* statName, sqa_stats* statType);

    void
    handleReflectorPacket(ReflectorPacket *reflectorPacket, msghdr msghdr, ssize_t payload_len, uint16_t packet_loss);

    template <typename Func>
    void
    printLine(const std::string& label, Func func);

    void
    printMetrics(const MetricData& data);
};


#endif //TWAMP_LIGHT_CLIENT_H
