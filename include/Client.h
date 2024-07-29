//
// Created by vladim0105 on 12/15/21.
//

#ifndef TWAMP_LIGHT_CLIENT_H
#define TWAMP_LIGHT_CLIENT_H

#include <string>
#include <vector>
#include <queue>
#include <semaphore.h>
#include "utils.hpp"
#include "TimeSync.h"
#include "packetlist.h"
extern "C" {
#include "simple-qoo.h"
}
struct Args {
    std::vector<std::string> remote_hosts;
    std::vector<uint16_t> remote_ports;
    std::string local_host;
    std::string local_port = "0";
    uint8_t ip_version = 4;
    std::vector<int16_t> payload_lens = {50, 250, 450, 650, 850, 1050, 1250, 1400};
    uint8_t snd_tos = 0;
    uint8_t dscp_snd = 0;
    uint32_t num_samples = 10;
    uint32_t mean_inter_packet_delay = 200;
    uint32_t timeout = 10;
    uint32_t seed = 0;
    uint32_t runtime = 0;
    char sep = ',';
    bool sync_time = false;
    bool print_digest = false;
    bool print_RTT_only = false;
    bool print_lost_packets = false;
    std::string print_format = "legacy";
    std::string json_output_file;
};

struct RawData {
    RawData *next;
    RawData *prev;
    uint64_t added_at_epoch_nanoseconds;
    uint32_t packet_id;
    uint16_t payload_len;
    uint64_t client_send_epoch_nanoseconds;
    uint64_t server_receive_epoch_nanoseconds;
    uint64_t server_send_epoch_nanoseconds;
    uint64_t client_receive_epoch_nanoseconds;
};
struct RawDataList {
    RawData *newest_entry;
    RawData *oldest_entry;
    uint32_t num_entries;
};

struct DelayData {
    uint32_t packet_id;
    uint16_t payload_len;
    uint64_t packet_generated_timestamp;
    uint64_t delay_to_server;
    uint64_t delay_to_server_response;
    uint64_t delay_round_trip;
};

struct MetricData {
    std::string ip;
    uint16_t sending_port = 0;
    uint16_t receiving_port = 0;
    uint16_t payload_length = 0;
    int64_t client_server_delay = 0;
    int64_t server_client_delay = 0;
    int64_t internal_delay = 0;
    int64_t rtt_delay = 0;
    uint64_t initial_send_time = 0;
    uint64_t packets_sent = 0;
    uint64_t packets_lost = 0;
    ReflectorPacket packet;
    IPHeader ipHeader;
};

class Client {
  public:
    Client(const Args &args);
    ~Client();
    Timestamp sendPacket(uint32_t idx, size_t payload_len);
    bool awaitAndHandleResponse();
    void printStats(int packets_sent);
    void printRawDataHeader();
    void aggregateRawData(RawData *oldest_raw_data);
    void runSenderThread();
    void runReceiverThread();
    void runCollatorThread();
    void enqueue_observation(struct qed_observation *obs);
    void process_observation(struct qed_observation *obs);
    void check_if_oldest_packet_should_be_processed();
    void print_lost_packet(uint32_t packet_id, uint64_t initial_send_time, uint16_t payload_len);
    int getSentPackets();
    void printHeader();
    void JsonLog(std::string filename);

  private:
    int fd = -1;
    int sent_packets = 0;
    int received_packets = 0;
    uint32_t last_received_packet_id = -1;
    uint64_t sending_completed = 0;
    uint64_t start_time = 0;
    int collator_started = 0;
    int collator_finished = 0;
    bool header_printed = false;
    sem_t observation_semaphore;
    pthread_mutex_t observation_list_mutex = PTHREAD_MUTEX_INITIALIZER;
    struct observation_list *observation_list;
    std::vector<struct addrinfo *> remote_address_info = {};
    struct addrinfo *local_address_info = {};
    struct sqa_stats *stats_RTT;
    struct sqa_stats *stats_internal;
    struct sqa_stats *stats_client_server;
    struct sqa_stats *stats_server_client;
    struct RawDataList *raw_data_list;
    uint64_t first_packet_sent_epoch_nanoseconds = 0;
    uint64_t last_packet_sent_epoch_nanoseconds = 0;
    uint64_t last_packet_received_epoch_nanoseconds = 0;
    Args args;
    TimeSynchronizer *timeSynchronizer = new TimeSynchronizer();
    ClientPacket craftSenderPacket(uint32_t idx);
    void printStat(const char *statName, sqa_stats *statType);

    void handleReflectorPacket(ReflectorPacket *reflectorPacket,
                               msghdr msghdr,
                               ssize_t payload_len,
                               timespec *incoming_timestamp);

    void printReflectorPacket(ReflectorPacket *reflectorPacket,
                              msghdr msghdr,
                              ssize_t payload_len,
                              uint64_t incoming_timestamp_nanoseconds,
                              struct sqa_stats *stats);

    template <typename Func> void printSummaryLine(const std::string &label, Func func);

    void printMetrics(const MetricData &data);
};

#endif // TWAMP_LIGHT_CLIENT_H
