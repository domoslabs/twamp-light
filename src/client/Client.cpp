//
// Created by vladim0105 on 12/15/21.
//

#include <netdb.h>
#include <cstring>
#include <stdlib.h>
#include <stdio.h>
#include <iostream>
#include <iomanip>
#include <unistd.h>
#include <arpa/inet.h>
#include <chrono>
#include <cstdint>
#include <ctime>
#include "Client.h"
#include "utils.hpp"
#include "json.hpp"

using Clock = std::chrono::system_clock;

Client::Client(const Args &args)
{
    this->args = args;
    // Construct remote socket address
    struct addrinfo hints {};
    memset(&hints, 0, sizeof(hints));
    if (args.ip_version == IPV4) {
        hints.ai_family = AF_INET;
    } else if (args.ip_version == IPV6) {
        hints.ai_family = AF_INET6;
    } else {
        std::cerr << "Invalid IP version." << std::endl;
        std::exit(EXIT_FAILURE);
    }
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = 0;
    hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG;
    // Resize the remote_address_info vector based on the number of remote hosts
    remote_address_info.resize(args.remote_hosts.size());
    int i = 0;
    for (const auto &remote_host : args.remote_hosts) {
        std::string port;
        try {
            // Convert port number to string
            port = std::to_string(args.remote_ports.at(i));
        } catch (std::out_of_range &e) {
            std::cerr << "Not enough remote ports provided" << std::endl;
            std::exit(EXIT_FAILURE);
        }
        int err = getaddrinfo(remote_host.c_str(), port.c_str(), &hints, &remote_address_info[i]);
        if (err != 0) {
            std::cerr << "failed to resolve remote socket address: " << err;
            std::exit(EXIT_FAILURE);
        }
        i++;
    }
    int err2 = getaddrinfo(args.local_host.empty() ? nullptr : args.local_host.c_str(),
                           args.local_port.c_str(),
                           &hints,
                           &local_address_info);
    if (err2 != 0) {
        std::cerr << "failed to resolve local socket address: " << err2;
        std::exit(EXIT_FAILURE);
    }
    // Create the socket
    fd = socket(remote_address_info[0]->ai_family,
                remote_address_info[0]->ai_socktype,
                remote_address_info[0]->ai_protocol);
    if (fd == -1) {
        std::cerr << strerror(errno) << std::endl;
        throw;
    }
    // Setup the socket options, to be able to receive TTL and TOS
    set_socket_options(fd, HDR_TTL, args.timeout);
    set_socket_tos(fd, args.snd_tos);
    // Bind the socket to a local port
    if (bind(fd, local_address_info->ai_addr, local_address_info->ai_addrlen) == -1) {
        std::cerr << strerror(errno) << std::endl;
        throw;
    }
    // Initialize the sent_packet_list
    observation_list = sent_packet_list_create();
    // Initialize the stats
    stats_RTT = sqa_stats_create();
    stats_internal = sqa_stats_create();
    stats_client_server = sqa_stats_create();
    stats_server_client = sqa_stats_create();
    // init the raw data array
    raw_data_list = new RawDataList();

    // Initialize the semaphore
    sem_init(&observation_semaphore, 0, 0);
}

Client::~Client()
{
    sqa_stats_destroy(stats_RTT);
    sqa_stats_destroy(stats_internal);
    sqa_stats_destroy(stats_client_server);
    sqa_stats_destroy(stats_server_client);
    for (auto &addrinfo : remote_address_info) {
        if (addrinfo != NULL) {
            freeaddrinfo(addrinfo);
        }
    }
    if (local_address_info != NULL) {
        freeaddrinfo(local_address_info);
    }
    free(observation_list);
    delete timeSynchronizer;
    delete raw_data_list;
    sem_destroy(&observation_semaphore);
}

std::string decode_observation_point(ObservationPoints observation_point)
{
    std::string retval;
    if (observation_point == ObservationPoints::CLIENT_SEND) {
        retval = "client_send_time";
    } else if (observation_point == ObservationPoints::SERVER_RECEIVE) {
        retval = "server_receive_time";
    } else if (observation_point == ObservationPoints::SERVER_SEND) {
        retval = "server_send_time";
    } else if (observation_point == ObservationPoints::CLIENT_RECEIVE) {
        retval = "client_receive_time";
    } else {
        retval = "unknown";
    }
    return retval;
}

struct qed_observation *make_qed_observation(ObservationPoints observation_point,
                                             uint64_t epoch_nanoseconds,
                                             uint32_t packet_id,
                                             uint16_t payload_len)
{
    struct qed_observation *obs = (struct qed_observation *) malloc(sizeof(struct qed_observation));
    obs->observation_point = observation_point;
    obs->epoch_nanoseconds = epoch_nanoseconds;
    obs->packet_id = packet_id;
    obs->payload_len = payload_len;
    return obs;
}

/* The packet generation function */
void Client::runSenderThread()
{
    uint32_t index = 0;
    std::random_device rd;  // Will be used to obtain a seed for the random number engine
    std::mt19937 gen(rd()); // Standard mersenne_twister_engine seeded with rd()
    std::exponential_distribution<> d(1.0 /
                                      (args.mean_inter_packet_delay * 1000)); // Lambda is 1.0/mean (in microseconds)
    while (args.num_samples == 0 || index < args.num_samples) {
        size_t payload_len = *select_randomly(args.payload_lens.begin(), args.payload_lens.end(), args.seed);
        int delay = std::max((double) std::min((double) d(gen), 10000000.0), 0.0);
        Timestamp sent_time = sendPacket(index, payload_len);
        if (first_packet_sent_epoch_nanoseconds == 0) {
            first_packet_sent_epoch_nanoseconds = timestamp_to_nsec(&sent_time);
        }
        last_packet_sent_epoch_nanoseconds = timestamp_to_nsec(&sent_time);
        struct qed_observation *obs =
            make_qed_observation(ObservationPoints::CLIENT_SEND, timestamp_to_nsec(&sent_time), index, payload_len);
        enqueue_observation(obs);
        index++;
        usleep(delay);
    }
    sent_packets = index;
    sending_completed = 1;
}

/* Receives and processes the reflected
    packets from the server side.*/
void Client::runReceiverThread()
{
    uint32_t index = 0;
    time_t time_of_last_received_packet = time(NULL);
    while ((args.num_samples == 0 || (sending_completed == 0 &&
            index < args.num_samples * args.remote_hosts.size() &&
             time(NULL) - time_of_last_received_packet <
                 args.timeout))) // run forever if num_samples is 0, otherwise run until num_samples is reached
    {
        bool response = awaitAndHandleResponse();
        if (response) {
            index++;
            time_of_last_received_packet = time(NULL);
        }
    }
}

// void Client::print_observation(struct qed_observation *obs) {
//     //Print all the observation info
//     std::cout << obs->epoch_nanoseconds << args.sep
//     << decode_observation_point(obs->observation_point) << args.sep
//     << obs->packet_id << args.sep
//     << obs->payload_len << "\n";
// }

void Client::process_observation(struct qed_observation *obs)
{

    // Look for the observation in the raw_data list
    RawData *entry = NULL;
    int made_new_entry = 0;
    struct RawData *current_entry = raw_data_list->oldest_entry;
    while (current_entry != NULL) {
        if (current_entry->packet_id == obs->packet_id) {
            // Found the entry
            entry = current_entry;
            break;
        }
        current_entry = current_entry->next;
    }
    if (entry == NULL) {
        // Didn't find the entry, so create a new one
        entry = new RawData();
        Timestamp now_ts = get_timestamp();
        entry->added_at_epoch_nanoseconds = timestamp_to_nsec(&now_ts);
        entry->packet_id = obs->packet_id;
        made_new_entry = 1;
        // Add the entry to the raw_data list
    }
    // Update the entry with the observation data
    entry->payload_len = obs->payload_len;
    switch (obs->observation_point) {
    case ObservationPoints::CLIENT_SEND:
        entry->client_send_epoch_nanoseconds = obs->epoch_nanoseconds;
        break;
    case ObservationPoints::SERVER_RECEIVE:
        entry->server_receive_epoch_nanoseconds = obs->epoch_nanoseconds;
        break;
    case ObservationPoints::SERVER_SEND:
        entry->server_send_epoch_nanoseconds = obs->epoch_nanoseconds;
        break;
    case ObservationPoints::CLIENT_RECEIVE:
        entry->client_receive_epoch_nanoseconds = obs->epoch_nanoseconds;
        break;
    default:
        break;
    }
    // If the entry is new, add it to the raw_data list
    if (made_new_entry > 0) {
        if (raw_data_list->oldest_entry == NULL) {
            // This is the first entry
            raw_data_list->newest_entry = entry;
            raw_data_list->oldest_entry = entry;
        } else {
            // Add the entry to the end of the list
            entry->prev = raw_data_list->newest_entry;
            raw_data_list->newest_entry->next = entry;
            raw_data_list->newest_entry = entry;
        }
        raw_data_list->num_entries++;
    }
}

void Client::check_if_oldest_packet_should_be_processed()
{
    // Check the timestamp on the oldest entry in raw_data and print it if it is old enough
    RawData *oldest_raw_data = raw_data_list->oldest_entry;
    Timestamp now = get_timestamp();
    uint64_t now_nanoseconds = timestamp_to_nsec(&now);
    int oldest_entry_is_complete = 0;
    if (oldest_raw_data != NULL && oldest_raw_data->client_send_epoch_nanoseconds > 0 &&
        oldest_raw_data->server_receive_epoch_nanoseconds > 0 && oldest_raw_data->server_send_epoch_nanoseconds > 0 &&
        oldest_raw_data->client_receive_epoch_nanoseconds > 0) {
        oldest_entry_is_complete = 1;
    }
    if (oldest_raw_data != NULL &&
        (oldest_entry_is_complete > 0 ||
         (now_nanoseconds - oldest_raw_data->added_at_epoch_nanoseconds) > args.timeout * 1000000000)) {
        // The oldest entry is old enough to be processed
        aggregateRawData(oldest_raw_data);

        if (args.print_format == "raw") {
            std::cout << oldest_raw_data->packet_id << args.sep << oldest_raw_data->payload_len << args.sep
                      << oldest_raw_data->client_send_epoch_nanoseconds << args.sep
                      << oldest_raw_data->server_receive_epoch_nanoseconds << args.sep
                      << oldest_raw_data->server_send_epoch_nanoseconds << args.sep
                      << oldest_raw_data->client_receive_epoch_nanoseconds << "\n";
        }
        // Remove the oldest entry from the raw_data list
        if (raw_data_list->num_entries > 0) {
            raw_data_list->oldest_entry = raw_data_list->oldest_entry->next;
            if (raw_data_list->oldest_entry != NULL) {
                // There is another entry after the oldest one
                raw_data_list->oldest_entry->prev = NULL;
            }
            if (raw_data_list->num_entries == 1) {
                // This was the last entry
                raw_data_list->newest_entry = NULL;
            }
            raw_data_list->num_entries--;
            delete oldest_raw_data;
        }
    }
    if (raw_data_list->num_entries == 0 && sending_completed == 1) {
        // All the packets have been sent and all the responses have been received or timed out
        // Close the thread
        collator_finished = 1;
    }
}

/* Processes observations recorded by the sender and the receiver */
void Client::runCollatorThread()
{
    // Consumes the observation queue and generates a table.
    // Uses semaphore to wake the thread only when there are observations to consume.
    while (collator_finished == 0) {
        struct qed_observation tmp_obs = {};
        struct qed_observation *tmp_obs_ptr = &tmp_obs;

        if (sem_trywait(&observation_semaphore) == 0) {
            pthread_mutex_lock(&observation_list_mutex);
            // Copy the observation data to tmp_obs
            memcpy(tmp_obs_ptr, observation_list->first->observation, sizeof(struct qed_observation));
            struct observation_list_entry *processed_entry = observation_list->first;
            observation_list->first = observation_list->first->next;
            free(processed_entry->observation);
            free(processed_entry);
            pthread_mutex_unlock(&observation_list_mutex);
            process_observation(tmp_obs_ptr);
            check_if_oldest_packet_should_be_processed();
        } else {
            check_if_oldest_packet_should_be_processed();
            usleep(100);
        }
    }
}

void Client::printRawDataHeader()
{
    // Print a header
    std::cout << "packet_id" << args.sep << "payload_len" << args.sep << "client_send_epoch_nanoseconds" << args.sep
              << "server_receive_epoch_nanoseconds" << args.sep << "server_send_epoch_nanoseconds" << args.sep
              << "client_receive_epoch_nanoseconds"
              << "\n";
    fflush(stdout);
}

int64_t calculate_correction(RawData **first_entry, RawData **last_entry)
{
    // Naive implementation that assumes no clock drift and symmetrical links
    int64_t min_fwd = INT64_MAX;
    int64_t min_bwd = INT64_MAX;
    RawData **current_entry = first_entry;
    while (current_entry <= last_entry) {
        RawData *entry = *current_entry;
        int64_t fwd = entry->server_receive_epoch_nanoseconds - entry->client_send_epoch_nanoseconds;
        if (fwd < min_fwd) {
            min_fwd = fwd;
        }
        int64_t bwd = entry->client_receive_epoch_nanoseconds - entry->server_send_epoch_nanoseconds;
        if (bwd < min_bwd) {
            min_bwd = bwd;
        }
        current_entry++;
    }
    // Calculate the correction. How must the server side clock change to make the min delays equal?
    uint64_t corrected_min_owd = (min_fwd + min_bwd) / 2;
    // If the server side clock is ahead of the client side clock, fwd will appear too large and bwd will appear too small.
    // If the server side clock is behind the client side clock, fwd will appear too small and bwd will appear too large.
    // The equation we need to solve is:
    // fwd = bwd = rtt/2
    // (server_receive + correction) - client_send = client_receive - (server_send + correction) = rtt/2
    int64_t correction = corrected_min_owd - min_fwd;
    return correction;
}

void Client::aggregateRawData(RawData *oldest_raw_data)
{
    // Compute the delays (without clock correction), and add them to the sqa_stats
    timespec client_server_delay = {};
    if (oldest_raw_data->client_send_epoch_nanoseconds > 0 && oldest_raw_data->server_receive_epoch_nanoseconds > 0) {
        client_server_delay = nanosecondsToTimespec(oldest_raw_data->server_receive_epoch_nanoseconds -
                                                    oldest_raw_data->client_send_epoch_nanoseconds);
        sqa_stats_add_sample(stats_client_server, &client_server_delay);
    }
    timespec server_client_delay = {};
    if (oldest_raw_data->server_send_epoch_nanoseconds > 0 && oldest_raw_data->client_receive_epoch_nanoseconds > 0 &&
        oldest_raw_data->server_receive_epoch_nanoseconds > 0 && oldest_raw_data->client_send_epoch_nanoseconds > 0) {
        server_client_delay = nanosecondsToTimespec(oldest_raw_data->client_receive_epoch_nanoseconds -
                                                    oldest_raw_data->server_send_epoch_nanoseconds);
        sqa_stats_add_sample(stats_server_client, &server_client_delay);
    } else {
        // We don't know where the packet was lost, so update all loss counters
        sqa_stats_count_loss(stats_client_server);
        sqa_stats_count_loss(stats_internal);
        sqa_stats_count_loss(stats_server_client);
        sqa_stats_count_loss(stats_RTT);
    }
    timespec internal_delay;
    timespec rtt_delay;

    tspecminus(&server_client_delay, &client_server_delay, &internal_delay);
    sqa_stats_add_sample(stats_internal, &internal_delay);

    tspecplus(&client_server_delay, &server_client_delay, &rtt_delay);
    sqa_stats_add_sample(stats_RTT, &rtt_delay);
}

int Client::getSentPackets()
{
    return sent_packets;
}

Timestamp Client::sendPacket(uint32_t idx, size_t payload_len)
{
    // Send the UDP packet
    ClientPacket senderPacket = craftSenderPacket(idx);
    struct iovec iov[1];
    iov[0].iov_base = &senderPacket;
    iov[0].iov_len = payload_len;
    for (const auto &rai : remote_address_info) {
        struct msghdr message = {};
        message.msg_name = rai->ai_addr;
        message.msg_namelen = rai->ai_addrlen;
        message.msg_iov = iov;
        message.msg_iovlen = 1;
        message.msg_control = nullptr;
        message.msg_controllen = 0;
        if (sendmsg(fd, &message, 0) == -1) {
            std::cerr << strerror(errno) << std::endl;
            throw std::runtime_error(std::string("Sending UDP message failed with error."));
        }
    }
    return ntohts(senderPacket.send_time_data);
}

ClientPacket Client::craftSenderPacket(uint32_t idx)
{
    ClientPacket packet = {};
    packet.seq_number = htonl(idx);
    packet.error_estimate = htons(0x8001); // Sync = 1, Multiplier = 1.
    if (args.sync_time) {
        uint32_t ts = TimeSynchronizer::LocalTimeToDatagramTS24(get_usec());
        uint32_t delta = timeSynchronizer->GetMinDeltaTS24().ToUnsigned();
        Timestamp send_time_data = {};
        send_time_data.integer = ts;
        send_time_data.fractional = delta;
        packet.send_time_data = htonts(send_time_data);
    } else {
        auto ts = get_timestamp();
        packet.send_time_data = htonts(ts);
    }
    return packet;
}

bool Client::awaitAndHandleResponse()
{
    // Read incoming datagram
    char buffer[sizeof(ReflectorPacket)]; // We should only be receiving ReflectorPackets
    char control[2048];
    struct sockaddr_in6 src_addr {};

    struct iovec iov;
    iov.iov_base = buffer;
    iov.iov_len = sizeof(buffer);

    timespec incoming_timestamp = {0,0};
    timespec *incoming_timestamp_ptr = &incoming_timestamp;

    struct msghdr incoming_msg = make_msghdr(&iov, 1, &src_addr, sizeof(src_addr), control, sizeof(control));

    ssize_t count = recvmsg(fd, &incoming_msg, MSG_WAITALL);
    get_kernel_timestamp(incoming_msg, incoming_timestamp_ptr);
    if (count == -1) {
        std::cerr << strerror(errno) << std::endl;
        return false;
    } else if (incoming_msg.msg_flags & MSG_TRUNC) {
        return false;
    } else {
        auto *rec = (ReflectorPacket *) buffer;
        handleReflectorPacket(rec, incoming_msg, count, incoming_timestamp_ptr);
    }
    return true;
}

struct TimeData {
    int64_t internal_delay;
    int64_t server_client_delay;
    int64_t client_server_delay;
    int64_t rtt;
    uint64_t client_send_time;
    uint64_t server_receive_time;
    uint64_t server_send_time;
};

TimeData computeTimeData(bool sync_time,
                         uint64_t client_receive_time,
                         ReflectorPacket *reflectorPacket,
                         TimeSynchronizer *timeSynchronizer)
{
    TimeData timeData;
    if (sync_time) {
        uint32_t server_timestamp = ntohl(reflectorPacket->server_time_data.integer);
        uint32_t server_delta = ntohl(reflectorPacket->server_time_data.fractional);
        uint32_t client_timestamp = ntohl(reflectorPacket->client_time_data.integer);

        int64_t server_client_delay =
            timeSynchronizer->OnAuthenticatedDatagramTimestamp(server_timestamp, client_receive_time);
        timeSynchronizer->OnPeerMinDeltaTS24(server_delta);

        auto a = timeSynchronizer->To64BitUSec(
            client_receive_time,
            timeSynchronizer->ToRemoteTime23(timeSynchronizer->To64BitUSec(client_receive_time, client_timestamp)));
        auto b = timeSynchronizer->To64BitUSec(client_receive_time, server_timestamp);
        int64_t client_server_delay = (int64_t) (b - a);

        timeData.client_send_time = timeSynchronizer->To64BitUSec(client_receive_time, client_timestamp);
        timeData.server_receive_time = timeSynchronizer->To64BitUSec(client_receive_time, server_timestamp);
        timeData.server_send_time =
            timeSynchronizer->To64BitUSec(client_receive_time, ntohl(reflectorPacket->send_time_data.integer));

        timeData.internal_delay = (int64_t) (timeData.server_send_time - timeData.server_receive_time);
        timeData.rtt = (int64_t) (client_receive_time - timeData.client_send_time);
        timeData.client_server_delay = client_server_delay;
        timeData.server_client_delay = server_client_delay;
    } else {
        auto client_timestamp = ntohts(reflectorPacket->client_time_data);
        auto server_timestamp = ntohts(reflectorPacket->server_time_data);
        auto send_timestamp = ntohts(reflectorPacket->send_time_data);

        timeData.client_send_time = timestamp_to_nsec(&client_timestamp);
        timeData.server_receive_time = timestamp_to_nsec(&server_timestamp);
        timeData.server_send_time = timestamp_to_nsec(&send_timestamp);

        timeData.internal_delay = timeData.server_send_time - timeData.server_receive_time;
        timeData.client_server_delay = timeData.server_receive_time - timeData.client_send_time;
        timeData.server_client_delay = client_receive_time - timeData.server_send_time;
        timeData.rtt = client_receive_time - timeData.client_send_time;
    }
    return timeData;
}

void populateMetricData(MetricData &data,
                        ReflectorPacket *reflectorPacket,
                        const IPHeader &ipHeader,
                        const std::string &host,
                        uint16_t local_port,
                        uint16_t port,
                        ssize_t payload_len,
                        TimeData &timeData)
{
    data.ip = host;
    data.sending_port = local_port;
    data.receiving_port = port;
    data.packet = *reflectorPacket;
    data.ipHeader = ipHeader;
    data.initial_send_time = timeData.client_send_time;
    data.payload_length = payload_len;
    data.internal_delay = timeData.internal_delay;
    data.server_client_delay = timeData.server_client_delay;
    data.client_server_delay = timeData.client_server_delay;
    data.rtt_delay = timeData.rtt;
}

void Client::enqueue_observation(struct qed_observation *obs)
{
    // Lock the receiver mutex
    pthread_mutex_lock(&observation_list_mutex);
    // Enqueue the observation in the FIFO
    struct observation_list_entry *entry =
        (struct observation_list_entry *) malloc(sizeof(struct observation_list_entry));
    entry->observation = obs;
    entry->next = NULL;
    if (observation_list->first == NULL) {
        observation_list->first = entry;
        observation_list->last = entry;
    } else {
        observation_list->last->next = entry;
        observation_list->last = entry;
    }
    // Unlock the receiver mutex
    pthread_mutex_unlock(&observation_list_mutex);
    sem_post(&observation_semaphore);
}

void Client::handleReflectorPacket(ReflectorPacket *reflectorPacket,
                                   msghdr msghdr,
                                   ssize_t payload_len,
                                   timespec *incoming_timestamp)
{
    Timestamp client_receive_time;
    uint64_t incoming_timestamp_nanoseconds = 0;
    if (incoming_timestamp->tv_sec == 0 && incoming_timestamp->tv_nsec == 0) {
        // If the kernel timestamp is not available, use the client receive time
        client_receive_time = get_timestamp();
        incoming_timestamp_nanoseconds = timestamp_to_nsec(&client_receive_time);
    } else {
        // Convert timespec to timestamp
        incoming_timestamp_nanoseconds = incoming_timestamp->tv_sec * 1000000000 + incoming_timestamp->tv_nsec;
    }
    last_packet_received_epoch_nanoseconds = incoming_timestamp_nanoseconds;

    Timestamp server_receive_time = ntohts(reflectorPacket->server_time_data);
    Timestamp server_send_time = ntohts(reflectorPacket->send_time_data);
    //IPHeader ipHeader = get_ip_header(msghdr);
    //uint8_t tos = ipHeader.tos;
    // sockaddr_in *sock = ((sockaddr_in *)msghdr.msg_name);
    // std::string host = inet_ntoa(sock->sin_addr);
    // uint16_t  port = ntohs(sock->sin_port);
    // uint16_t local_port = atoi(args.local_port.c_str());
    uint32_t packet_id = ntohl(reflectorPacket->seq_number);

    struct qed_observation *obs1 =
        make_qed_observation(ObservationPoints::CLIENT_RECEIVE, incoming_timestamp_nanoseconds, packet_id, payload_len);
    struct qed_observation *obs2 = make_qed_observation(ObservationPoints::SERVER_RECEIVE,
                                                        timestamp_to_nsec(&server_receive_time),
                                                        packet_id,
                                                        payload_len);
    struct qed_observation *obs3 = make_qed_observation(ObservationPoints::SERVER_SEND,
                                                        timestamp_to_nsec(&server_send_time),
                                                        packet_id,
                                                        payload_len);

    // Queue all observations in the FIFO to the collator
    enqueue_observation(obs3);
    enqueue_observation(obs2);
    enqueue_observation(obs1);
    if (args.print_format == "legacy") {
        printReflectorPacket(reflectorPacket, msghdr, payload_len, incoming_timestamp_nanoseconds);
    }
}

void Client::printReflectorPacket(ReflectorPacket *reflectorPacket,
                                  msghdr msghdr,
                                  ssize_t payload_len,
                                  uint64_t incoming_timestamp_nanoseconds)
{
    uint64_t client_receive_time = incoming_timestamp_nanoseconds;
    IPHeader ipHeader = get_ip_header(msghdr);
    char host[INET6_ADDRSTRLEN] = {0};
    uint16_t port;
    parse_ip_address(msghdr, &port, host, args.ip_version);
    uint16_t local_port = atoi(args.local_port.c_str());
    TimeData timeData = computeTimeData(args.sync_time, client_receive_time, reflectorPacket, timeSynchronizer);

    MetricData data;
    populateMetricData(data, reflectorPacket, ipHeader, host, local_port, port, payload_len, timeData);

    if (args.print_RTT_only) {
        std::cout << std::fixed << (double) timeData.rtt / 1e-6 << "\n";
        fflush(stdout);
    } else {
        printMetrics(data);
    }
}

void Client::printHeader()
{
    if (args.print_format == "legacy") {
        std::cout << "Time" << args.sep << "IP" << args.sep << "Snd#" << args.sep << "Rcv#" << args.sep << "SndPort"
                  << args.sep << "RscPort" << args.sep << "Sync" << args.sep << "FW_TTL" << args.sep << "SW_TTL"
                  << args.sep << "SndTOS" << args.sep << "FW_TOS" << args.sep << "SW_TOS" << args.sep << "RTT"
                  << args.sep << "IntD" << args.sep << "FWD" << args.sep << "BWD" << args.sep << "PLEN" << args.sep
                  << "LOSS"
                  << "\n";
        } else if (args.print_format == "raw") {
        std::cout << "packet_id" << args.sep << "payload_len" << args.sep << "client_send_epoch_nanoseconds" << args.sep
                  << "server_receive_epoch_nanoseconds" << args.sep << "server_send_epoch_nanoseconds" << args.sep
                  << "client_receive_epoch_nanoseconds"
                  << "\n";
    } else if (args.print_format == "clockcorrected") {
        std::cout << "packet_id" << args.sep << "payload_len" << args.sep << "packet_generated_timestamp" << args.sep
                  << "delay_to_server" << args.sep << "delay_to_server_response" << args.sep << "delay_round_trip"
                  << "\n";
    }
    fflush(stdout);
}

void Client::printMetrics(const MetricData &data)
{
    char sync = 'N';
    uint64_t estimated_rtt = data.client_server_delay + data.server_client_delay + data.internal_delay;
    if (isWithinEpsilon((double) data.rtt_delay * 1e-6, (double) estimated_rtt * 1e-6, 0.01)) {
        sync = 'Y';
    }
    if ((data.client_server_delay < 0) || (data.server_client_delay < 0)) {
        sync = 'N';
    }
    /*Sequence number */
    uint32_t rcv_sn = ntohl(data.packet.seq_number);
    uint32_t snd_sn = ntohl(data.packet.sender_seq_number);

    std::cout << std::fixed << data.initial_send_time << args.sep << data.ip << args.sep << snd_sn << args.sep << rcv_sn
              << args.sep << data.sending_port << args.sep << data.receiving_port << args.sep << sync << args.sep
              << unsigned(data.packet.sender_ttl) << args.sep << unsigned(data.ipHeader.ttl) << args.sep
              << unsigned(data.packet.sender_tos) << args.sep << '-' << args.sep << unsigned(data.ipHeader.tos)
              << args.sep << (double) data.rtt_delay * 1e-6 // Nanoseconds to milliseconds
              << args.sep << (double) data.internal_delay * 1e-6 << args.sep << (double) data.client_server_delay * 1e-6
              << args.sep << (double) data.server_client_delay * 1e-6 << args.sep << data.payload_length << args.sep
              << data.packet_loss << "\n";
    fflush(stdout);
}

void Client::print_lost_packet(uint32_t packet_id, uint64_t initial_send_time, uint16_t payload_len)
{
    std::cout << std::fixed << initial_send_time
              << args.sep
              //<< data.ip
              << args.sep << packet_id
              << args.sep
              //<< rcv_sn
              << args.sep
              //<< data.sending_port
              << args.sep
              //<< data.receiving_port
              << args.sep
              //<< sync
              << args.sep
              //<< unsigned(data.packet.sender_ttl)
              << args.sep
              //<< unsigned(data.ipHeader.ttl)
              << args.sep
              //<< unsigned(data.packet.sender_tos)
              << args.sep << '-'
              << args.sep
              //<< unsigned(data.ipHeader.tos)
              << args.sep
              //<<(double) data.rtt_delay * 1e-3
              << args.sep
              //<<(double) data.internal_delay* 1e-3
              << args.sep
              //<< (double) data.client_server_delay * 1e-3
              << args.sep
              //<< (double) data.server_client_delay * 1e-3
              << args.sep << payload_len
              << args.sep
              //<< data.packet_loss
              << "\n";
    fflush(stdout);
}

template <typename Func> void Client::printSummaryLine(const std::string &label, Func func)
{
    std::cout << " " << std::left << std::setw(10) << label << std::setprecision(6);
    std::cout << func(stats_RTT) << " s      ";
    std::cout << func(stats_client_server) << " s      ";
    std::cout << func(stats_server_client) << " s      ";
    std::cout << func(stats_internal) << " s\n";
    fflush(stdout);
}

void Client::printStats(int packets_sent)
{
    // printLostPackets();
    std::cout << std::fixed;
    std::cout
        << "Time spent generating packets: "
        << (double) (Client::last_packet_sent_epoch_nanoseconds - Client::first_packet_sent_epoch_nanoseconds) / 1e9
        << " s\n";
    Timestamp now_ts = get_timestamp();
    std::cout << "Total time elapsed: "
              << (double) (timestamp_to_nsec(&now_ts) - Client::first_packet_sent_epoch_nanoseconds) / 1e9 << " s\n";
    std::cout << "Packets sent: " << packets_sent << "\n";
    std::cout << "Packets lost: " << sqa_stats_get_number_of_lost_packets(Client::stats_RTT) << "\n";
    std::cout << "Packet loss: " << sqa_stats_get_loss_percentage(Client::stats_RTT) << "%\n";
    std::cout << "           RTT             FWD             BWD             Internal\n";
    fflush(stdout);

    auto printPercentileLine = [&](const std::string &label, double percentile) {
        std::cout << " " << std::left << std::setw(10) << label << std::setprecision(6);
        std::cout << sqa_stats_get_percentile(Client::stats_RTT, percentile) << " s      ";
        std::cout << sqa_stats_get_percentile(Client::stats_client_server, percentile) << " s      ";
        std::cout << sqa_stats_get_percentile(Client::stats_server_client, percentile) << " s      ";
        std::cout << sqa_stats_get_percentile(Client::stats_internal, percentile) << " s\n";
        fflush(stdout);
    };

    printSummaryLine("mean:", sqa_stats_get_mean);
    printSummaryLine("median:", sqa_stats_get_median);
    printSummaryLine("min:", sqa_stats_get_min_as_seconds);
    printSummaryLine("max:", sqa_stats_get_max_as_seconds);
    printSummaryLine("std:", sqa_stats_get_standard_deviation);
    printSummaryLine("variance:", sqa_stats_get_variance);
    printPercentileLine("p95:", 95);
    printPercentileLine("p99:", 99);
    printPercentileLine("p99.9:", 99.9);
}

nlohmann::json td_to_json(td_histogram_t *histogram)
{
    nlohmann::json json;
    td_compress(histogram);
    json["compression"] = histogram->compression;

    // Create the digest-centroid array
    nlohmann::json centroidsJson = nlohmann::json::array();
    for (int i = 0; i < histogram->merged_nodes; ++i) {
        centroidsJson.push_back({{"m", histogram->nodes_mean[i]}, {"c", histogram->nodes_weight[i]}});
    }

    json["digest-centroid"] = centroidsJson;
    return json;
}

std::string map_tos_to_traffic_class(uint8_t tos)
{
    switch (tos) {
    case 0x00:
        return "BE";
    case 0x20:
        return "BK";
    case 0x80:
        return "VI";
    case 0xA0:
        return "VO";
    default:
        return "Unknown";
    }
}

void Client::JsonLog(std::string json_output_file)
{
    nlohmann::json logData;
    time_t first_sent_seconds = Client::first_packet_sent_epoch_nanoseconds / 1e9;
    int microseconds = Client::first_packet_sent_epoch_nanoseconds % 1000000000;
    auto now_as_tm_date = std::gmtime(&first_sent_seconds);
    char first_packet_sent_date[80];
    strftime(first_packet_sent_date, sizeof(first_packet_sent_date), "%Y-%m-%dT%H:%M:%S", now_as_tm_date);
    // Add the microseconds back in:
    char first_packet_sent_date_with_microseconds[91];
    sprintf(first_packet_sent_date_with_microseconds, "%s.%06dZ", first_packet_sent_date, microseconds);
    long duration_nanoseconds =
        (Client::last_packet_received_epoch_nanoseconds - Client::first_packet_sent_epoch_nanoseconds);
    double duration = duration_nanoseconds / 1e9;
    // Describe the sampling pattern
    nlohmann::json samplingpattern;
    samplingpattern["type"] = "Erlang-k";
    samplingpattern["k"] = 1;
    samplingpattern["mean"] = args.mean_inter_packet_delay / 1000.0;
    samplingpattern["min"] = 0;
    samplingpattern["max"] = 10.0;
    logData["sampling_pattern"] = samplingpattern;
    // Describe the packet size distribution
    logData["packet_sizes"] = nlohmann::json::array();
    for (const auto &payload_len : args.payload_lens) {
        logData["packet_sizes"].push_back(payload_len);
    }
    logData["traffic_class"] = map_tos_to_traffic_class(args.snd_tos);

    // Describe the observation points
    logData["intermediate_nodes"] = nlohmann::json::array();
    logData["start_node"] = {{"ip", "localhost"}, {"port", args.local_port}};
    // Loop through the list of remote hosts and ports
    for (uint32_t i = 0; i < args.remote_hosts.size(); ++i) {
        logData["intermediate_nodes"].push_back(
            {{"ip", args.remote_hosts[i]}, {"port", args.remote_ports[i]}, {"label", "1"}});
        logData["intermediate_nodes"].push_back(
            {{"ip", args.remote_hosts[i]}, {"port", args.remote_ports[i]}, {"label", "2"}});
    }
    logData["end_node"] = {{"ip", "localhost"}, {"port", args.local_port}};

    logData["version"] = "0.1";
    logData["qualityattenuationaggregate"] = {
        {"t0", first_packet_sent_date_with_microseconds},
        {"duration", duration},
        {"num_samples", sqa_stats_get_number_of_samples(Client::stats_RTT)},
        {"num_lost_samples", sqa_stats_get_number_of_lost_packets(Client::stats_RTT)},
        {"max", sqa_stats_get_max_as_seconds(Client::stats_RTT)},
        {"min", sqa_stats_get_min_as_seconds(Client::stats_RTT)},
        {"mean", sqa_stats_get_mean(Client::stats_RTT)},
        {"variance", sqa_stats_get_variance(Client::stats_RTT)},
        {"empirical_distribution", td_to_json(Client::stats_RTT->empirical_distribution)},
    };

    // Dump data to file
    std::ofstream file(json_output_file);
    file << std::setw(4) << logData << std::endl;
    file.close();
}

struct observation_list *sent_packet_list_create()
{
    struct observation_list *res = (struct observation_list *) malloc(sizeof(struct observation_list));
    res->first = NULL;
    res->last = NULL;
    return res;
}

void sent_packet_list_destroy(struct observation_list *spl)
{
    struct observation_list_entry *next = NULL;
    struct observation_list_entry *first = spl->first;
    while (first != NULL) {
        next = first->next;
        free(first);
        first = next;
    }
}

void remove_packet(struct observation_list_entry *packet,
                   struct observation_list_entry *prev_packet,
                   struct observation_list *spl)
{
    if (packet->next == NULL && prev_packet == NULL) {
        // list now empty
        spl->first = NULL;
        spl->last = NULL;
    } else if (prev_packet == NULL) {
        // We're removing the first entry in the list
        spl->first = packet->next;
    } else if (packet->next == NULL) {
        // We're removing the entry at the end of the list
        prev_packet->next = NULL;
        spl->last = prev_packet;
    } else {
        // We're removing an entry in the middle of the list
        prev_packet->next = packet->next;
    }
}