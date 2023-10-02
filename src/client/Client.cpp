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
#include "Client.h"
#include "utils.hpp"


Client::Client(const Args& args) {
    this->args = args;
    // Construct remote socket address
    struct addrinfo hints{};
    memset(&hints,0,sizeof(hints));
    hints.ai_family=AF_INET; //TODO IPv6
    hints.ai_socktype=SOCK_DGRAM;
    hints.ai_protocol=0;
    hints.ai_flags=AI_PASSIVE|AI_ADDRCONFIG;
    // Resize the remote_address_info vector based on the number of remote hosts
    remote_address_info.resize(args.remote_hosts.size());
    int i = 0;
    for (const auto& remote_host : args.remote_hosts) {
        std::string port;
        try {
            // Convert port number to string
            port = std::to_string(args.remote_ports.at(i));
        } catch (std::out_of_range& e) {
            std::cerr << "Not enough remote ports provided" << std::endl;
            std::exit(EXIT_FAILURE);
        }
        int err=getaddrinfo(remote_host.c_str(), port.c_str(), &hints, &remote_address_info[i]);
        if (err!=0) {
            std::cerr << "failed to resolve remote socket address: " << err;
            std::exit(EXIT_FAILURE);
        }
        i++;
    }
    int err2=getaddrinfo(args.local_host.empty()? nullptr : args.local_host.c_str(), args.local_port.c_str(),&hints,&local_address_info);
    if (err2!=0) {
        std::cerr << "failed to resolve local socket address: " << err2;
        std::exit(EXIT_FAILURE);
    }
    // Create the socket
    fd=socket(remote_address_info[0]->ai_family, remote_address_info[0]->ai_socktype, remote_address_info[0]->ai_protocol);
    if (fd==-1) {
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
}

Client::~Client() {
    sqa_stats_destroy(stats_RTT);
    sqa_stats_destroy(stats_internal);
    sqa_stats_destroy(stats_client_server);
    sqa_stats_destroy(stats_server_client);
    for( auto& addrinfo : remote_address_info) {
        if (addrinfo!=NULL) {
            freeaddrinfo(addrinfo);
        }
    }
    if (local_address_info!=NULL) {
        freeaddrinfo(local_address_info);
    }
    delete timeSynchronizer;
}


void Client::runSenderThread() {
    uint32_t index = 0;
    std::random_device rd;  //Will be used to obtain a seed for the random number engine
    std::mt19937 gen(rd()); //Standard mersenne_twister_engine seeded with rd()
    std::exponential_distribution<> d(1.0/(args.mean_inter_packet_delay*1000)); //Lambda is 1.0/mean (in microseconds)
    while (args.num_samples == 0 || index < args.num_samples) {
        size_t payload_len = *select_randomly(args.payload_lens.begin(), args.payload_lens.end(), args.seed);
        int delay = std::max((double)std::min((double)d(gen), 10000000.0), 0.0);
        sendPacket(index, payload_len);
        index++;
        usleep(delay);
    }
    sent_packets = index;
}

int Client::getSentPackets() {
    return sent_packets;
}

void Client::sendPacket(uint32_t idx, size_t payload_len) {
    // Send the UDP packet
    for (const auto& rai : remote_address_info) {
        ClientPacket senderPacket = craftSenderPacket(idx);
        struct iovec iov[1];
        iov[0].iov_base=&senderPacket;
        iov[0].iov_len=payload_len;
        struct msghdr message = {};
        message.msg_name=rai->ai_addr;
        message.msg_namelen=rai->ai_addrlen;
        message.msg_iov=iov;
        message.msg_iovlen=1;
        message.msg_control= nullptr;
        message.msg_controllen=0;
        if (sendmsg(fd,&message,0)==-1) {
            std::cerr << strerror(errno) << std::endl;
            throw std::runtime_error(std::string("Sending UDP message failed with error."));
        }
    }
}

ClientPacket Client::craftSenderPacket(uint32_t idx){
    ClientPacket packet = {};
    packet.seq_number = htonl(idx);
    packet.error_estimate = htons(0x8001); // Sync = 1, Multiplier = 1.
    if(args.sync_time){
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

bool Client::awaitResponse(uint16_t packet_loss) {
    // Read incoming datagram
    char buffer[sizeof(ReflectorPacket)]; //We should only be receiving ReflectorPackets
    struct sockaddr src_addr{};

    struct iovec iov[1];
    iov[0].iov_base=buffer;
    iov[0].iov_len=sizeof(buffer);

    struct msghdr incoming_msg{};
    incoming_msg.msg_name=&src_addr;
    incoming_msg.msg_namelen=sizeof(src_addr);
    incoming_msg.msg_iov=iov;
    incoming_msg.msg_iovlen=1;
    incoming_msg.msg_control= nullptr;
    incoming_msg.msg_controllen=0;
    ssize_t count=recvmsg(fd, &incoming_msg, MSG_WAITALL);
    if (count==-1) {
        if(errno == 11){
            return false;
        } else {
            std::cerr << strerror(errno) << std::endl;
            return false;
        }
    } else if (incoming_msg.msg_flags & MSG_TRUNC) {
        return false;
    } else {
        auto *rec = (ReflectorPacket *)buffer;
        handleReflectorPacket(rec, incoming_msg, count, packet_loss);
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

TimeData computeTimeData(bool sync_time, uint64_t client_receive_time, ReflectorPacket *reflectorPacket, TimeSynchronizer* timeSynchronizer) {
    TimeData timeData;
    if(sync_time) {
        uint32_t server_timestamp = ntohl(reflectorPacket->server_time_data.integer);
        uint32_t server_delta = ntohl(reflectorPacket->server_time_data.fractional);
        uint32_t client_timestamp = ntohl(reflectorPacket->client_time_data.integer);

        int64_t server_client_delay = timeSynchronizer->OnAuthenticatedDatagramTimestamp(server_timestamp, client_receive_time);
        timeSynchronizer->OnPeerMinDeltaTS24(server_delta);

        auto a = timeSynchronizer->To64BitUSec(client_receive_time, timeSynchronizer->ToRemoteTime23(timeSynchronizer->To64BitUSec(client_receive_time, client_timestamp)));
        auto b = timeSynchronizer->To64BitUSec(client_receive_time, server_timestamp);
        int64_t client_server_delay = (int64_t)(b - a);

        timeData.client_send_time = timeSynchronizer->To64BitUSec(client_receive_time, client_timestamp);
        timeData.server_receive_time = timeSynchronizer->To64BitUSec(client_receive_time, server_timestamp);
        timeData.server_send_time = timeSynchronizer->To64BitUSec(client_receive_time, ntohl(reflectorPacket->send_time_data.integer));

        timeData.internal_delay = (int64_t)(timeData.server_send_time - timeData.server_receive_time);
        timeData.rtt = (int64_t)(client_receive_time - timeData.client_send_time);
        timeData.client_server_delay = client_server_delay;
        timeData.server_client_delay = server_client_delay;
    } else {
        auto client_timestamp = ntohts(reflectorPacket->client_time_data);
        auto server_timestamp = ntohts(reflectorPacket->server_time_data);
        auto send_timestamp = ntohts(reflectorPacket->send_time_data);

        timeData.client_send_time = timestamp_to_usec(&client_timestamp);
        timeData.server_receive_time = timestamp_to_usec(&server_timestamp);
        timeData.server_send_time = timestamp_to_usec(&send_timestamp);

        timeData.internal_delay = timeData.server_send_time - timeData.server_receive_time;
        timeData.client_server_delay = timeData.server_receive_time - timeData.client_send_time;
        timeData.server_client_delay = client_receive_time - timeData.server_send_time;
        timeData.rtt = client_receive_time - timeData.client_send_time;
    }
    return timeData;
}

void populateMetricData(MetricData &data, ReflectorPacket *reflectorPacket, const IPHeader &ipHeader, const std::string &host, uint16_t local_port, uint16_t port, ssize_t payload_len, uint16_t packet_loss, TimeData &timeData) {
    data.ip = host;
    data.sending_port = local_port;
    data.receiving_port = port;
    data.packet = *reflectorPacket;
    data.ipHeader = ipHeader;
    data.initial_send_time = timeData.client_send_time;
    data.payload_length = payload_len;
    data.packet_loss = packet_loss;
    data.internal_delay = timeData.internal_delay;
    data.server_client_delay = timeData.server_client_delay;
    data.client_server_delay = timeData.client_server_delay;
    data.rtt_delay = timeData.rtt;
}

struct timespec convertToTimespec(int64_t delay) {
    struct timespec ts;
    ts.tv_sec = delay / 1000000;
    ts.tv_nsec = (delay % 1000000) * 1000;
    return ts;
}

void Client::handleReflectorPacket(ReflectorPacket *reflectorPacket, msghdr msghdr, ssize_t payload_len, uint16_t packet_loss) {
    IPHeader ipHeader = get_ip_header(msghdr);
    sockaddr_in *sock = ((sockaddr_in *)msghdr.msg_name);
    std::string host = inet_ntoa(sock->sin_addr);
    uint16_t local_port = atoi(args.local_port.c_str());
    uint16_t  port = ntohs(sock->sin_port);
    uint64_t client_receive_time = get_usec();

    TimeData timeData = computeTimeData(args.sync_time, client_receive_time, reflectorPacket, timeSynchronizer);

    MetricData data;
    populateMetricData(data, reflectorPacket, ipHeader, host, local_port, port, payload_len, packet_loss, timeData);

    struct timespec rtt_ts = convertToTimespec(timeData.rtt);
    struct timespec client_server_delay_ts = convertToTimespec(timeData.client_server_delay);
    struct timespec server_client_delay_ts = convertToTimespec(timeData.server_client_delay);

    sqa_stats_add_sample(Client::stats_RTT, &rtt_ts);
    sqa_stats_add_sample(Client::stats_client_server, &client_server_delay_ts);
    sqa_stats_add_sample(Client::stats_server_client, &server_client_delay_ts);

    if (Client::first_packet_sent == 0) {
        Client::first_packet_sent = timeData.client_send_time;
    }
    Client::last_packet_sent = timeData.client_send_time;

    if (args.print_RTT_only) {
        std::cout << std::fixed << (double) timeData.rtt / 1e6 << "\n";
    } else {
        printMetrics(data);
    }
}

void Client::printHeader() {
    std::cout << "Time"<< args.sep << "IP"<< args.sep << "Snd#"<< args.sep << "Rcv#"<< args.sep << "SndPort"<< args.sep
        << "RscPort"<< args.sep << "Sync"<< args.sep << "FW_TTL"<< args.sep << "SW_TTL"<< args.sep << "SndTOS"<< args.sep
        << "FW_TOS"<< args.sep << "SW_TOS"<< args.sep << "RTT"<< args.sep << "IntD"<< args.sep << "FWD"<< args.sep
        << "BWD"<< args.sep << "PLEN" << args.sep << "LOSS" << "\n";
}

void Client::printMetrics(const MetricData& data) {
    char sync = 'N';
    uint64_t estimated_rtt = data.client_server_delay+data.server_client_delay+data.internal_delay;
    if(isWithinEpsilon((double)data.rtt_delay*1e-3, (double)estimated_rtt*1e-3, 0.01)){
        sync = 'Y';
    }
    if ((data.client_server_delay < 0) || (data.server_client_delay < 0)) {
        sync = 'N';
    }
    /*Sequence number */
    uint32_t rcv_sn = ntohl(data.packet.seq_number);
    uint32_t snd_sn = ntohl(data.packet.sender_seq_number);

    std::cout
    << std::fixed
    << data.initial_send_time
    << args.sep
    << data.ip
    << args.sep
    << snd_sn
    << args.sep
    << rcv_sn
    << args.sep
    << data.sending_port
    << args.sep
    << data.receiving_port
    << args.sep
    << sync
    << args.sep
    << unsigned(data.packet.sender_ttl)
    << args.sep
    << unsigned(data.ipHeader.ttl)
    << args.sep
    << unsigned(data.packet.sender_tos)
    << args.sep
    << '-'
    << args.sep
    << unsigned(data.ipHeader.tos)
    << args.sep
    <<(double) data.rtt_delay * 1e-3
    << args.sep
    <<(double) data.internal_delay* 1e-3
    << args.sep
    << (double) data.client_server_delay * 1e-3
    << args.sep
    << (double) data.server_client_delay * 1e-3
    << args.sep
    << data.payload_length
    << args.sep
    << data.packet_loss
    << "\n";
}

template <typename Func>
void Client::printLine(const std::string& label, Func func) {
    std::cout << " " << std::left << std::setw(10) << label << std::setprecision(6);
    std::cout << func(this->stats_RTT) << " s      ";
    std::cout << func(this->stats_client_server) << " s      ";
    std::cout << func(this->stats_server_client) << " s\n";
}

void Client::printStats(int packets_sent) {
    std::cout << std::fixed;
    std::cout << "Time elapsed: " << (double)(Client::last_packet_sent - Client::first_packet_sent) / 1e6 << " s\n";
    std::cout << "Packets sent: " << packets_sent << " Packets received: " << sqa_stats_get_number_of_samples(Client::stats_RTT) << "\n";
    std::cout << "Packets lost: " << packets_sent - sqa_stats_get_number_of_samples(Client::stats_RTT) << "\n";
    std::cout << "Packet loss: " << (double)(packets_sent - sqa_stats_get_number_of_samples(Client::stats_RTT)) / packets_sent * 100 << "%\n";
    std::cout << "                RTT             FWD             BWD\n";
    
    auto printPercentileLine = [&](const std::string& label, double percentile) {
        std::cout << " " << std::left << std::setw(10) << label << std::setprecision(6);
        std::cout << sqa_stats_get_percentile(Client::stats_RTT, percentile) << " s      ";
        std::cout << sqa_stats_get_percentile(Client::stats_client_server, percentile) << " s      ";
        std::cout << sqa_stats_get_percentile(Client::stats_server_client, percentile) << " s\n";
    };
    
    printLine("mean:", sqa_stats_get_mean);
    printLine("median:", sqa_stats_get_median);
    printLine("min:", sqa_stats_get_min_as_seconds);
    printLine("max:", sqa_stats_get_max_as_seconds);
    printLine("std:", sqa_stats_get_standard_deviation);
    printLine("variance:", sqa_stats_get_variance);
    printPercentileLine("p95:", 95);
    printPercentileLine("p99:", 99);
    printPercentileLine("p99.9:", 99.9);
}
