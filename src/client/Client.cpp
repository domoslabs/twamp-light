//
// Created by vladim0105 on 12/15/21.
//

#include <netdb.h>
#include <cstring>
#include <iostream>
#include <unistd.h>
#include <arpa/inet.h>
#include "Client.h"
#include "utils.hpp"

Client::Client(const Args& args) {
    // Construct remote socket address
    struct addrinfo hints{};
    memset(&hints,0,sizeof(hints));
    hints.ai_family=AF_INET; //TODO IPv6
    hints.ai_socktype=SOCK_DGRAM;
    hints.ai_protocol=0;
    hints.ai_flags=AI_PASSIVE|AI_ADDRCONFIG;

    int err=getaddrinfo(args.remote_host.c_str(),args.remote_port.c_str(),&hints,&remote_address_info);
    int err2=getaddrinfo(args.local_host.empty()? nullptr : args.local_host.c_str(),args.local_port.c_str(),&hints,&local_address_info);
    if (err!=0) {
        std::cerr << "failed to resolve remote socket address: " << err;
        std::exit(EXIT_FAILURE);
    }
    if (err2!=0) {
        std::cerr << "failed to resolve local socket address: " << err;
        std::exit(EXIT_FAILURE);
    }
    // Create the socket
    fd=socket(remote_address_info->ai_family, remote_address_info->ai_socktype, remote_address_info->ai_protocol);
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

void Client::sendPacket(int idx, size_t payload_len, const Args &args) {
    // Send the UDP packet
    ClientPacket senderPacket = craftSenderPacket(idx, args);
    struct iovec iov[1];
    iov[0].iov_base=&senderPacket;
    iov[0].iov_len=payload_len;
    struct msghdr message = {};
    message.msg_name=remote_address_info->ai_addr;
    message.msg_namelen=remote_address_info->ai_addrlen;
    message.msg_iov=iov;
    message.msg_iovlen=1;
    message.msg_control= nullptr;
    message.msg_controllen=0;

    if (sendmsg(fd,&message,0)==-1) {
        std::cerr << strerror(errno) << std::endl;
        throw std::runtime_error(std::string("Sending UDP message failed with error."));
    }
}

ClientPacket Client::craftSenderPacket(int idx, const Args& args){
    ClientPacket packet = {};
    packet.seq_number = htonl(idx);
    packet.error_estimate = htons(0x8001); // Sync = 1, Multiplier = 1.
    if(args.sync_time){
        uint32_t ts = TimeSynchronizer::LocalTimeToDatagramTS24(get_usec());
        uint32_t delta = timeSynchronizer->GetMinDeltaTS24().ToUnsigned();
        packet.send_time_data.integer = ts;
        packet.send_time_data.fractional = delta;
    } else {
        auto ts = get_timestamp();
        packet.send_time_data = ts;
    }
    return packet;
}

bool Client::awaitResponse(size_t payload_len, uint16_t  packet_loss, const Args& args) {
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

    ssize_t count=recvmsg(fd, &incoming_msg, 0);
    if (count==-1) {
        if(errno == 11){
            return false;
        } else {
            printf("%s", strerror(errno));
        }
        throw;
    } else if (incoming_msg.msg_flags & MSG_TRUNC) {
        return false;
    } else {
        auto *rec = (ReflectorPacket *)buffer;
        handleReflectorPacket(rec, incoming_msg, payload_len, packet_loss, args);
    }
    return true;
}
void Client::handleReflectorPacket(ReflectorPacket *reflectorPacket, msghdr msghdr, size_t payload_len, uint16_t packet_loss, const Args& args) {
    IPHeader ipHeader = get_ip_header(msghdr);
    sockaddr_in *sock = ((sockaddr_in *)msghdr.msg_name);
    char* host = inet_ntoa(sock->sin_addr);
    uint16_t  port = ntohs(sock->sin_port);
    int64_t server_client_delay, client_server_delay, internal_delay, rtt;
    uint64_t client_send_time, server_receive_time, server_send_time;
    uint64_t client_receive_time = get_usec();
    if(args.sync_time){
        uint32_t server_timestamp = reflectorPacket->server_time_data.integer;
        uint32_t server_delta = reflectorPacket->server_time_data.fractional;
        std::cout << std::fixed <<server_delta<< std::endl;

        uint32_t client_timestamp = reflectorPacket->client_time_data.integer;
        uint32_t client_delta = reflectorPacket->client_time_data.fractional;

        uint32_t send_timestamp = reflectorPacket->send_time_data.integer;
        uint32_t send_delta = reflectorPacket->send_time_data.fractional;

        server_client_delay = timeSynchronizer->OnAuthenticatedDatagramTimestamp(server_timestamp, get_usec());
        timeSynchronizer->OnPeerMinDeltaTS24(server_delta);
        // Convert initial client send timestamp to server time, then subtract it from the server received timestamp.
        auto a = timeSynchronizer->To64BitUSec(get_usec(), timeSynchronizer->ToRemoteTime23(timeSynchronizer->To64BitUSec(get_usec(), client_timestamp)));
        auto b = timeSynchronizer->To64BitUSec(get_usec(), server_timestamp);
        client_server_delay = (int64_t)(b-a);
        /* Compute timestamps in usec */
         client_send_time = timeSynchronizer->To64BitUSec(get_usec(), client_timestamp);
         server_receive_time = timeSynchronizer->To64BitUSec(get_usec(), server_timestamp);
         server_send_time = timeSynchronizer->To64BitUSec(get_usec(), send_timestamp);

        /* Compute delays */
        internal_delay = (int64_t)(server_send_time - server_receive_time);
        rtt = (int64_t)(client_receive_time - client_send_time);
    } else {
        /* Compute timestamps in usec */
        client_send_time = timestamp_to_usec(&reflectorPacket->client_time_data);
        server_receive_time = timestamp_to_usec(&reflectorPacket->server_time_data);
        server_send_time = timestamp_to_usec(&reflectorPacket->send_time_data);

        /* Compute delays */
        internal_delay = (int64_t)(server_send_time - server_receive_time);
        client_server_delay = (int64_t)(server_receive_time-client_send_time);
        server_client_delay = (int64_t)(client_receive_time-server_send_time);
        rtt = (int64_t)(client_receive_time - client_send_time);
    }
    MetricData data;
    data.ip = host;
    data.sending_port = std::stoi(args.local_port);
    data.receiving_port = port;
    data.packet = *reflectorPacket;
    data.ipHeader = ipHeader;
    data.initial_send_time = client_send_time;
    data.payload_length = payload_len;
    data.packet_loss = packet_loss;
    data.internal_delay = internal_delay;
    data.server_client_delay = server_client_delay;
    data.client_server_delay = client_server_delay;
    data.rtt_delay = rtt;

    printMetrics(data);
}
void Client::printMetrics(const MetricData& data) {
    char sync = 'Y';
    if ((data.client_server_delay < 0) || (data.server_client_delay < 0)) {
        sync = 'N';
    }
    /*Sequence number */
    uint32_t rcv_sn = ntohl(data.packet.seq_number);
    uint32_t snd_sn = ntohl(data.packet.sender_seq_number);

    if(!header_printed){
        std::cout << "Time,"<< "IP,"<< "Snd#,"<< "Rcv#,"<< "SndPort,"<< "RscPort,"<< "Sync,"<< "FW_TTL,"
                  << "SW_TTL,"<< "SndTOS,"<< "FW_TOS,"<< "SW_TOS,"<< "RTT,"<< "IntD,"
                  << "FWD,"<< "BWD,"<< "PLEN," << "LOSS" << "\n";
        header_printed = true;
    }
    std::cout << std::fixed << (double) data.initial_send_time * 1e-3 << "," << data.ip<< ","<< snd_sn<< ","<< rcv_sn<< ","<< data.sending_port<< ","
              << data.receiving_port<< ","<< sync<< ","<< unsigned(data.packet.sender_ttl)<< ","<< unsigned(data.ipHeader.ttl)<< ","
              << unsigned(data.packet.sender_tos)<< ","<< '-'<< ","<< unsigned(data.ipHeader.tos)<< ","<<(double) data.rtt_delay * 1e-3<< ","
              <<(double) data.internal_delay* 1e-3<< ","<< (double) data.client_server_delay * 1e-3<< ","<< (double) data.server_client_delay * 1e-3<< ","<< data.payload_length<< "," << data.packet_loss << "\n";
}