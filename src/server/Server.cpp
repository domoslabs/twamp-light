//
// Created by vladim0105 on 12/17/21.
//

#include <sys/socket.h>
#include <netdb.h>
#include <cstring>
#include <iostream>
#include <arpa/inet.h>
#include "Server.h"
#include "utils.hpp"
#include "TimeSync.h"

Server::Server(const Args& args) {
    this->args = args;
    // Construct socket address
    struct addrinfo hints = {};
    memset(&hints,0,sizeof(hints));
    hints.ai_family=AF_INET; //TODO IPv6
    hints.ai_socktype=SOCK_DGRAM;
    hints.ai_protocol=0;
    hints.ai_flags=AI_PASSIVE|AI_ADDRCONFIG;
    struct addrinfo* res= nullptr;
    int err=getaddrinfo(args.local_host.empty()? nullptr : args.local_host.c_str(),args.local_port.c_str(),&hints,&res);
    if (err!=0) {
        std::cerr << "failed to resolve local socket address: " << err << std::endl;
        std::exit(EXIT_FAILURE);
    }

    // Create the socket
    fd=socket(res->ai_family,res->ai_socktype,res->ai_protocol);
    if (fd==-1) {
        std::cerr << strerror(errno) << std::endl;
        std::exit(EXIT_FAILURE);
    }
    // Setup the socket options, to be able to receive TTL and TOS
    set_socket_options(fd, HDR_TTL, args.timeout);
    set_socket_tos(fd, 10);
    // Bind the socket
    if (bind(fd,res->ai_addr,res->ai_addrlen)==-1) {
        std::cerr << strerror(errno) << std::endl;
        std::exit(EXIT_FAILURE);
    }
}

void Server::listen() {
    // Read incoming datagrams
    int counter = 0;
    while(true){
        if(args.num_samples != 0){
            counter++;
            if(counter > args.num_samples){
                break;
            }
        }
        char buffer[sizeof(ClientPacket)]; //We should only be receiving test_packets
        struct sockaddr src_addr{};

        struct iovec iov[1];
        iov[0].iov_base = buffer;
        iov[0].iov_len = sizeof(buffer);
        char *control_buffer = (char *) malloc(TST_PKT_SIZE);
        uint16_t control_length = TST_PKT_SIZE;

        struct msghdr message{};
        message.msg_name = &src_addr;
        message.msg_namelen = sizeof(src_addr);
        message.msg_iov = iov;
        message.msg_iovlen = 1;
        message.msg_control = nullptr;
        message.msg_controllen = 1;

        ssize_t payload_len = recvmsg(fd, &message, 0);
        if (payload_len == -1) {
            if(errno == 11){
                std::cerr << "Socket timed out." << std::endl;
                std::exit(EXIT_FAILURE);
            } else {
                printf("%s", strerror(errno));
            }
            std::exit(EXIT_FAILURE);
        } else if (message.msg_flags & MSG_TRUNC) {
            std::cout << "Datagram too large for buffer: truncated" << std::endl;
        } else {
            auto *rec = (ClientPacket *) buffer;
            handleTestPacket(rec, message, payload_len);
        }
    }
}

void Server::handleTestPacket(ClientPacket *packet, msghdr sender_msg, size_t payload_len) {
    ReflectorPacket reflector_packet = craftReflectorPacket(packet, sender_msg);
    sockaddr_in *sock = ((sockaddr_in *)sender_msg.msg_name);
    // Overwrite and reuse the sender message with our own data and send it back, instead of creating a new one.
    char* host = inet_ntoa(sock->sin_addr);
    uint16_t  port = ntohs(sock->sin_port);
    uint64_t server_receive_time, server_send_time, initial_send_time;
    int64_t client_server_delay;
    if(args.sync_time){
        uint32_t client_timestamp = ntohl(packet->send_time_data.integer);
        uint32_t client_delta = ntohl(packet->send_time_data.fractional);
        uint32_t server_timestamp = ntohl(reflector_packet.server_time_data.integer);
        uint32_t server_delta = ntohl(reflector_packet.server_time_data.fractional);
        uint32_t send_timestamp = ntohl(reflector_packet.send_time_data.integer);

        timeSynchronizer->OnPeerMinDeltaTS24(client_delta);
        client_server_delay = timeSynchronizer->OnAuthenticatedDatagramTimestamp(client_timestamp, get_usec());
        /* Compute timestamps in usec */
        server_receive_time = timeSynchronizer->To64BitUSec(get_usec(), server_timestamp);
        server_send_time = timeSynchronizer->To64BitUSec(get_usec(), send_timestamp);
        initial_send_time = timeSynchronizer->To64BitUSec(get_usec(), client_timestamp);
    } else {
        Timestamp client_timestamp = ntohts(packet->send_time_data);
        Timestamp server_timestamp = ntohts(reflector_packet.server_time_data);
        Timestamp send_timestamp = ntohts(reflector_packet.send_time_data);
        client_server_delay = (int64_t)(timestamp_to_usec(&server_timestamp)-timestamp_to_usec(&client_timestamp));
        server_receive_time = timestamp_to_usec(&server_timestamp);
        server_send_time = timestamp_to_usec(&send_timestamp);
        initial_send_time = timestamp_to_usec(&client_timestamp);
    }




    /* Compute delays */
    auto internal_delay = (int64_t)(server_send_time - server_receive_time);

    MetricData data;
    data.payload_length = payload_len;
    data.packet = reflector_packet;
    data.client_server_delay = client_server_delay;
    data.internal_delay = internal_delay;
    data.receiving_port = std::stoi(args.local_port);
    data.sending_port = port;
    data.initial_send_time = initial_send_time;
    data.ip = host;
    printMetrics(data);
    msghdr message = sender_msg;

    struct iovec iov[1];
    iov[0].iov_base=&reflector_packet;
    iov[0].iov_len=payload_len;
    message.msg_iov=iov;
    message.msg_iovlen=1;

    if (sendmsg(fd,&message,0)==-1) {
        std::cerr << strerror(errno) << std::endl;
        return;
    }
}

ReflectorPacket Server::craftReflectorPacket(ClientPacket *clientPacket, msghdr sender_msg){

    ReflectorPacket packet = {};
    if(args.sync_time){
        Timestamp server_timestamp = {};
        server_timestamp.integer = TimeSynchronizer::LocalTimeToDatagramTS24(get_usec());
        server_timestamp.fractional = timeSynchronizer->GetMinDeltaTS24().ToUnsigned();
        packet.server_time_data = htonts(server_timestamp);
    } else {
        Timestamp server_timestamp = get_timestamp();
        packet.server_time_data = htonts(server_timestamp);
    }
    packet.seq_number = clientPacket->seq_number;
    packet.sender_seq_number = clientPacket->seq_number;

    packet.sender_error_estimate = clientPacket->error_estimate;
    IPHeader ipHeader = get_ip_header(sender_msg);
    packet.sender_ttl = ipHeader.ttl;
    packet.sender_tos = ipHeader.tos;
    packet.error_estimate = htons(0x8001);    // Sync = 1, Multiplier = 1 Taken from TWAMP C implementation.
    packet.client_time_data = clientPacket->send_time_data;
    if(args.sync_time){
        Timestamp send_timestamp = {};
        send_timestamp.integer = TimeSynchronizer::LocalTimeToDatagramTS24(get_usec());
        send_timestamp.fractional = timeSynchronizer->GetMinDeltaTS24().ToUnsigned();
        packet.send_time_data = htonts(send_timestamp);
    } else {
        Timestamp send_timestamp = get_timestamp();
        packet.send_time_data = htonts(send_timestamp);
    }

    return packet;
}


void Server::printMetrics(const MetricData& data) {


    char sync1 = 'Y';
    if (data.client_server_delay < 0) {
        sync1 = 'N';
    }
    /* Sequence number */
    uint32_t snd_nb = ntohl(data.packet.sender_seq_number);
    uint32_t rcv_nb = ntohl(data.packet.seq_number);
    uint64_t client_send_time = data.initial_send_time;
    /* Sender TOS with ECN from FW TOS */
    uint8_t fw_tos = 0;
    uint8_t snd_tos = data.packet.sender_tos + (fw_tos & 0x3) - (((fw_tos & 0x2) >> 1) & (fw_tos & 0x1));
    if(!header_printed){

        std::cout << "Time," << "IP,"<< "Snd#,"<< "Rcv#,"<< "SndPort,"<< "RscPort,"<< "Sync,"<< "FW_TTL,"
                  << "SndTOS,"<< "FW_TOS,"<< "IntD,"<< "FWD," << "PLEN" << "\n";
        header_printed = true;
    }
    std::cout << std::fixed << (double) client_send_time* 1e-3 << "," << data.ip << "," << snd_nb << ","
              << rcv_nb << "," << data.sending_port << "," << data.receiving_port << "," << sync1 << "," << unsigned(data.packet.sender_ttl) << "," << unsigned(snd_tos) << ","
              << unsigned(fw_tos) << "," << (double) data.internal_delay * 1e-3 << "," << (double) data.client_server_delay * 1e-3 << "," << std::to_string(data.payload_length) << "\n";

}
