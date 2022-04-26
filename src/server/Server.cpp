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
    timeSynchronizer->OnPeerMinDeltaTS24(packet->min_delta);
    int64_t client_server_delay = timeSynchronizer->OnAuthenticatedDatagramTimestamp(packet->timestamp, get_usec());
    /* Compute timestamps in usec */
    uint64_t t_receive_usec1 = reflector_packet.server_timestamp.ToUnsigned() << kTime23LostBits;
    uint64_t t_reflsender_usec1 = reflector_packet.send_timestamp.ToUnsigned() << kTime23LostBits;

    /* Compute delays */
    int64_t intd1 = t_reflsender_usec1 - t_receive_usec1;

    MetricData data;
    data.payload_length = payload_len;
    data.packet = reflector_packet;
    data.client_server_delay = client_server_delay;
    data.internal_delay = intd1;
    data.receiving_port = std::stoi(args.local_port);
    data.sending_port = port;
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
    packet.seq_number = clientPacket->seq_number;
    packet.sender_seq_number = clientPacket->seq_number;
    packet.client_timestamp = clientPacket->timestamp;
    packet.client_min_delta = clientPacket->min_delta;
    packet.sender_error_estimate = clientPacket->error_estimate;
    IPHeader ipHeader = get_ip_header(sender_msg);
    packet.sender_ttl = ipHeader.ttl;
    packet.sender_tos = ipHeader.tos;
    packet.error_estimate = htons(0x8001);    // Sync = 1, Multiplier = 1 Taken from TWAMP C implementation.
    packet.server_timestamp = TimeSynchronizer::LocalTimeToDatagramTS24(get_usec());
    packet.server_min_delta = timeSynchronizer->GetMinDeltaTS24();
    packet.send_timestamp = TimeSynchronizer::LocalTimeToDatagramTS24(get_usec());
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
    uint64_t t_sender_usec1 = data.packet.client_timestamp.ToUnsigned() << kTime23LostBits;
    /* Sender TOS with ECN from FW TOS */
    uint8_t fw_tos = 0;
    uint8_t snd_tos = data.packet.sender_tos + (fw_tos & 0x3) - (((fw_tos & 0x2) >> 1) & (fw_tos & 0x1));
    if(!header_printed){

        std::cout << "Time," << "IP,"<< "Snd#,"<< "Rcv#,"<< "SndPort,"<< "RscPort,"<< "Sync,"<< "FW_TTL,"
                  << "SndTOS,"<< "FW_TOS,"<< "IntD,"<< "FWD," << "PLEN" << "\n";
        header_printed = true;
    }
    std::cout << std::fixed << (double) t_sender_usec1* 1e-3 << "," << data.ip << "," << snd_nb << ","
              << rcv_nb << "," << data.sending_port << "," << data.receiving_port << "," << sync1 << "," << unsigned(data.packet.sender_ttl) << "," << unsigned(snd_tos) << ","
              << unsigned(fw_tos) << "," << (double) data.internal_delay * 1e-3 << "," << (double) data.client_server_delay * 1e-3 << "," << std::to_string(data.payload_length) << "\n";

}
