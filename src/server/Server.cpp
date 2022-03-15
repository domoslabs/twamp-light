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
    bool run = true;
    int counter = 0;
    while(run){
        if(args.num_samples != 0){
            counter++;
            if(counter > args.num_samples){
                run = false;
            }
        }
        char buffer[sizeof(SenderPacket)]; //We should only be receiving test_packets
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
            auto *rec = (SenderPacket *) buffer;
            handleTestPacket(rec, message, payload_len);
        }
    }
}

void Server::handleTestPacket(SenderPacket *packet, msghdr sender_msg, size_t payload_len) {
    ReflectorPacket reflector_packet = craftReflectorPacket(packet, sender_msg);
    sockaddr_in *sock = ((sockaddr_in *)sender_msg.msg_name);
    // Overwrite and reuse the sender message with our own data and send it back, instead of creating a new one.
    char* host = inet_ntoa(sock->sin_addr);
    uint16_t  port = ntohs(sock->sin_port);
    printMetrics(host, port, std::stoi(args.local_port), reflector_packet.sender_tos, 0, payload_len, &reflector_packet);
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

ReflectorPacket Server::craftReflectorPacket(SenderPacket *sender_packet, msghdr sender_msg){

    ReflectorPacket packet = {};
    packet.receive_time = get_timestamp();
    packet.seq_number = sender_packet->seq_number;
    packet.sender_seq_number = sender_packet->seq_number;
    packet.sender_time = sender_packet->time;
    packet.sender_error_estimate = sender_packet->error_estimate;
    IPHeader ipHeader = get_ip_header(sender_msg);
    packet.sender_ttl = ipHeader.ttl;
    packet.sender_tos = ipHeader.tos;
    packet.error_estimate = htons(0x8001);    // Sync = 1, Multiplier = 1 Taken from TWAMP C implementation.
    packet.time = get_timestamp();
    return packet;
}


void Server::printMetrics(const char *addr_cl, uint16_t snd_port, uint16_t rcv_port,
                          uint8_t snd_tos, uint8_t fw_tos, uint16_t plen,
                          const ReflectorPacket *pack) {

    /* Compute timestamps in usec */
    uint64_t t_sender_usec1 = get_usec(&pack->sender_time);
    uint64_t t_receive_usec1 = get_usec(&pack->receive_time);
    uint64_t t_reflsender_usec1 = get_usec(&pack->time);

    /* Compute delays */
    int64_t fwd1 = t_receive_usec1 - t_sender_usec1;
    int64_t intd1 = t_reflsender_usec1 - t_receive_usec1;
    char sync1 = 'Y';
    if (fwd1 < 0) {
        sync1 = 'N';
    }
    /* Sequence number */
    uint32_t snd_nb = ntohl(pack->sender_seq_number);
    uint32_t rcv_nb = ntohl(pack->seq_number);

    /* Sender TOS with ECN from FW TOS */
    snd_tos =
            snd_tos + (fw_tos & 0x3) - (((fw_tos & 0x2) >> 1) & (fw_tos & 0x1));
    if(!header_printed){

        std::cout << "Time," << "IP,"<< "Snd#,"<< "Rcv#,"<< "SndPort,"<< "RscPort,"<< "Sync,"<< "FW_TTL,"
                  << "SndTOS,"<< "FW_TOS,"<< "IntD,"<< "FWD," << "PLEN" << "\n";
        header_printed = true;
    }
    std::cout << std::fixed << (double) t_sender_usec1* 1e-3 << "," << addr_cl << ","  << snd_nb << ","
              <<rcv_nb << "," << snd_port << "," << rcv_port << "," << sync1 << "," << unsigned(pack->sender_ttl) << ","<< unsigned(snd_tos) << ","
              <<unsigned(fw_tos) << "," << (double) intd1 * 1e-3  << ","<< (double) fwd1 * 1e-3 << ","<<std::to_string(plen) << "\n";

}
