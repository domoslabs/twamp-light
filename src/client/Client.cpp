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

void Client::sendPacket(int idx, size_t payload_len) {
    // Send the UDP packet
    SenderPacket senderPacket = craftSenderPacket(idx);
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

SenderPacket Client::craftSenderPacket(int idx){
    SenderPacket packet = {};
    packet.seq_number = htonl(idx);
    packet.time = get_timestamp();
    packet.error_estimate = htons(0x8001); // Sync = 1, Multiplier = 1.
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
    TWAMPTimestamp ts = get_timestamp();
    sockaddr_in *sock = ((sockaddr_in *)msghdr.msg_name);
    char* host = inet_ntoa(sock->sin_addr);
    uint16_t  port = ntohs(sock->sin_port);
    printMetrics(host, std::stoi(args.local_port), port, reflectorPacket->sender_tos, ipHeader.ttl,
                 ipHeader.tos, &ts,
                 reflectorPacket, payload_len, packet_loss);
}
uint64_t Client::printMetrics(const char *server, uint16_t snd_port, uint16_t rcv_port, uint8_t snd_tos, uint8_t sw_ttl, uint8_t sw_tos,
              TWAMPTimestamp *recv_resp_time, const ReflectorPacket *pack, uint16_t plen, uint16_t packets_lost) {
    /* Compute timestamps in usec */
    uint64_t t_sender_usec = get_usec(&pack->sender_time);
    uint64_t t_receive_usec = get_usec(&pack->receive_time);
    uint64_t t_reflsender_usec = get_usec(&pack->time);
    uint64_t t_recvresp_usec = get_usec(recv_resp_time);

    /* Compute delays */
    uint64_t fwd = t_receive_usec - t_sender_usec;
    uint64_t swd = t_recvresp_usec - t_reflsender_usec;
    uint64_t intd = t_reflsender_usec - t_receive_usec;
    uint64_t rtt = t_recvresp_usec - t_sender_usec;
    char sync = 'Y';
    if ((fwd < 0) || (swd < 0)) {
        sync = 'N';
    }

    /*Sequence number */
    uint32_t rcv_sn = ntohl(pack->seq_number);
    uint32_t snd_sn = ntohl(pack->sender_seq_number);

    if(!header_printed){
        std::cout << "Time,"<< "IP,"<< "Snd#,"<< "Rcv#,"<< "SndPort,"<< "RscPort,"<< "Sync,"<< "FW_TTL,"
                  << "SW_TTL,"<< "SndTOS,"<< "FW_TOS,"<< "SW_TOS,"<< "RTT,"<< "IntD,"
                  << "FWD,"<< "BWD,"<< "PLEN," << "LOSS" << "\n";
        header_printed = true;
    }
    std::cout << std::fixed << (double) t_sender_usec * 1e-3 << "," << server<< ","<< snd_sn<< ","<< rcv_sn<< ","<< snd_port<< ","
              << rcv_port<< ","<< sync<< ","<< unsigned(pack->sender_ttl)<< ","<< unsigned(sw_ttl)<< ","
              << unsigned(snd_tos)<< ","<< '-'<< ","<< unsigned(sw_tos)<< ","<<(double) rtt * 1e-3<< ","
              <<(double) intd* 1e-3<< ","<< (double) fwd * 1e-3<< ","<< (double) swd * 1e-3<< ","<< plen<< "," << packets_lost << "\n";

    return t_recvresp_usec - t_sender_usec;

}