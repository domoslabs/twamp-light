#include <iostream>
#include <cerrno>
#include <cstring>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include "twamp_light.h"
const char* local_host = "127.0.0.1"; // Does not matter, use wildcard
const char* local_port = "443";
ReflectorPacket craft_reflector_packet(SenderPacket *sender_packet, msghdr sender_msg){
    ReflectorPacket packet;
    packet.receive_time = get_timestamp();
    // Reflect the seq number as is defined in https://tools.ietf.org/id/draft-mirsky-ippm-twamp-light-yang-09.html
    packet.seq_number = sender_packet->seq_number;
    packet.sender_seq_number = sender_packet->seq_number;
    packet.sender_time = sender_packet->time;
    packet.sender_error_estimate = sender_packet->error_estimate;
    IPHeader ipHeader = get_ip_header(&sender_msg);
    packet.sender_ttl = ipHeader.ttl;
    packet.sender_tos = ipHeader.tos;
    packet.error_estimate = htons(0x8001);    // Sync = 1, Multiplier = 1
    packet.time = get_timestamp();
    return packet;
}
void handle_test_packet(SenderPacket *packet, msghdr sender_msg, int fd){
    std::cout << htonl(packet->seq_number) << std::endl;
    //std::cout << packet->time << std::endl;
    std::cout << packet->error_estimate << std::endl;
    ReflectorPacket reflector_packet = craft_reflector_packet(packet, sender_msg);

    struct iovec iov[1];
    iov[0].iov_base=&reflector_packet;
    iov[0].iov_len=sizeof(reflector_packet);


    if (sendmsg(fd,&sender_msg,0)==-1) {
        std::cerr << strerror(errno) << std::endl;
        return;
    }
}
int main() {

    std::cout << "Running Server" << std::endl;
    // Construct socket address
    struct addrinfo hints;
    memset(&hints,0,sizeof(hints));
    hints.ai_family=AF_INET; //TODO IPv6
    hints.ai_socktype=SOCK_DGRAM;
    hints.ai_protocol=0;
    hints.ai_flags=AI_PASSIVE|AI_ADDRCONFIG;
    struct addrinfo* res= nullptr;
    int err=getaddrinfo(local_host,local_port,&hints,&res);
    if (err!=0) {
        std::cerr << "failed to resolve local socket address: " << err << std::endl;
        return 0;
    }

    // Create the socket
    int fd=socket(res->ai_family,res->ai_socktype,res->ai_protocol);
    if (fd==-1) {
        std::cerr << strerror(errno) << std::endl;
        return 0;
    }

    // Bind the socket
    if (bind(fd,res->ai_addr,res->ai_addrlen)==-1) {
        std::cerr << strerror(errno) << std::endl;
        return 0;
    }
    // Free the socket address info, since it is no longer needed.
    freeaddrinfo(res);

    // Read incoming datagrams
    while(true){
        char buffer[sizeof(SenderPacket)]; //We should only be receiving test_packets
        struct sockaddr *src_addr;

        struct iovec iov[1];
        iov[0].iov_base=buffer;
        iov[0].iov_len=sizeof(buffer);

        struct msghdr message{};
        message.msg_name=&src_addr;
        message.msg_namelen=sizeof(&src_addr);
        message.msg_iov=iov;
        message.msg_iovlen=1;
        message.msg_control= nullptr;
        message.msg_controllen=0;

        ssize_t count=recvmsg(fd,&message,0);
        if (count==-1) {
            printf("%s",strerror(errno));
            return 0;
        } else if (message.msg_flags&MSG_TRUNC) {
            std::cout << "Datagram too large for buffer: truncated" << std::endl;
        } else {
            std::cout << "Received Datagram" << std::endl;
            auto *rec = (SenderPacket *)buffer;
            handle_test_packet(rec, message, fd);
        }
    }
    return 0;
}
