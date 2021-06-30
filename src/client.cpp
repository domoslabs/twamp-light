#include <iostream>
#include <cerrno>
#include <cstring>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/uio.h>
#include "twamp_light.h"
const char* remote_host = "127.0.0.1";
const char* remote_port = "443";
const char* local_host = nullptr;
const char* local_port = "445";
SenderPacket craft_sender_packet(){
    SenderPacket packet;
    packet.seq_number = htonl(5); //TODO Use an index value or something here
    packet.time = get_timestamp();
    packet.error_estimate = htons(0x8001); // Sync = 1, Multiplier = 1.
    return packet;
}
void handle_reflector_packet(ReflectorPacket *reflectorPacket, msghdr msghdr, int fd) {
    std::cout << htonl(reflectorPacket->seq_number) << std::endl;
}
int main() {
    std::cout << "Running Client" << std::endl;

    // Construct remote socket address
    struct addrinfo hints{};
    memset(&hints,0,sizeof(hints));
    hints.ai_family=AF_INET; //TODO IPv6
    hints.ai_socktype=SOCK_DGRAM;
    hints.ai_protocol=0;
    hints.ai_flags=AI_PASSIVE|AI_ADDRCONFIG;
    struct addrinfo* remote_address_info=nullptr;
    struct addrinfo* local_address_info=nullptr;
    int err=getaddrinfo(remote_host,remote_port,&hints,&remote_address_info);
    int err2=getaddrinfo(local_host,local_port,&hints,&local_address_info);
    if (err!=0) {
        std::cerr << "failed to resolve remote socket address: " << err;
        return 0;
    }
    if (err2!=0) {
        std::cerr << "failed to resolve local socket address: " << err;
        return 0;
    }
    // Create the socket
    int fd=socket(remote_address_info->ai_family, remote_address_info->ai_socktype, remote_address_info->ai_protocol);
    if (fd==-1) {
        std::cerr << strerror(errno) << std::endl;
        return 0;
    }

    // Bind the socket to a local port
    if (bind(fd, local_address_info->ai_addr, local_address_info->ai_addrlen) == -1) {
        std::cerr << strerror(errno) << std::endl;
        return 0;
    }
    // Set socket options
    set_socket_ttl(fd, HDR_TTL);
    // Send the UDP packet
    SenderPacket senderPacket = craft_sender_packet();
    struct iovec iov[1];
    iov[0].iov_base=&senderPacket;
    iov[0].iov_len=sizeof(senderPacket);

    struct msghdr message{};
    message.msg_name=remote_address_info->ai_addr;
    message.msg_namelen=remote_address_info->ai_addrlen;
    message.msg_iov=iov;
    message.msg_iovlen=1;
    message.msg_control=nullptr;
    message.msg_controllen=0;

    if (sendmsg(fd,&message,0)==-1) {
        std::cerr << strerror(errno) << std::endl;
        return 0;
    }
    // Read incoming datagrams
    while(true){
        char buffer[sizeof(ReflectorPacket)]; //We should only be receiving ReflectorPackets
        struct sockaddr *src_addr;

        struct iovec iov[1];
        iov[0].iov_base=buffer;
        iov[0].iov_len=sizeof(buffer);

        struct msghdr incoming_msg{};
        incoming_msg.msg_name=&src_addr;
        incoming_msg.msg_namelen=sizeof(&src_addr);
        incoming_msg.msg_iov=iov;
        incoming_msg.msg_iovlen=1;
        incoming_msg.msg_control= nullptr;
        incoming_msg.msg_controllen=0;

        ssize_t count=recvmsg(fd, &incoming_msg, 0);
        if (count==-1) {
            printf("%s",strerror(errno));
            return 0;
        } else if (incoming_msg.msg_flags & MSG_TRUNC) {
            std::cout << "Datagram too large for buffer: truncated" << std::endl;
        } else {
            std::cout << "Received Datagram" << std::endl;
            auto *rec = (ReflectorPacket *)buffer;
            handle_reflector_packet(rec, incoming_msg, fd);
        }
    }

}


