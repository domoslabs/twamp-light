#include <iostream>
#include <cerrno>
#include <cstring>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <getopt.h>
#include <arpa/inet.h>
#include "twamp_light.h"
#include "fort.hpp"
const char* local_host = nullptr; // Does not matter, use wildcard
const char* local_port = "443";
void show_help(char* progname){
    std::cout << "\nTwamp-Light implementation written by Vladimir Monakhov. \n" << std::endl;
    std::cout << "Usage: " << progname << " [--local_address] [--local_port] [--help]"<< std::endl;
    std::cout << "-a    --local_address           The address to set up the local socket on.          (Optional, not needed in most cases)" << std::endl;
    std::cout << "-P    --local_port              The port to set up the local socket on.             (Default: " << local_port << ")" << std::endl;
    std::cout << "-h    --help                    Show this message." << std::endl;
}
void parse_args(int argc, char **argv){
    const char *shortopts = "a:p:h";
    const struct option longopts[] = {
            {"local_address", required_argument, 0, 'a'},
            {"local_port", required_argument, 0, 'P'},
            {"help", no_argument, 0, 'h'},
            {0, 0, 0, 0},
    };
    int c, option_index;
    while ((c = getopt_long(argc, argv, shortopts, longopts, &option_index)) != -1)
        switch (c)
        {
            case 'a':
                local_host = optarg;
                break;
            case 'h':
                show_help(argv[0]);
                std::exit(EXIT_SUCCESS);
            case 'P':
                local_port = optarg;
                break;
            default:
                std::cerr << "Invalid argument: " << c << ". See --help." << std::endl;
                std::exit(EXIT_FAILURE);
        }
}
ReflectorPacket craft_reflector_packet(SenderPacket *sender_packet, msghdr sender_msg){

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
void handle_test_packet(SenderPacket *packet, msghdr sender_msg, int fd){
    ReflectorPacket reflector_packet = craft_reflector_packet(packet, sender_msg);
    // Overwrite and reuse the sender message with our own data and send it back, instead of creating a new one.
    auto *hdr = (sockaddr_in *)sender_msg.msg_name;
    char *ip = inet_ntoa(hdr->sin_addr);
    print_metrics_server(ip, htons(hdr->sin_port), std::stoi(local_port), reflector_packet.sender_tos, 0, &reflector_packet);
    msghdr message = sender_msg;
    struct iovec iov[1];
    iov[0].iov_base=&reflector_packet;
    iov[0].iov_len=sizeof(reflector_packet);
    message.msg_iov=iov;
    message.msg_iovlen=1;

    if (sendmsg(fd,&message,0)==-1) {
        std::cerr << strerror(errno) << std::endl;
        return;
    }
}
int main(int argc, char **argv) {
    parse_args(argc, argv);
    // Construct socket address
    struct addrinfo hints = {};
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
        return -1;
    }
    // Setup the socket options, to be able to receive TTL and TOS
    set_socket_options(fd, HDR_TTL);
    set_socket_tos(fd, 10);
    // Bind the socket
    if (bind(fd,res->ai_addr,res->ai_addrlen)==-1) {
        std::cerr << strerror(errno) << std::endl;
        return -1;
    }
    // Free the socket address info, since it is no longer needed. ??
    freeaddrinfo(res);
    // Read incoming datagrams
    while(true){
        char buffer[sizeof(SenderPacket)]; //We should only be receiving test_packets
        struct sockaddr *src_addr;

        struct iovec iov[1];
        iov[0].iov_base=buffer;
        iov[0].iov_len=sizeof(buffer);
        char *control_buffer = (char *)malloc(TST_PKT_SIZE);
        uint16_t control_length = TST_PKT_SIZE;

        struct msghdr message{};
        message.msg_name=&src_addr;
        message.msg_namelen=sizeof(&src_addr);
        message.msg_iov=iov;
        message.msg_iovlen=1;
        message.msg_control= control_buffer;
        message.msg_controllen=control_length;

        ssize_t count=recvmsg(fd,&message,0);
        if (count==-1) {
            printf("%s",strerror(errno));
            return 0;
        } else if (message.msg_flags&MSG_TRUNC) {
            std::cout << "Datagram too large for buffer: truncated" << std::endl;
        } else {
            auto *rec = (SenderPacket *)buffer;
            handle_test_packet(rec, message, fd);
        }
    }
}
