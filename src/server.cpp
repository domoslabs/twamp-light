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
#include <vector>
#include <CLI11.hpp>
#include "twamp_light.hpp"
struct Args{
    std::string local_host;
    std::string local_port = "443";
    uint32_t num_samples = 0;
    uint8_t timeout = 10;
};
Args parse_args(int argc, char **argv){
    Args args;
    CLI::App app{"Twamp-Light implementation written by Domos."};
    app.option_defaults()->always_capture_default(true);
    app.add_option("-a, --local_address", args.local_host, "The address to set up the local socket on. Auto-selects by default.");
    app.add_option("-P, --local_port", args.local_port, "The port to set up the local socket on.");
    app.add_option("-n, --num_samples", args.num_samples, "Number of samples to expect before shutdown. Set to 0 to expect unlimited samples.");
    app.add_option("-t, --timeout", args.timeout, "How long (in seconds) to keep the socket open, when no packets are incoming. Set to 0 to disable timeout.")->default_str(std::to_string(args.timeout));
    try{
        app.parse(argc, argv);
    }catch(const CLI::ParseError &e) {
        std::exit((app).exit(e));
    }

    return args;
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
void handle_test_packet(SenderPacket *packet, msghdr sender_msg, int fd, size_t payload_len, const Args& args){
    ReflectorPacket reflector_packet = craft_reflector_packet(packet, sender_msg);
    // Overwrite and reuse the sender message with our own data and send it back, instead of creating a new one.
    auto *addr = (sockaddr_in *)sender_msg.msg_name;
    char *ip = inet_ntoa(addr->sin_addr);
    print_metrics_server(ip, ntohs(addr->sin_port), std::stoi(args.local_port), reflector_packet.sender_tos, 0, payload_len, &reflector_packet);
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
int main(int argc, char **argv) {
    Args args = parse_args(argc, argv);
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
        return 0;
    }

    // Create the socket
    int fd=socket(res->ai_family,res->ai_socktype,res->ai_protocol);
    if (fd==-1) {
        std::cerr << strerror(errno) << std::endl;
        return -1;
    }
    // Setup the socket options, to be able to receive TTL and TOS
    set_socket_options(fd, HDR_TTL, args.timeout);
    set_socket_tos(fd, 10);
    // Bind the socket
    if (bind(fd,res->ai_addr,res->ai_addrlen)==-1) {
        std::cerr << strerror(errno) << std::endl;
        return -1;
    }
    // Free the socket address info, since it is no longer needed. ??
    freeaddrinfo(res);
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
        struct sockaddr *src_addr;

        struct iovec iov[1];
        iov[0].iov_base = buffer;
        iov[0].iov_len = sizeof(buffer);
        char *control_buffer = (char *) malloc(TST_PKT_SIZE);
        uint16_t control_length = TST_PKT_SIZE;

        struct msghdr message{};
        message.msg_name = &src_addr;
        message.msg_namelen = sizeof(&src_addr);
        message.msg_iov = iov;
        message.msg_iovlen = 1;
        message.msg_control = control_buffer;
        message.msg_controllen = control_length;

        ssize_t payload_len = recvmsg(fd, &message, 0);
        if (payload_len == -1) {
            if(errno == 11){
                std::cerr << "Socket timed out." << std::endl;
                std::exit(EXIT_FAILURE);
            } else {
                printf("%s", strerror(errno));
            }
            return 0;
        } else if (message.msg_flags & MSG_TRUNC) {
            std::cout << "Datagram too large for buffer: truncated" << std::endl;
        } else {
            auto *rec = (SenderPacket *) buffer;
            handle_test_packet(rec, message, fd, payload_len, args);
        }
    }
}
