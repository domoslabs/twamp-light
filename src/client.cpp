#include <iostream>
#include <cerrno>
#include <cstring>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/uio.h>
#include <getopt.h>
#include "twamp_light.h"
#include <fstream>
const char* remote_host = "";
const char* remote_port = "443";
const char* local_host = nullptr;
const char* local_port = "445";
const char* filename = nullptr;
uint16_t payload_len = 140;
uint8_t snd_tos = 0;
uint8_t dscp_snd = 0;
uint32_t delay_millis = 1000;
uint32_t num_packets = 10;
void show_help(char* progname){
    std::cout << "\nTwamp-Light implementation written by Vladimir Monakhov. \n" << std::endl;
    std::cout << "Usage: " << progname << " <remote address> [--local_address] [--local_port] [--help]"<< std::endl;
    std::cout << "-a    --local_address           The address to set up the local socket on.          (Optional, not needed in most cases)" << std::endl;
    std::cout << "-P    --local_port              The port to set up the local socket on.             (Default: " << local_port << ")" << std::endl;
    std::cout << "-p    --port                    The port that the remote server is listening on.    (Default: " << remote_port << ")" << std::endl;
    std::cout << "-l    --payload_len             The payload length. Must be in range (40, 1473).    (Default: " << payload_len << ")" << std::endl;
    std::cout << "-d    --delay                   The delay given in milliseconds.                    (Default: " << delay_millis << ")" << std::endl;
    std::cout << "-n    --num_packets             The number of packets to send.                      (Default: " << num_packets << ")" << std::endl;
    std::cout << "-f    --file                    Save the output as a .csv formatted file. Disables terminal output." <<std::endl;
    std::cout << "-t    --snd_tos                 The TOS value for Test packets (<256).              (Default: " << unsigned(snd_tos) << ")" << std::endl;
    std::cout << "-D    --snd_tos                 The DSCP value for Test packets (<64).              (Default: " << unsigned(snd_tos) << ")" << std::endl;
    std::cout << "-h    --help                    Show this message." << std::endl;
}
void parse_args(int argc, char **argv){
    const char *shortopts = "a:P:p:l:d:n:f:t:D:h";
    const struct option longopts[] = {
            {"local_address", required_argument, 0, 'a'},
            {"local_port", required_argument, 0, 'P'},
            {"port", required_argument, 0, 'p'},
            {"payload_len", required_argument, 0, 'l'},
            {"delay", required_argument, 0, 'd'},
            {"num_packets", required_argument, 0, 'n'},
            {"file", required_argument, 0, 'f'},
            {"snd_tos", required_argument, 0, 't'},
            {"snd_tos", required_argument, 0, 'D'},
            {"help", no_argument, 0, 'h'},
            {0, 0, 0, 0},
    };
    int c, option_index;
    while ((c = getopt_long(argc, argv, shortopts, longopts, &option_index)) != -1){
        switch (c)
        {
            case 'a':
                local_host = optarg;
                break;
            case 'h':
                show_help(argv[0]);
                std::exit(EXIT_SUCCESS);
            case 'p':
                remote_port = optarg;
                break;
            case 'l':
                payload_len = std::stol(optarg);
                /* The length value must be a valid one */
                if (payload_len < 41 || payload_len > TST_PKT_SIZE){
                    std::cerr << "The payload length must be in range (40, 1473). See --help." << std::endl;
                    std::exit(EXIT_FAILURE);
                }
                break;
            case 'd':
                delay_millis = std::stoi(optarg);
                break;
            case 'n':
                num_packets = std::stoi(optarg);
                break;
            case 'f':
                filename = optarg;
                break;
            case 't':
                snd_tos = std::stol(optarg);
                /* The TOS value must be a valid one (no congestion on ECN */
                snd_tos = snd_tos - (((snd_tos & 0x2) >> 1) & (snd_tos & 0x1));
                break;
            case 'D':
                dscp_snd = std::stol(optarg);
                /* The DSCP value must be a valid one */
                if (dscp_snd > 63) {
                    std::cerr << "The DSCP value must be  <64. See --help." << std::endl;
                    std::exit(EXIT_FAILURE);
                }
                snd_tos = dscp_snd << 2;
                break;
            case 'P':
                local_port = optarg;
                break;
            default:
                std::cerr << "Invalid argument: " << c << ". See --help." << std::endl;
                std::exit(EXIT_FAILURE);
        }
    }
    if (optind == argc) {
        std::cerr << "Remote host address is required. See --help" << std::endl;
        std::exit(EXIT_FAILURE);
    }
    if (optind + 1 < argc) {
        std::cerr << "Exactly one remote host is required. See --help" << std::endl;
        std::exit(EXIT_FAILURE);
    }
    remote_host = argv[optind];
}
SenderPacket craft_sender_packet(int idx){
    SenderPacket packet = {};
    packet.seq_number = htonl(idx); //TODO Use an index value or something here
    packet.time = get_timestamp();
    packet.error_estimate = htons(0x8001); // Sync = 1, Multiplier = 1.
    return packet;
}
uint16_t num_lost = 0;
void handle_reflector_packet(ReflectorPacket *reflectorPacket, msghdr msghdr, int fd, std::ofstream& filestream) {
    IPHeader ipHeader = get_ip_header(msghdr);
    TWAMPTimestamp ts = get_timestamp();
    if(reflectorPacket->sender_seq_number != reflectorPacket->seq_number){
        num_lost++;
    }
    print_metrics(remote_host, std::stoi(local_port), std::stoi(remote_port), reflectorPacket->sender_tos, ipHeader.ttl,
                  ipHeader.tos, &ts,
                  reflectorPacket, payload_len, nullptr, nullptr, filestream, filename);
}
void send_packet(addrinfo* remote_address_info, int idx, int fd){
    // Send the UDP packet
    SenderPacket senderPacket = craft_sender_packet(idx);
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
void await_response(int fd, std::ofstream& filestream) {
    // Read incoming datagram
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
        throw;
    } else if (incoming_msg.msg_flags & MSG_TRUNC) {
        std::cout << "Datagram too large for buffer: truncated" << std::endl;
    } else {
        auto *rec = (ReflectorPacket *)buffer;
        handle_reflector_packet(rec, incoming_msg, fd, filestream);
    }

}
int main(int argc, char **argv) {
    auto filestream = std::ofstream();
    parse_args(argc, argv);

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
        throw;
    }
    // Setup the socket options, to be able to receive TTL and TOS
    set_socket_options(fd, HDR_TTL);
    set_socket_tos(fd, snd_tos);
    // Bind the socket to a local port
    if (bind(fd, local_address_info->ai_addr, local_address_info->ai_addrlen) == -1) {
        std::cerr << strerror(errno) << std::endl;
        throw;
    }
    for(int i = 0; i < num_packets; i++){
        send_packet(remote_address_info, i, fd);
        await_response(fd, filestream);
        usleep(delay_millis*1000);
    }
    filestream.close();
}


