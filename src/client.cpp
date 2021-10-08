#include <iostream>
#include <cerrno>
#include <cstring>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/uio.h>
#include "twamp_light.hpp"
#include <CLI11.hpp>
struct Args {
    std::string remote_host;
    std::string remote_port = "443";
    std::string local_host;
    std::string local_port = "445";
    std::vector<uint16_t> payload_lens = std::vector<uint16_t>();
    uint8_t snd_tos = 0;
    uint8_t dscp_snd = 0;
    uint32_t delay_millis = 200;
    uint32_t num_samples = 10;
    uint8_t timeout = 10;
    uint32_t seed = 0;
};
Args parse_args(int argc, char **argv){
    Args args;
    args.payload_lens.push_back(50);
    args.payload_lens.push_back(100);
    args.payload_lens.push_back(150);
    uint8_t dscp = 0, tos = 0;
    CLI::App app{"Twamp-Light implementation written by Domos."};
    app.option_defaults()->always_capture_default(true);
    app.add_option("address", args.remote_host, "The address of the remote TWAMP Server.");
    app.add_option("-a, --local_address", args.local_host, "The address to set up the local socket on. Auto-selects by default.");
    app.add_option("-P, --local_port", args.local_port, "The port to set up the local socket on.");
    app.add_option("-p, --port", args.remote_port, "The port that the remote server is listening on.");
    app.add_option<std::vector<uint16_t>>("-l, --payload_lens", args.payload_lens,
            "The payload length. Must be in range (42, 1473). Can be multiple values, in which case it is selected randomly.")
            ->default_str(vectorToString(args.payload_lens, " "))->check(CLI::Range(42, 1473));
    app.add_option("-n, --num_samples", args.num_samples, "Number of samples to expect.");
    app.add_option("-t, --timeout", args.timeout, "How long (in seconds) to keep the socket open, when no packets are incoming.")->default_str(std::to_string(args.timeout));
    app.add_option("-d, --delay", args.delay_millis, "How long (in millis) to wait between sending each packet.");
    app.add_option("-s, --seed", args.seed, "Seed for the RNG. 0 means random.");
    auto opt_tos = app.add_option("-T, --tos", tos, "The TOS value (<256).")->check(CLI::Range(256))->default_str(std::to_string(args.snd_tos));
    auto opt_dscp = app.add_option("-D, --dscp", dscp, "The DSCP value (<64).")->check(CLI::Range(64))->default_str(std::to_string(args.dscp_snd));
    opt_tos->excludes(opt_dscp);
    opt_dscp->excludes(opt_tos);
    try{
        app.parse(argc, argv);
    }catch(const CLI::ParseError &e) {
        std::exit((app).exit(e));
    }

    if(*opt_tos){
        args.snd_tos = tos - (((tos & 0x2) >> 1) & (tos & 0x1));
    }
    if(*opt_dscp){
        args.snd_tos = dscp << 2;
    }
    return args;
}

SenderPacket craft_sender_packet(int idx){
    SenderPacket packet = {};
    packet.seq_number = htonl(idx); //TODO Use an index value or something here
    packet.time = get_timestamp();
    packet.error_estimate = htons(0x8001); // Sync = 1, Multiplier = 1.
    return packet;
}
void handle_reflector_packet(ReflectorPacket *reflectorPacket, msghdr msghdr, int fd, size_t payload_len, uint16_t packet_loss, const Args& args) {
    IPHeader ipHeader = get_ip_header(msghdr);
    TWAMPTimestamp ts = get_timestamp();

    char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
    if (getnameinfo((sockaddr *)msghdr.msg_name, msghdr.msg_namelen, hbuf, sizeof(hbuf), sbuf,
                    sizeof(sbuf), NI_NUMERICHOST | NI_NUMERICSERV) != 0){
        std::cerr << "Error in getnameinfo" << std::endl;
    }
    print_metrics(hbuf, std::stoi(args.local_port), std::stol(sbuf), reflectorPacket->sender_tos, ipHeader.ttl,
                  ipHeader.tos, &ts,
                  reflectorPacket, payload_len, packet_loss, nullptr, nullptr);
}
void send_packet(addrinfo* remote_address_info, int idx, int fd, size_t payload_len){
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
bool await_response(int fd, size_t payload_len, uint16_t  packet_loss, const Args& args) {
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
        if(errno == 11){
            return false;
        } else {
            printf("%s", strerror(errno));
        }
        throw;
    } else if (incoming_msg.msg_flags & MSG_TRUNC) {
        std::cout << "Datagram too large for buffer: truncated" << std::endl;
    } else {
        auto *rec = (ReflectorPacket *)buffer;
        handle_reflector_packet(rec, incoming_msg, fd, payload_len, packet_loss, args);
    }
    return true;
}
int main(int argc, char **argv) {
    Args args = parse_args(argc, argv);

    // Construct remote socket address
    struct addrinfo hints{};
    memset(&hints,0,sizeof(hints));
    hints.ai_family=AF_INET; //TODO IPv6
    hints.ai_socktype=SOCK_DGRAM;
    hints.ai_protocol=0;
    hints.ai_flags=AI_PASSIVE|AI_ADDRCONFIG;
    struct addrinfo* remote_address_info=nullptr;
    struct addrinfo* local_address_info=nullptr;
    int err=getaddrinfo(args.remote_host.c_str(),args.remote_port.c_str(),&hints,&remote_address_info);
    int err2=getaddrinfo(args.local_host.empty()? nullptr : args.local_host.c_str(),args.local_port.c_str(),&hints,&local_address_info);
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
    set_socket_options(fd, HDR_TTL, args.timeout);
    set_socket_tos(fd, args.snd_tos);
    // Bind the socket to a local port
    if (bind(fd, local_address_info->ai_addr, local_address_info->ai_addrlen) == -1) {
        std::cerr << strerror(errno) << std::endl;
        throw;
    }
    uint16_t lost_packets = 0;
    for(int i = 0; i < args.num_samples; i++){
        size_t payload_len = *select_randomly(args.payload_lens.begin(), args.payload_lens.end(), args.seed);
        send_packet(remote_address_info, i, fd, payload_len);
        bool response = await_response(fd, payload_len, lost_packets, args);
        if(!response){
            lost_packets++;
        }
        usleep(args.delay_millis*1000);
    }
}


