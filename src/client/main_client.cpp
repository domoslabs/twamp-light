//
// Created by vladim0105 on 12/15/21.
//
#include <unistd.h>
#include <fcntl.h>              /* Obtain O_* constant definitions */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <poll.h>
#include "Client.h"
#include "CLI11.hpp"

// Function to parse the IP:Port format
bool parseIPPort(const std::string& input, std::string& ip, uint16_t& port) {
    size_t colon_pos = input.find(':');
    if (colon_pos == std::string::npos) return false;

    ip = input.substr(0, colon_pos);
    std::string port_str = input.substr(colon_pos + 1);

    int tmpport = atoi(port_str.c_str());
    if (tmpport > 0 && tmpport < 65536) {
        port = (uint16_t)tmpport;
        return true;
    } else {
        return false;
    }
}

Args parse_args(int argc, char **argv){
    Args args;
    CLI::App app{"Twamp-Light implementation written by Domos."};
    app.option_defaults()->always_capture_default(true);
    app.add_option("-a, --local_address", args.local_host, "The address to set up the local socket on. Auto-selects by default.");
    app.add_option("-P, --local_port", args.local_port, "The port to set up the local socket on.");
    app.add_option("-l, --payload_lens", args.payload_lens,
            "The payload length. Must be in range (42, 1473). Can be multiple values, in which case it will be sampled randomly.")
            ->default_str(vectorToString(args.payload_lens, " "))->check(CLI::Range(42, 1473));
    app.add_option("-n, --num_samples", args.num_samples, "Number of samples to expect. Set to 0 for unlimited.");
    app.add_option("-t, --timeout", args.timeout, "How long (in seconds) to wait for response before aborting.")->default_str(std::to_string(args.timeout));
    app.add_option("-s, --seed", args.seed, "Seed for the RNG. 0 means random.");
    app.add_flag("--print-digest{true}", args.print_digest, "Prints a statistical summary at the end.");
    app.add_option("--print-RTT-only", args.print_RTT_only, "Prints only the RTT values.");
    app.add_option("--sep", args.sep, "The separator to use in the output.");
    app.add_flag("--sync{true}", args.sync_time, "Disables time synchronization mechanism. Not RFC-compatible, so disable to make this work with other TWAMP implementations.");
    app.add_option("-i, --mean_inter_packet_delay", args.mean_inter_packet_delay, "The mean inter-packet delay in milliseconds.")->default_str(std::to_string(args.mean_inter_packet_delay));
    uint8_t tos = 0;
    auto opt_tos = app.add_option("-T, --tos", tos, "The TOS value (<256).")->check(CLI::Range(256))->default_str(std::to_string(args.snd_tos));

    std::vector<std::string> ipPortStrs;
    app.add_option("addresses", ipPortStrs, "IPs and Ports in the format IP:Port")
        ->required()
        ->check([&args](const std::string& str) {
            std::string ip;
            uint16_t port;
            if (!parseIPPort(str, ip, port)) {
                return "Address must be in the format IP:Port";
            }
            args.remote_hosts.push_back(ip);
            args.remote_ports.push_back(port);
            return "";
        });

    try{
        app.parse(argc, argv);
    }catch(const CLI::ParseError &e) {
        std::exit((app).exit(e));
    }

    if(*opt_tos){
        args.snd_tos = tos - (((tos & 0x2) >> 1) & (tos & 0x1));
    }
    return args;
}

void handle_sigchld(int sig) {
    int saved_errno = errno;
    while (waitpid((pid_t)(-1), 0, WNOHANG) > 0) {}
    errno = saved_errno;
}

int main(int argc, char **argv) {
    signal(SIGCHLD, handle_sigchld);
    Args args = parse_args(argc, argv);
    Client client = Client(args);
    uint16_t lost_packets = 0;
    uint32_t index = 0;
    std::random_device rd;  //Will be used to obtain a seed for the random number engine
    std::mt19937 gen(rd()); //Standard mersenne_twister_engine seeded with rd()
    std::exponential_distribution<> d(1.0/(args.mean_inter_packet_delay*1000)); //Lambda is 1.0/mean (in microseconds)
    time_t start_time = time(NULL);
    time_t expected_time_of_last_packet_generation = start_time + args.num_samples * args.mean_inter_packet_delay / 1000;
    int pipefd[2];
    if(pipe2(pipefd, O_CLOEXEC) != 0) { // create a pipe for inter-process communication
        std::cerr << "Pipe failed." << std::endl;
    }

    pid_t pid;
    pid = fork();
    char sent_packets[10];
    
    switch (pid)
    {
    case -1:
        std::cerr << "Fork failed." << std::endl;
        break;
    case 0:
        //Child does the packet generating
        close(pipefd[0]); // close the read-end of the pipe
        while (args.num_samples == 0 || index < args.num_samples) {
            size_t payload_len = *select_randomly(args.payload_lens.begin(), args.payload_lens.end(), args.seed);
            int delay = std::max((double)std::min((double)d(gen), 10000000.0), 0.0);
            client.sendPacket(index, payload_len);
            index++;
            usleep(delay);
        }
        sprintf(sent_packets, "%09d", index);
        // send the number of sent packets to the collector
        if (write(pipefd[1], sent_packets, strlen(sent_packets)) <= 0) {
            perror("write");
            return EXIT_FAILURE;
        } 
        close(pipefd[1]); // close the write-end of the pipe
        return EXIT_SUCCESS;
        break;
    default:
        //Parent does the packet collecting
        time_t time_of_last_received_packet = time(NULL);
        close(pipefd[1]); // close the write-end of the pipe
        while ((time(NULL) < expected_time_of_last_packet_generation || time(NULL) - time_of_last_received_packet < args.timeout) && // timeout if no packet received for timeout seconds
            (args.num_samples == 0 || index < args.num_samples * args.remote_hosts.size())) // run forever if num_samples is 0, otherwise run until num_samples is reached
        {
            bool response = client.awaitResponse(lost_packets);
            if (response){
                time_of_last_received_packet = time(NULL);
                index++;
            }
        }
        int status;
        struct pollfd waiter = {.fd = pipefd[0], .events = POLLIN, .revents = 0};
        switch (poll(&waiter, 1, 100)) {
        case 0:
            std::cerr << "The fifo timed out." << std::endl;
            kill(pid, SIGKILL);
            waitpid(pid, &status, 0);
            break;
        case 1:
            if (waiter.revents & POLLIN) {

                ssize_t len = read(pipefd[0], sent_packets, 9);
                if (len < 0) {
                    perror("read");
                    return EXIT_FAILURE;
                }
                sent_packets[len] = '\0';
                //printf("Read: %s\n", sent_packets);
                int packets_sent = atoi(sent_packets);
                if (args.print_digest) {
                    client.printStats(packets_sent);
                }
                close(pipefd[0]); // close the read-end of the pipe
                // Kill the generator
                std::cerr << "Kill the generator." << std::endl;
                kill(pid, SIGKILL);
                waitpid(pid, &status, 0);
                return EXIT_SUCCESS;
                break;
            } else if (waiter.revents & POLLERR) {
                puts("Got a POLLERR");
                kill(pid, SIGKILL);
                waitpid(pid, &status, 0);
                return EXIT_FAILURE;
            } else if (waiter.revents & POLLHUP) {
            // Writer closed its end
                kill(pid, SIGKILL);
                waitpid(pid, &status, 0);
                goto closed;
            }
            break;
        default:
            perror("poll");
            kill(pid, SIGKILL);
            waitpid(pid, &status, 0);
            return EXIT_FAILURE;
        }
        closed:
        if (close(pipefd[0]) < 0) {
            perror("close");
            return EXIT_FAILURE;
        }
    }
    return 0;
}
