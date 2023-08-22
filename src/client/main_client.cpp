//
// Created by vladim0105 on 12/15/21.
//
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <signal.h>
#include "Client.h"
#include "CLI11.hpp"

Args parse_args(int argc, char **argv){
    Args args;
    args.payload_lens.push_back(50);
    args.payload_lens.push_back(250);
    args.payload_lens.push_back(450);
    args.payload_lens.push_back(650);
    args.payload_lens.push_back(850);
    args.payload_lens.push_back(1050);
    args.payload_lens.push_back(1250);
    args.payload_lens.push_back(1400);
    uint8_t tos = 0;
    CLI::App app{"Twamp-Light implementation written by Domos."};
    app.option_defaults()->always_capture_default(true);
    app.add_option("addresses", args.remote_hosts, "The address of the remote TWAMP Server.")->required();
    app.add_option("-a, --local_address", args.local_host, "The address to set up the local socket on. Auto-selects by default.");
    app.add_option("-P, --local_port", args.local_port, "The port to set up the local socket on.");
    app.add_option<std::vector<uint16_t>>("-p, --port", args.remote_ports, "The port that the remote server is listening on.")->default_str(vectorToString(args.remote_ports, " "))->check(CLI::Range(0, 65535));
    app.add_option<std::vector<uint16_t>>("-l, --payload_lens", args.payload_lens,
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
    auto opt_tos = app.add_option("-T, --tos", tos, "The TOS value (<256).")->check(CLI::Range(256))->default_str(std::to_string(args.snd_tos));
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
int main(int argc, char **argv) {
    Args args = parse_args(argc, argv);
    Client client = Client(args);
    uint16_t lost_packets = 0;
    uint16_t retries = 0;
    uint32_t index = 0;
    std::random_device rd;  //Will be used to obtain a seed for the random number engine
    std::mt19937 gen(rd()); //Standard mersenne_twister_engine seeded with rd()
    std::exponential_distribution<> d(1.0/(args.mean_inter_packet_delay*1000)); //Lambda is 1.0/mean (in microseconds)
    time_t start_time = time(NULL);
    int pipefd[2];
    if(pipe(pipefd) != 0) { // create a pipe for inter-process communication
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
        write(pipefd[1], sent_packets, strlen(sent_packets)); // send the number of sent packets to the collector
        close(pipefd[1]); // close the write-end of the pipe
        exit(EXIT_SUCCESS);
        break;
    default:
        //Parent does the packet collecting
        time_t time_of_last_received_packet = time(NULL);
        close(pipefd[1]); // close the write-end of the pipe
        while (args.num_samples == 0 || index < args.num_samples * args.remote_hosts.size())
        {
            bool response = client.awaitResponse(lost_packets);
            if (response){
                time_of_last_received_packet = time(NULL);
                index++;
            }
        }
        read(pipefd[0], sent_packets, 10);
        int packets_sent = atoi(sent_packets);
        if (args.print_digest) {
            client.printStats(packets_sent);
        }
        close(pipefd[0]); // close the read-end of the pipe
        // Kill the generator
        kill(pid, SIGKILL);
        exit(EXIT_SUCCESS);
        break;
    }

    return 0;
}
