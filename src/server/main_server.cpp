#include <iostream>
#include <unistd.h>
#include "CLI11.hpp"
#include "Server.h"

Args parse_args(int argc, char **argv){
    Args args;
    uint8_t tos = 0;
    CLI::App app{"Twamp-Light implementation written by Domos."};
    app.option_defaults()->always_capture_default(true);
    app.add_option("-a, --local_address", args.local_host, "The address to set up the local socket on. Auto-selects by default.");
    app.add_option("-P, --local_port", args.local_port, "The port to set up the local socket on.");
    app.add_option("-n, --num_samples", args.num_samples, "Number of samples to expect before shutdown. Set to 0 to expect unlimited samples.");
    app.add_option("-t, --timeout", args.timeout, "How long (in seconds) to keep the socket open, when no packets are incoming. Set to 0 to disable timeout.")->default_str(std::to_string(args.timeout));
    app.add_option("--sep", args.sep, "The separator to use in the output.");
    app.add_flag("--no-sync{false}", args.sync_time, "Disables time synchronization mechanism. Not RFC-compatible, so disable to make this work with other TWAMP implementations.");
    auto opt_tos = app.add_option("-T, --tos", tos, "The TOS value (<256).")->check(CLI::Range(256))->default_str(std::to_string(args.snd_tos));
    try {
        app.parse(argc, argv);
    } catch(const CLI::ParseError &e) {
        std::exit((app).exit(e));
    }

    if(*opt_tos){
        args.snd_tos = tos - (((tos & 0x2) >> 1) & (tos & 0x1));
    }
    return args;
}

int main(int argc, char **argv) {
    Args args = parse_args(argc, argv);
    Server server = Server(args);
    server.listen();
}
