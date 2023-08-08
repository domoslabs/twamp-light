/*
 * Modified by Domos, original:
 *
 * Name: Emma Mirică
 * Project: TWAMP Protocol
 * Class: OSS
 * Email: emma.mirica@cti.pub.ro
 * Contributions: stephanDB
 *
 * Source: timestamp.c
 * Note: contains helpful functions to get the timestamp
 * in the required TWAMP format.
 *
 */

#include "utils.hpp"
#include <cinttypes>
#include <sys/time.h>
#include <arpa/inet.h>
#include <cstdio>
#include <cstring>
#include <iostream>
#include "cstdlib"

void timeval_to_timestamp(const struct timeval *tv, Timestamp *ts) {
    if (!tv || !ts)
        return;

    /* Unix time to NTP */
    ts->integer = tv->tv_sec + 2208988800uL;
    ts->fractional = (uint32_t) ((double) tv->tv_usec * ((double) (1uLL << 32)
                                                         / (double) 1e6));

    ts->integer = (ts->integer);
    ts->fractional = (ts->fractional);
}

void timestamp_to_timeval(const Timestamp *ts, struct timeval *tv) {
    if (!tv || !ts)
        return;

    Timestamp ts_host_ord;

    ts_host_ord.integer = (ts->integer);
    ts_host_ord.fractional = (ts->fractional);

    /* NTP to Unix time */
    tv->tv_sec = ts_host_ord.integer - 2208988800uL;
    tv->tv_usec = (uint32_t) (double) ts_host_ord.fractional * (double) 1e6
                  / (double) (1uLL << 32);
}

Timestamp get_timestamp() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    Timestamp ts;
    timeval_to_timestamp(&tv, &ts);
    return ts;
}

uint64_t timestamp_to_usec(const Timestamp *ts) {
    struct timeval tv;
    timestamp_to_timeval(ts, &tv);
    return (uint64_t) tv.tv_sec * 1000000 + (uint64_t) tv.tv_usec;
}
uint64_t get_usec() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t) tv.tv_sec * 1000000 + (uint64_t) tv.tv_usec;
}
/**
 * Session-Reflector implementations SHOULD fetch
      the TTL/Hop Limit value from the IP header of the packet,
      replacing the value of 255 set by the Session-Sender.  If an
      implementation does not fetch the actual TTL value (the only good
      reason not to do so is an inability to access the TTL field of
      arriving packets), it MUST set the Sender TTL value as 255.
 */
IPHeader get_ip_header(msghdr hdr) {
    /* Get TTL/TOS values from IP header */
    uint8_t ttl = 255;
    uint8_t tos = 0;

#ifndef NO_MESSAGE_CONTROL
    struct cmsghdr *c_msg;
    for (c_msg = CMSG_FIRSTHDR(&hdr); c_msg;
         c_msg = (CMSG_NXTHDR(&hdr, c_msg))) {
        std::cout << "c_msg->cmsg_level: " << c_msg->cmsg_level << std::endl;
        if ((c_msg->cmsg_level == IPPROTO_IP && c_msg->cmsg_type == IP_TTL)
            || (c_msg->cmsg_level == IPPROTO_IPV6
                && c_msg->cmsg_type == IPV6_HOPLIMIT)) {
            ttl = *(int *) CMSG_DATA(c_msg);

        } else if (c_msg->cmsg_level == IPPROTO_IP
                   && c_msg->cmsg_type == IP_TOS) {
            tos = *(int *) CMSG_DATA(c_msg);

        } else {
            fprintf(stderr,
                    "\tWarning, unexpected data of level %i and type %i\n",
                    c_msg->cmsg_level, c_msg->cmsg_type);
        }
    }
#else
    fprintf(stdout,
            "No message control on that platform, so no way to find IP options\n");
#endif
    IPHeader ipHeader = {
            ttl,
            tos
    };
    return ipHeader;
}

void set_socket_options(int socket, uint8_t ip_ttl, uint8_t timeout_secs) {
    /* Set socket options : timeout, IPTTL, IP_RECVTTL, IP_RECVTOS */
    uint8_t One = 1;
    int result;

    /* Set Timeout */
    struct timeval timeout = {timeout_secs, 0};   //set timeout for 2 seconds

    /* Set receive UDP message timeout value */
#ifdef SO_RCVTIMEO
    if(timeout_secs != 0){
        result = setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO,
                            (char *) &timeout, sizeof(struct timeval));
        if (result != 0) {
            fprintf(stderr,
                    "[PROBLEM] Cannot set the timeout value for reception.\n");
        }
    }

#else
    fprintf(stderr,
            "No way to set the timeout value for incoming packets on that platform.\n");
#endif

    /* Set IPTTL value to twamp standard: 255 */
#ifdef IP_TTL
    result = setsockopt(socket, IPPROTO_IP, IP_TTL, &ip_ttl, sizeof(ip_ttl));
    if (result != 0) {
        fprintf(stderr, "[PROBLEM] Cannot set the TTL value for emission.\n");
    }
#else
    fprintf(stderr,
            "No way to set the TTL value for leaving packets on that platform.\n");
#endif

    /* Set receive IP_TTL option */
#ifdef IP_RECVTTL
    result = setsockopt(socket, IPPROTO_IP, IP_RECVTTL, &One, sizeof(One));
    if (result != 0) {
        fprintf(stderr,
                "[PROBLEM] Cannot set the socket option for TTL reception.\n");
    }
#else
    fprintf(stderr,
            "No way to ask for the TTL of incoming packets on that platform.\n");
#endif
#ifdef IP_TOS
    result = setsockopt(socket, IPPROTO_IP, IP_TOS, &One, sizeof(One));
    if (result != 0) {
        fprintf(stderr,
                "[PROBLEM] Cannot set the socket option for TOS reception.\n");
    }
#else
    fprintf(stderr,
            "No way to ask for the TOS of incoming packets on that platform.\n");
#endif
    /* Set receive IP_TOS option */
#ifdef IP_RECVTOS
    result = setsockopt(socket, IPPROTO_IP, IP_RECVTOS, &One, sizeof(One));
    if (result != 0) {
        fprintf(stderr,
                "[PROBLEM] Cannot set the socket option for TOS reception.\n");
    }
#else
    fprintf(stderr,
            "No way to ask for the TOS of incoming packets on that platform.\n");
#endif
}
void set_socket_tos(int socket, uint8_t ip_tos)
{
    /* Set socket options : IP_TOS */
    int result;

    /* Set IP TOS value */
#ifdef IP_TOS
    result = setsockopt(socket, IPPROTO_IP, IP_TOS, &ip_tos, sizeof(ip_tos));
    if (result != 0) {
        fprintf(stderr, "[PROBLEM] Cannot set the TOS value for emission.\n");
    }
#else
    fprintf(stderr,
            "No way to set the TOS value for leaving packets on that platform.\n");
#endif
}
bool isWithinEpsilon(double a, double b, double percentEpsilon)
{
    return (std::abs(a - b) <= (std::max(std::abs(a), std::abs(b)) * percentEpsilon));
}
Timestamp ntohts(Timestamp ts){
    Timestamp out = {};
    out.integer = ntohl(ts.integer);
    out.fractional = ntohl(ts.fractional);
    return out;
}
Timestamp htonts(Timestamp ts){
    Timestamp out = {};
    out.integer = htonl(ts.integer);
    out.fractional = htonl(ts.fractional);
    return out;
}