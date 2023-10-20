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
#include <linux/net_tstamp.h>
#include "cstdlib"

void timeval_to_timestamp(const struct timeval *tv, Timestamp *ts)
{
    if (!tv || !ts)
        return;

    /* Unix time to NTP */
    ts->integer = tv->tv_sec + 2208988800uL;
    ts->fractional = (uint32_t) ((double) tv->tv_usec * ((double) (1uLL << 32) / (double) 1e6));

    ts->integer = (ts->integer);
    ts->fractional = (ts->fractional);
}

void timespec_to_timestamp(const struct timespec *tv, Timestamp *ts)
{
    if (!tv || !ts)
        return;

    /* Unix time to NTP */
    ts->integer = tv->tv_sec + 2208988800uL;
    ts->fractional = (uint32_t) ((double) tv->tv_nsec * ((double) (1uLL << 32) / (double) 1e9));
    ts->integer = (ts->integer);
    ts->fractional = (ts->fractional);
}

void timestamp_to_timeval(const Timestamp *ts, struct timeval *tv)
{
    if (!tv || !ts)
        return;

    Timestamp ts_host_ord;

    ts_host_ord.integer = (ts->integer);
    ts_host_ord.fractional = (ts->fractional);

    /* NTP to Unix time */
    tv->tv_sec = ts_host_ord.integer - 2208988800uL;
    tv->tv_usec = (uint32_t) (double) ts_host_ord.fractional * (double) 1e6 / (double) (1uLL << 32);
}

void timestamp_to_timespec(const Timestamp *ts, struct timespec *tv)
{
    if (!tv || !ts)
        return;

    Timestamp ts_host_ord;

    ts_host_ord.integer = (ts->integer);
    ts_host_ord.fractional = (ts->fractional);

    /* NTP to Unix time */
    tv->tv_sec = ts_host_ord.integer - 2208988800uL;
    tv->tv_nsec = (uint32_t) (double) ts_host_ord.fractional * (double) 1e9 / (double) (1uLL << 32);
}

Timestamp get_timestamp()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    Timestamp ts;
    timeval_to_timestamp(&tv, &ts);
    return ts;
}

uint64_t timestamp_to_usec(const Timestamp *ts)
{
    struct timeval tv;
    timestamp_to_timeval(ts, &tv);
    return (uint64_t) tv.tv_sec * 1000000 + (uint64_t) tv.tv_usec;
}

uint64_t timestamp_to_nsec(const Timestamp *ts)
{
    struct timespec tv;
    timestamp_to_timespec(ts, &tv);
    return (uint64_t) tv.tv_sec * 1000000000 + (uint64_t) tv.tv_nsec;
}

struct timespec nanosecondsToTimespec(uint64_t delay_epoch_nanoseconds)
{
    struct timespec ts;
    ts.tv_sec = delay_epoch_nanoseconds / 1000000000;
    ts.tv_nsec = (delay_epoch_nanoseconds % 1000000000);
    return ts;
}

uint64_t get_usec()
{
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
IPHeader get_ip_header(msghdr hdr)
{
    /* Get TTL/TOS values from IP header */
    uint8_t ttl = 255;
    uint8_t tos = 0;

#ifndef NO_MESSAGE_CONTROL
    struct cmsghdr *c_msg;
    for (c_msg = CMSG_FIRSTHDR(&hdr); c_msg; c_msg = (CMSG_NXTHDR(&hdr, c_msg))) {
        switch (c_msg->cmsg_level) {
        case IPPROTO_IP:
            switch (c_msg->cmsg_type) {
            case IP_TTL:
                ttl = *(int *) CMSG_DATA(c_msg);
                break;
            case IP_TOS:
                tos = *(int *) CMSG_DATA(c_msg);
                break;
            default:
                fprintf(stderr,
                        "\tWarning, unexpected data of level %i and type %i\n",
                        c_msg->cmsg_level,
                        c_msg->cmsg_type);
                break;
            }
            break;

        case IPPROTO_IPV6:
            if (c_msg->cmsg_type == IPV6_HOPLIMIT) {
                ttl = *(int *) CMSG_DATA(c_msg);
            } else {
                fprintf(stderr,
                        "\tWarning, unexpected data of level %i and type %i\n",
                        c_msg->cmsg_level,
                        c_msg->cmsg_type);
            }
            break;

        default:
            break;
        }
    }
#else
    fprintf(stdout, "No message control on that platform, so no way to find IP options\n");
#endif
    IPHeader ipHeader = {ttl, tos};
    return ipHeader;
}

void get_kernel_timestamp(msghdr incoming_msg, timespec *incoming_timestamp)
{
    struct cmsghdr *cm;
    for (cm = CMSG_FIRSTHDR(&incoming_msg); cm != NULL; cm = CMSG_NXTHDR(&incoming_msg, cm)) {
        if (cm->cmsg_level != SOL_SOCKET)
            continue;
        switch (cm->cmsg_type) {
        case SO_TIMESTAMPNS:
            memcpy(incoming_timestamp, CMSG_DATA(cm), sizeof(struct timespec));
            break;
        case SO_TIMESTAMPING:
            memcpy(incoming_timestamp, CMSG_DATA(cm), sizeof(struct timespec));
            break;
        default:
            /* Ignore other cmsg options */
            break;
        }
    }
}

void set_socket_options(int socket, uint8_t ip_ttl, uint8_t timeout_secs)
{
    /* Set socket options : timeout, IPTTL, IP_RECVTTL, IP_RECVTOS */
    uint8_t One = 1;
    int result;

    /* Set Timeout */
    struct timeval timeout = {timeout_secs, 0}; // set timeout for 2 seconds

    /* Enable socket timestamping and set the timestamp resolution to nanoseconds */
    int flags = 1;
    if (setsockopt(socket, SOL_SOCKET, SO_TIMESTAMPNS, &flags, sizeof(flags)) < 0)
        printf("ERROR: setsockopt SO_TIMESTAMPING\n");

        /* Set receive UDP message timeout value */
#ifdef SO_RCVTIMEO
    if (timeout_secs != 0) {
        result = setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, (char *) &timeout, sizeof(struct timeval));
        if (result != 0) {
            fprintf(stderr, "[PROBLEM] Cannot set the timeout value for reception.\n");
        }
    }

#else
    fprintf(stderr, "No way to set the timeout value for incoming packets on that platform.\n");
#endif

    /* Set IPTTL value to twamp standard: 255 */
#ifdef IP_TTL
    result = setsockopt(socket, IPPROTO_IP, IP_TTL, &ip_ttl, sizeof(ip_ttl));
    if (result != 0) {
        fprintf(stderr, "[PROBLEM] Cannot set the TTL value for emission.\n");
    }
#else
    fprintf(stderr, "No way to set the TTL value for leaving packets on that platform.\n");
#endif

    /* Set receive IP_TTL option */
#ifdef IP_RECVTTL
    result = setsockopt(socket, IPPROTO_IP, IP_RECVTTL, &One, sizeof(One));
    if (result != 0) {
        fprintf(stderr, "[PROBLEM] Cannot set the socket option for TTL reception.\n");
    }
#else
    fprintf(stderr, "No way to ask for the TTL of incoming packets on that platform.\n");
#endif
#ifdef IP_TOS
    result = setsockopt(socket, IPPROTO_IP, IP_TOS, &One, sizeof(One));
    if (result != 0) {
        fprintf(stderr, "[PROBLEM] Cannot set the socket option for TOS.\n");
    }
#else
    fprintf(stderr, "No way to ask for the TOS of incoming packets on that platform.\n");
#endif
    /* Set receive IP_TOS option */
#ifdef IP_RECVTOS
    result = setsockopt(socket, IPPROTO_IP, IP_RECVTOS, &One, sizeof(One));
    if (result != 0) {
        fprintf(stderr, "[PROBLEM] Cannot set the socket option for TOS reception.\n");
    }
#else
    fprintf(stderr, "No way to ask for the TOS of incoming packets on that platform.\n");
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
    fprintf(stderr, "No way to set the TOS value for leaving packets on that platform.\n");
#endif
}
bool isWithinEpsilon(double a, double b, double percentEpsilon)
{
    return (std::abs(a - b) <= (std::max(std::abs(a), std::abs(b)) * percentEpsilon));
}
Timestamp ntohts(Timestamp ts)
{
    Timestamp out = {};
    out.integer = ntohl(ts.integer);
    out.fractional = ntohl(ts.fractional);
    return out;
}
Timestamp htonts(Timestamp ts)
{
    Timestamp out = {};
    out.integer = htonl(ts.integer);
    out.fractional = htonl(ts.fractional);
    return out;
}

// Function to parse the IP:Port format
bool parseIPPort(const std::string &input, std::string &ip, uint16_t &port)
{
    size_t colon_pos = input.find(':');
    if (colon_pos == std::string::npos)
        return false;

    ip = input.substr(0, colon_pos);
    std::string port_str = input.substr(colon_pos + 1);

    int tmpport = atoi(port_str.c_str());
    if (tmpport > 0 && tmpport < 65536) {
        port = (uint16_t) tmpport;
        return true;
    } else {
        return false;
    }
}

struct msghdr make_msghdr(
    struct iovec *iov, size_t iov_len, struct sockaddr *addr, socklen_t addr_len, char *control, size_t control_len)
{
    struct msghdr message = {};
    message.msg_name = addr;
    message.msg_namelen = addr_len;
    message.msg_iov = iov;
    message.msg_iovlen = iov_len;
    message.msg_control = control;
    message.msg_controllen = control_len;
    return message;
}