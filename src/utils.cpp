/*
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

#include "twamp_light.h"
#include "fort.hpp"
#include <inttypes.h>
#include <sys/time.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <iostream>

void timeval_to_timestamp(const struct timeval *tv, TWAMPTimestamp *ts) {
    if (!tv || !ts)
        return;

    /* Unix time to NTP */
    ts->integer = tv->tv_sec + 2208988800uL;
    ts->fractional = (uint32_t) ((double) tv->tv_usec * ((double) (1uLL << 32)
                                                         / (double) 1e6));

    ts->integer = htonl(ts->integer);
    ts->fractional = htonl(ts->fractional);
}

void timestamp_to_timeval(const TWAMPTimestamp *ts, struct timeval *tv) {
    if (!tv || !ts)
        return;

    TWAMPTimestamp ts_host_ord;

    ts_host_ord.integer = ntohl(ts->integer);
    ts_host_ord.fractional = ntohl(ts->fractional);

    /* NTP to Unix time */
    tv->tv_sec = ts_host_ord.integer - 2208988800uL;
    tv->tv_usec = (uint32_t) (double) ts_host_ord.fractional * (double) 1e6
                  / (double) (1uLL << 32);
}

TWAMPTimestamp get_timestamp() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    TWAMPTimestamp ts;
    timeval_to_timestamp(&tv, &ts);
    return ts;
}

uint64_t get_usec(const TWAMPTimestamp *ts) {
    struct timeval tv;
    timestamp_to_timeval(ts, &tv);
    return (uint64_t) tv.tv_sec * 1000000 + (uint64_t) tv.tv_usec;
}

void print_chanims_stats(char *interface) {
    FILE *fp;
    char path[1035];
    char command[128];
    sprintf(command, "/usr/sbin/wlctl -i %s chanim_stats", interface);
    fp = popen(command, "r");
    if (fp == NULL) {
        printf("Failed to run wlctl chanim_stats\n");
    } else {
        int line = 0;
        while (fgets(path, sizeof(path) - 1, fp) != NULL) {
            if (line == 2) {
                for (int i = 0; i < 1035; i++) {
                    if (path[i] == '\t') {
                        path[i] = ',';
                    } else if (path[i] == 0) {
                        break;
                    } else if (path[i] == '\n') {
                        path[i] = ',';
                    }
                }
                fprintf(stderr, "%s", path);
            }
            line++;
        }
        pclose(fp);
    }
}

void print_sta_info(char *interface, char *mac) {
    FILE *fp;
    char path[1035];
    char command[128];
    sprintf(command, "/usr/sbin/wlctl -i %s sta_info %s", interface, mac);
    fp = popen(command, "r");
    if (fp == NULL) {
        printf("Failed to run %s\n", command);
    } else {
        int line = 0;
        while (fgets(path, sizeof(path) - 1, fp) != NULL) {
            line++;
            if (line <= 8) continue;
            if (line >= 37) break;

            char *point = strchr(path, ':');
            if (point == NULL) {
                continue;
            }
            point += 2;
            char *tmp = point;
            if (line == 22 || line == 23) {
                while (*tmp != 0) {
                    if (*tmp == ' ') {
                        *tmp = 0;
                        break;
                    }
                    tmp++;
                }
            } else {
                while (*tmp != 0) {
                    if (*tmp == ' ') {
                        *tmp = ',';
                    }
                    if (*tmp == '\n') {
                        *tmp = 0;
                        break;
                    }
                    tmp++;
                }
            }

            fprintf(stderr, "%s,", point);

        }
        pclose(fp);
    }
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

uint64_t print_metrics(const char *server, uint16_t snd_port, uint16_t rcv_port, uint8_t snd_tos,
                       uint8_t sw_ttl, uint8_t sw_tos,
                       TWAMPTimestamp *recv_resp_time,
                       const ReflectorPacket *pack, uint16_t plen, char *device_mac, char *radio_interface) {
    /* Compute timestamps in usec */
    uint64_t t_sender_usec = get_usec(&pack->sender_time);
    uint64_t t_receive_usec = get_usec(&pack->receive_time);
    uint64_t t_reflsender_usec = get_usec(&pack->time);
    uint64_t t_recvresp_usec = get_usec(recv_resp_time);

    /* Compute delays */
    int64_t fwd = t_receive_usec - t_sender_usec;
    int64_t swd = t_recvresp_usec - t_reflsender_usec;
    int64_t intd = t_reflsender_usec - t_receive_usec;
    int64_t rtt = t_recvresp_usec - t_sender_usec;
    char sync = 'Y';
    if ((fwd < 0) || (swd < 0)) {
        sync = 'N';
    }

    /*Sequence number */
    uint32_t rcv_sn = ntohl(pack->seq_number);
    uint32_t snd_sn = ntohl(pack->sender_seq_number);

    if (device_mac != NULL && radio_interface != NULL) {
        print_chanims_stats(radio_interface);
        print_sta_info(radio_interface, device_mac);
        fprintf(stdout, "%s,%s,", device_mac, radio_interface);
    }
    fort::char_table table;
    table.set_border_style(FT_EMPTY_STYLE);
    table << fort::header
            << "Time"<< "IP"<< "Snd#"<< "Rcv#"<< "SndPt"<< "RscPt"<< "Sync"<< "FW_TTL"
            << "SW_TTL"<< "SndTOS"<< "FW_TOS"<< "SW_TOS"<< "RTT [ms]"<< "IntD [ms]"
            << "FWD [ms]"<< "SWD [ms]"<< "PLEN"
          << fort::endr;
    table << fort::header
            << std::fixed << (double) t_sender_usec * 1e-3<< server<< snd_sn<< rcv_sn<< snd_port
            << rcv_port<< sync<< unsigned(pack->sender_ttl)<< unsigned(sw_ttl)
            << unsigned(snd_tos)<< '-'<< unsigned(sw_tos)<<(double) rtt * 1e-3
            <<(double) intd* 1e-3<< (double) fwd * 1e-3<< (double) swd * 1e-3<< plen
          << fort::endr;
    std::cout << table.to_string() << std::flush;
    return t_recvresp_usec - t_sender_usec;

}


void print_metrics_server(const char *addr_cl, uint16_t snd_port, uint16_t rcv_port,
                          uint8_t snd_tos, uint8_t fw_tos,
                          const ReflectorPacket *pack) {

    /* Compute timestamps in usec */
    uint64_t t_sender_usec1 = get_usec(&pack->sender_time);
    uint64_t t_receive_usec1 = get_usec(&pack->receive_time);
    uint64_t t_reflsender_usec1 = get_usec(&pack->time);

    /* Compute delays */
    int64_t fwd1 = t_receive_usec1 - t_sender_usec1;
    int64_t intd1 = t_reflsender_usec1 - t_receive_usec1;
    char sync1 = 'Y';
    if (fwd1 < 0) {
        sync1 = 'N';
    }
    /* Sequence number */
    uint32_t snd_nb = ntohl(pack->sender_seq_number);
    uint32_t rcv_nb = ntohl(pack->seq_number);

    /* Sender TOS with ECN from FW TOS */
    snd_tos =
            snd_tos + (fw_tos & 0x3) - (((fw_tos & 0x2) >> 1) & (fw_tos & 0x1));
    fort::char_table table;
    table.set_border_style(FT_EMPTY_STYLE);
    table << fort::header
          << "Time" << "IP"<< "Snd#"<< "Rcv#"<< "SndPt"<< "RscPt"<< "Sync"<< "FW_TTL"
          << "SndTOS"<< "FW_TOS"<< "IntD [ms]"<< "FWD [ms]"
          << fort::endr;
    table << fort::header
            << std::fixed << (double) t_sender_usec1 << addr_cl  << snd_nb
            <<rcv_nb << snd_port << rcv_port << sync1 << unsigned(pack->sender_ttl)<< unsigned(snd_tos)
            <<unsigned(fw_tos) << (double) intd1 * 1e-3 << (double) fwd1 * 1e-3
            << fort::endr;
    std::cout << table.to_string() << std::flush;

}

void set_socket_options(int socket, uint8_t ip_ttl) {
    /* Set socket options : timeout, IPTTL, IP_RECVTTL, IP_RECVTOS */
    uint8_t One = 1;
    int result;

    /* Set Timeout */
    struct timeval timeout = {LOSTTIME, 0};   //set timeout for 2 seconds

    /* Set receive UDP message timeout value */
#ifdef SO_RCVTIMEO
/*    result = setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO,
                        (char *) &timeout, sizeof(struct timeval));
    if (result != 0) {
        fprintf(stderr,
                "[PROBLEM] Cannot set the timeout value for reception.\n");
    }*/
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