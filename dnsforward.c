// DNS forwarder by Daniel Mendler <mail@daniel-mendler.de>
#define _BSD_SOURCE
#define _XOPEN_SOURCE
#include <arpa/inet.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <idna.h>
#include <ctype.h>
#include <getopt.h>
#include <pwd.h>
#include <time.h>
#include <signal.h>
#include "utils.h"

static char query[0x400], ans[0x400];

struct zone {
        char*              name;
        struct sockaddr_in addr;
};

static void usage(const char* prog) {
        fprintf(stderr, "Usage: %s [-d] [-p port] ip:port[,zone]...\n", prog);
        exit(1);
}

int main(int argc, char* argv[]) {
        uint16_t port = 53;
        int daemonize = 0, verbose = 0;
        char c;
        FILE *log = stdout;
        while ((c = getopt(argc, argv, "hvdp:l:")) != -1) {
                switch (c) {
                case 'p': port = atoi(optarg); break;
                case 'd': daemonize = 1;       break;
                case 'v': ++verbose;           break;
                case 'l':
                        log = fopen(optarg, "a");
                        DIE(log, "Could not open log file");
                        break;
                default:
                        usage(argv[0]);
                        break;
                }
        }

        if (argc - optind < 1)
                usage(argv[0]);

        int numzones = argc - optind;
        struct zone zones[numzones];
        memset(zones, 0, sizeof (struct zone) * numzones);
        for (int i = 0; i < numzones; ++i) {
                char* p = strchr(argv[optind + i], ',');
                if (p) {
                        FATAL(strlen(p) > 1, "Zone name must not be empty.");
                        zones[i].name = p + 1;
                        *p = 0;
                }
                p = strchr(argv[optind + i], ':');
                if (p) {
                        zones[i].addr.sin_port = htons(atoi(p + 1));
                        *p = 0;
                        FATAL(zones[i].addr.sin_port, "Invalid port.");
                } else {
                        zones[i].addr.sin_port = htons(53);
                }
                FATAL(inet_pton(AF_INET, argv[optind + i], &zones[i].addr.sin_addr), "Invalid address.");
                zones[i].addr.sin_family = AF_INET;
        }

        setvbuf(log, NULL, _IONBF, 0);

        int srvsock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
        DIE(srvsock, socket);

        int clisock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
        DIE(clisock, socket);

        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        setsockopt(clisock, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(struct timeval));

        struct sockaddr_in6 sa = {
                .sin6_family = AF_INET6,
                .sin6_port = htons(port),
                .sin6_addr = in6addr_any
        };
        DIE(!bind(srvsock, (struct sockaddr*)&sa, sizeof(sa)), bind);
        DIE(!daemonize || !daemon(0, 0), daemon);
        drop_privs();

        struct sigaction sig = { .sa_handler = exit };
        sigemptyset(&sig.sa_mask);
        DIE(!sigaction(SIGINT, &sig, 0) || !sigaction(SIGTERM, &sig, 0), "sigaction");

        for (;;) {
                struct sockaddr_storage ss;
                socklen_t sslen = sizeof (ss);
                ssize_t querysize = recvfrom(srvsock, query, sizeof (query), 0, (struct sockaddr*)&ss, &sslen);
                if (querysize < 0) {
                        perror("recvfrom");
                        continue;
                }

                time_t now = time(0);

                struct dnsheader* h = (struct dnsheader*)query;
                uint16_t error = 0;
                ASSUME(ntohs(h->qdcount) >= 1, NOTIMP);

                char name[512];
                char *q = dns2str(name, sizeof(name), query + sizeof (struct dnsheader), query + querysize);
                ASSUME(q && q + 4 <= query + querysize, FORMAT);

                uint16_t qtype = ntohs(*((uint16_t*)q));
                uint16_t qclass = ntohs(*((uint16_t*)q + 1));
                ASSUME(qclass == CLASS_INET, NOTIMP);
                q += 4;

                LOG("%10ld Q %-5s %s\n", now, type2str(qtype), name);

                size_t anssize = 0;
                for (int i = 0; i < numzones; ++i) {
                        if (!zones[i].name || subdomain(name, zones[i].name) >= 0) {
                                ASSUME(sendto(clisock, query, querysize, 0, (struct sockaddr*)&zones[i].addr, sizeof (zones[i].addr)) >= 0, SERVER);

                                struct sockaddr_storage zone_ss;
                                socklen_t zone_sslen = sizeof (zone_ss);
                                anssize = recvfrom(clisock, ans, sizeof (query), 0, (struct sockaddr*)&zone_ss, &zone_sslen);
                                ASSUME(anssize > 0, SERVER);
                                break;
                        }
                }

        error:
                if (error || anssize == 0) {
                        LOG("%10ld E %d\n", now, error);
                        h->qdcount = h->ancount = h->nscount = h->arcount = 0;
                        h->flags |= htons(FLAG_QR | error);
                        h->flags &= ~htons(FLAG_RD);
                        memcpy(ans, h, anssize = sizeof (struct dnsheader));
                }

                if (sendto(srvsock, ans, anssize, 0, (struct sockaddr*)&ss, sslen) < 0)
                        perror("sendto");
        }
}
