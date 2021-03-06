// DNS forwarder by Daniel Mendler <mail@daniel-mendler.de>
#include "utils.h"
#include "list.h"

struct zone {
        char*               name;
        struct sockaddr_in6 addr;
};

struct entry {
        struct dnsheader    header;
        struct zone*        zone;
        struct sockaddr_in6 addr;
        struct list_head    list;
        time_t              time;
};

static char buf[PACKET_SIZE];
LIST_HEAD(queue);

static void usage(const char* prog) {
        fprintf(stderr, "Usage: %s [-dhv] [-p port] 'zone ip port'...\n", prog);
        exit(1);
}

static void send_error(int sock, struct dnsheader* h, int error, struct sockaddr* ss, socklen_t sslen) {
        h->qdcount = h->ancount = h->nscount = h->arcount = 0;
        h->flags |= htons(FLAG_QR | error);
        h->flags &= ~htons(FLAG_RD);
        if (sendto(sock, h, sizeof (struct dnsheader), 0, ss, sslen) < 0)
                perror("sendto");
}

int main(int argc, char* argv[]) {
        uint16_t port = 53;
        int daemonize = 0, verbose = 0;
        char c;
        FILE* log = stdout;
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
                char* p;
                while ((p = strsep(&argv[optind + i], " "))) {
                        int port;
                        struct in_addr addr;
                        if (!zones[i].addr.sin6_family && inet_pton(AF_INET6, p, &zones[i].addr.sin6_addr)) {
                                zones[i].addr.sin6_family = AF_INET6;
                        } else if (!zones[i].addr.sin6_family && inet_pton(AF_INET, p, &addr)) {
                                zones[i].addr.sin6_family = AF_INET6;
                                zones[i].addr.sin6_addr.s6_addr32[3] = addr.s_addr;
                                zones[i].addr.sin6_addr.s6_addr16[5]= 0xFFFF;
                        } else if (!zones[i].addr.sin6_port && (port = atoi(p))) {
                                zones[i].addr.sin6_port = htons(port);
                        } else if (!zones[i].name) {
                                zones[i].name = p;
                        } else {
                                FATAL(1, "Invalid zone specification");
                        }
                }
                if (!zones[i].addr.sin6_port)
                        zones[i].addr.sin6_port = htons(53);
                if (!zones[i].addr.sin6_family) {
                        zones[i].addr.sin6_family = AF_INET6;
                        zones[i].addr.sin6_addr = in6addr_loopback;
                }
                FATAL(!zones[i].name || strlen(zones[i].name) > 1, "Zone name must not be empty.");
        }

        setvbuf(log, NULL, _IONBF, 0);

        int sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
        DIE(sock, socket);

        struct sockaddr_in6 sa = {
                .sin6_family = AF_INET6,
                .sin6_port = htons(port),
                .sin6_addr = in6addr_any
        };
        DIE(!bind(sock, (struct sockaddr*)&sa, sizeof(sa)), bind);
        DIE(!daemonize || !daemon(0, 0), daemon);
        drop_privs();
        struct sigaction sig = { .sa_handler = exit };
        sigemptyset(&sig.sa_mask);
        DIE(!sigaction(SIGINT, &sig, 0) || !sigaction(SIGTERM, &sig, 0), sigaction);

        for (;;) {
                struct sockaddr_storage ss;
                socklen_t sslen = sizeof (ss);
                ssize_t size = recvfrom(sock, buf, sizeof (buf), 0, (struct sockaddr*)&ss, &sslen);
                if (size < 0) {
                        perror("recvfrom");
                        continue;
                }

                time_t now = time(0);
                struct tm* nowtm = localtime(&now);
                char nowstr[32];
                strftime(nowstr, sizeof (nowstr), "%F %T", nowtm);

                uint16_t error = 0;
                ASSUME(sslen == sizeof (struct sockaddr_in6), SERVER);

                struct dnsheader* h = (struct dnsheader*)buf;
                ASSUME(ntohs(h->qdcount) >= 1, NOTIMP);

                char name[NI_MAXHOST];
                char *q = dns2str(name, sizeof(name), buf + sizeof (struct dnsheader), buf + size);
                ASSUME(q && q + 4 <= buf + size, FORMAT);

                char pname[NI_MAXHOST], zhost[NI_MAXHOST], zport[NI_MAXSERV], host[NI_MAXHOST], port[NI_MAXSERV];
                if (verbose > 0) {
                        printable(name, pname, sizeof (pname));
                        getnameinfo((struct sockaddr*)&ss, sslen, host, sizeof(host), port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV);
                }

                uint16_t qtype = ntohs(*((uint16_t*)q));
                uint16_t qclass = ntohs(*((uint16_t*)q + 1));
                ASSUME(qclass == CLASS_INET, NOTIMP);
                q += 4;

                if (ntohs(h->flags) & FLAG_QR) {
                        struct entry* e;
                        list_for_each_entry(e, &queue, list) {
                                if (h->id == e->header.id && !memcmp(&e->zone->addr, &ss, sizeof (e->zone->addr))) {
                                        if (verbose > 0) {
                                                getnameinfo((struct sockaddr*)&e->addr, sizeof(e->addr), zhost, sizeof(zhost), zport, sizeof(zport), NI_NUMERICHOST | NI_NUMERICSERV);
                                                LOG("%s R %s %s %s %s <- %s %s %s\n", nowstr, zhost, zport, type2str(qtype), pname, host, port, e->zone->name ? e->zone->name : "DEFAULT");
                                        }
                                        if (sendto(sock, buf, size, 0, (struct sockaddr*)&e->addr, sizeof (e->addr)) < 0)
                                                perror("sendto");
                                        list_del(&e->list);
                                        free(e);
                                        break;
                                }
                        }
                        continue;
                }

                LOG("%s Q %s %s %s %s\n", nowstr, type2str(qtype), pname, host, port);

                int i;
                for (i = 0; i < numzones; ++i) {
                        if (!zones[i].name || subdomain(name, zones[i].name) >= 0) {
                                if (verbose > 0) {
                                        getnameinfo((struct sockaddr*)&zones[i].addr, sizeof(zones[i].addr), zhost, sizeof(host), zport, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV);
                                        LOG("%s F %s %s %s %s -> %s %s %s\n", nowstr, host, port, type2str(qtype), pname, zhost, zport, zones[i].name ? zones[i].name : "DEFAULT");
                                }
                                ASSUME(sendto(sock, buf, size, 0, (struct sockaddr*)&zones[i].addr, sizeof (zones[i].addr)) >= 0, SERVER);
                                struct entry* e = malloc(sizeof (struct entry));
                                e->zone = zones + i;
                                e->time = now;
                                memcpy(&e->header, h, sizeof (struct dnsheader));
                                memcpy(&e->addr, &ss, sslen);
                                list_add_tail(&e->list, &queue);
                                break;
                        }
                }
                ASSUME(i < numzones, SERVER);

                struct entry* e, *next;

        error:
                list_for_each_entry_safe(e, next, &queue, list) {
                        if (e->time + 10 >= now)
                                break;
                        if (verbose > 0) {
                                getnameinfo((struct sockaddr*)&e->zone->addr, sizeof(e->zone->addr), zhost, sizeof(zhost), zport, sizeof(zport), NI_NUMERICHOST | NI_NUMERICSERV);
                                getnameinfo((struct sockaddr*)&e->addr, sizeof(e->addr), host, sizeof(host), port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV);
                                LOG("%s X %s %s -> %s %s\n", nowstr, host, port, zhost, zport);
                        }
                        send_error(sock, &e->header, ERROR_SERVER, (struct sockaddr*)&e->addr, sizeof (e->addr));
                        list_del(&e->list);
                        free(e);
                }

                if (error) {
                        LOG("%s E %d\n", nowstr, error);
                        send_error(sock, h, error, (struct sockaddr*)&ss, sslen);
                }
        }
}
