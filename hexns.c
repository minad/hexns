// Hexspeak DNS server by Daniel Mendler <mail@daniel-mendler.de>
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

#define SOA_ADMIN        "postmaster"
#define DIE(cond, name)  if (!(cond)) { perror(#name); exit(1); }
#define FATAL(cond, msg) if (!(cond)) { fprintf(stderr, "%s\n", msg); exit(1); }
#define ASSUME(cond, e)  if (!(cond)) { error = ERROR_##e; goto error; }
#define LOG(...)         if (verbose > 0) { fprintf(log, __VA_ARGS__); }

enum {
        CLASS_INET   = 0x01,
        OP_MASK      = 0x7000,
        OP_QUERY     = 0x0000,
        FLAG_QR      = 0x8000,
        FLAG_AA      = 0x0400,
        FLAG_RD      = 0x0100,
        LABEL_BITS   = 0xC000,
        ERROR_FORMAT = 0x0001,
        ERROR_SERVER = 0x0002,
        ERROR_NOTIMP = 0x0004,
        MAX_NS       = 4,
        TYPE_A       = 1,
        TYPE_NS      = 2,
        TYPE_CNAME   = 5,
        TYPE_SOA     = 6,
        TYPE_MX      = 15,
        TYPE_TXT     = 16,
        TYPE_AAAA    = 28,
        TYPE_ANY     = 255,
};

static char buf[0x400];

struct dnsheader {
        uint16_t id;
        uint16_t flags;
        uint16_t qdcount;
        uint16_t ancount;
        uint16_t nscount;
        uint16_t arcount;
} __attribute__ ((packed));

struct dnsrecord {
        uint16_t label;
        uint16_t type;
        uint16_t class;
        uint32_t ttl;
        uint16_t rdlength;
        char     rdata[0];
} __attribute__ ((packed));

struct dnssoa {
        uint32_t serial;
        uint32_t refresh;
        uint32_t retry;
        uint32_t expire;
        uint32_t minttl;
} __attribute__ ((packed));

struct nameserver {
        char*           name;
        int             has4, has6;
        struct in_addr  addr4;
        struct in6_addr addr6;
};

static const char* type2str(uint16_t type) {
        static char buf[8];
        switch (type) {
        case TYPE_A:     return "A";
        case TYPE_NS:    return "NS";
        case TYPE_CNAME: return "CNAME";
        case TYPE_MX:    return "MX";
        case TYPE_TXT:   return "TXT";
        case TYPE_SOA:   return "SOA";
        case TYPE_AAAA:  return "AAAA";
        case TYPE_ANY:   return "ANY";
        default:
                snprintf(buf, sizeof (buf), "%d", type);
                return buf;
        }
}

static void suffix1337(char* dst, size_t size, const char* name) {
        char* out, nibs[2 * size];
        idna_to_unicode_8z8z(name, &out, 0);
        char* p = nibs;
        for (uint8_t* q = (uint8_t*)out; *q && p < nibs + sizeof (nibs); ++q) {
                switch(tolower(*q)) {
                case '1': case '2': case '3': case '4':
                case '5': case '6': case '7': case '8': case '9':
                        *p++ = *q - '0';
                        break;
                case 'a': case 'b': case 'c': case 'd': case 'e': case 'f':
                        *p++ = 10 + *q - 'a';
                        break;
                case 'p':
                        *p++ = q[1] == 'h' || q[1] == 'H' ? ++q, 0xF : 0xB;
                        break;
                case 'l':
                        if (q[1] == 'e' && q[2] == 'e' && q[3] == 't' && p + 3 < nibs + sizeof (nibs)) {
                                *p++ = 1; *p++ = 3; *p++ = 3; *p++ = 7;
                                q += 3;
                                break;
                        }
                        // fall through
                case 'i': case 'j': *p++ = 0x1; break;
                case 'g':           *p++ = 0x9; break;
                case '0': case 'o': *p++ = 0x0; break;
                case 'q':           *p++ = 0x6; break;
                case 'k': case 'z': *p++ = 0xC; break;
                case 's':           *p++ = 0x5; break;
                case 'r':           *p++ = 0x7; break;
                case 't':           *p++ = 0xD; break;
                case 195:
                        if (q[1] == 164 || q[1] == 132 || q[1] == 182 || q[1] == 150 || q[1] == 188) {
                                ++q;
                                *p++ = *q == 164 || *q == 132 ? 0xA : 0x0;
                                if (p < nibs + sizeof (nibs))
                                        *p++ = 0xE;
                        }
                        break;
                }
        }
        --p;
        for (char* q = dst + size - 1; q >= dst; --q) {
                *q = p >= nibs ? *p-- : 0;
                if (p >= nibs)
                        *q |= *p-- << 4;
        }
        free(out);
}

static void usage(const char* prog) {
        fprintf(stderr, "Usage: %s [-d] [-p port] [-t ttl] [-x txt] [-n ns,ipv6[,ipv4]] ipv6addr domains...", prog);
        exit(1);
}

static char* dns2str(char* str, size_t size, char* dns, const char* end) {
        size_t n;
        char* p = str;
        for (; dns < end && (n = *dns++); p += n, dns += n) {
                if (n > 63 || p + n + 1 > str + size - 1)
                        return 0;
                if (p != str)
                        *p++ = '.';
                memcpy(p, dns, n);
        }
        *p = 0;
        return dns;
}

static void str2dns(const char* str, char* dns) {
        const char* end;
        do {
                end = strchr(str, '.');
                size_t len = end ? end - str : strlen(str);
                *dns++ = len;
                memcpy(dns, str, len);
                dns += len;
                str += len + 1;
        } while (end);
        *dns = 0;
}

static struct dnsrecord* record(char** q, uint16_t label, uint16_t type, uint32_t ttl, uint16_t rdlength) {
        struct dnsrecord* a = (struct dnsrecord*)*q;
        *q += sizeof (struct dnsrecord) + rdlength;
        if (*q > buf + sizeof (buf))
                return 0;
        a->label = htons(label | LABEL_BITS);
        a->type = htons(type);
        a->class = htons(CLASS_INET);
        a->ttl = htonl(ttl);
        a->rdlength = htons(rdlength);
        return a;
}

static struct dnsrecord* record_rdata(char** q, uint16_t label, uint16_t type, uint32_t ttl, const void* rdata, uint16_t rdlength) {
        struct dnsrecord* a = record(q, label, type, ttl, rdlength);
        if (!a)
                return 0;
        memcpy(a->rdata, rdata, rdlength);
        return a;
}

static struct dnsrecord* record_aaaa1337(char** q, const void* addr, uint32_t ttl, uint16_t label, size_t prefix, const char* name) {
        struct dnsrecord* a = record_rdata(q, label, TYPE_AAAA, ttl, addr, 16);
        if (name)
                suffix1337(a->rdata + prefix, 16 - prefix, name);
        return a;
}

static struct dnsrecord* record_ns(char** q, uint16_t type, size_t rdlength, uint32_t ttl, const char* nsname, uint16_t* nslabel, uint16_t label) {
        struct dnsrecord* a = record(q, label, type, ttl, rdlength + (*nslabel ? 2 : strlen(nsname) + 2));
        if (!a)
                return 0;
        if (*nslabel) {
                *((uint16_t*)a->rdata) = htons(*nslabel | LABEL_BITS);
        } else {
                *nslabel = a->rdata - buf;
                str2dns(nsname, a->rdata);
        }
        return a;
}

static struct dnssoa* record_soa(char** q, uint32_t ttl, const char* nsname, uint16_t* nslabel, uint16_t label) {
        time_t now = time(0);
        struct tm* t = localtime(&now);
        static struct dnssoa soa;
        soa.serial = 1000000 * (t->tm_year + 1900) + 10000 * (t->tm_mon + 1) + 100 * t->tm_mday + t->tm_hour * 4 + t->tm_min / 15;
        soa.refresh = ttl;
        soa.retry   = ttl;
        soa.expire  = 10 * ttl;
        soa.minttl  = ttl;
        size_t len = strlen(SOA_ADMIN);
        struct dnsrecord* a = record_ns(q, TYPE_SOA, len + 3 + sizeof (struct dnssoa), ttl, nsname, nslabel, label);
        if (!a)
                return 0;
        char* p = *q - (len + 3 + sizeof (struct dnssoa));
        *p++ = len;
        memcpy(p, SOA_ADMIN, len);
        p += len;
        *(uint16_t*)p = htons(label | LABEL_BITS);
        struct dnssoa* s = (struct dnssoa*)(p + 2);
        s->serial = htonl(soa.serial);
        s->refresh = htonl(soa.refresh);
        s->retry = htonl(soa.retry);
        s->expire = htonl(soa.expire);
        s->minttl = htonl(soa.minttl);
        return &soa;
}

int main(int argc, char* argv[]) {
        struct nameserver ns[MAX_NS] = {};
        uint16_t port = 53;
        uint32_t ttl = 300;
        int daemonize = 0, verbose = 0, numns = 0;
        char c, *txt = 0, *p;
        FILE *log = stdout;
        while ((c = getopt(argc, argv, "hvdp:t:n:x:l:")) != -1) {
                switch (c) {
                case 'p': port = atoi(optarg); break;
                case 'd': daemonize = 1;       break;
                case 'v': ++verbose;           break;
                case 't':
                        ttl = atoi(optarg);
                        FATAL(ttl >= 60, "ttl must be >= 60");
                        break;
                case 'x':
                        txt = optarg;
                        FATAL(strlen(txt) <= 255, "TXT field too long");
                        break;
                case 'l':
                        log = fopen(optarg, "a");
                        DIE(log, "Could not open log file");
                        break;
                case 'n':
                        FATAL(numns < MAX_NS, "Too many nameservers given");
                        while ((p = strsep(&optarg, ","))) {
                                if (inet_pton(AF_INET6, p, &ns[numns].addr6))
                                        ns[numns].has6 = 1;
                                else if (inet_pton(AF_INET, p, &ns[numns].addr4))
                                        ns[numns].has4 = 1;
                                else
                                        ns[numns].name = p;
                        }
                        FATAL(ns[numns].name && (ns[numns].has4 || ns[numns].has6), "You must specify a name and an IPv4/IPv6 address.");
                        ++numns;
                        break;
                default:
                        usage(argv[0]);
                        break;
                }
        }

        if (argc - optind < 2)
                usage(argv[0]);

        setvbuf(log, NULL, _IONBF, 0);

        p = strchr(argv[optind], '/');
        size_t prefix = 0;
        if (p) {
                *p++ = 0;
                prefix = atoi(p);
                if (prefix % 8)
                        prefix += 8;
                prefix /= 8;
        } else {
                p = strstr(argv[optind], "::");
                FATAL(p, "Invalid address format, use 1:2::1 or 1:2::/64");
                while (p >= argv[optind]) {
                        if (*p-- == ':')
                                prefix += 2;
                }
        }
        FATAL(prefix < 16, "Number of netmask bits must be less than 128");

        struct in6_addr addr;
        FATAL(inet_pton(AF_INET6, argv[optind], &addr), "Invalid IPv6 address");

        int sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
        DIE(sock, socket);

        struct sockaddr_in6 sa = {
                .sin6_family = AF_INET6,
                .sin6_port = htons(port),
                .sin6_addr = in6addr_any
        };
        DIE(!bind(sock, (struct sockaddr*)&sa, sizeof(sa)), bind);
        DIE(!daemonize || !daemon(0, 0), daemon);

        if (!getuid()) {
                struct passwd* pw = getpwnam("nobody");
                DIE(pw, getpwname);
                char name[] = "/tmp/hexns.XXXXXX";
                DIE(mkdtemp(name), mkdtemp);
                DIE(!chdir(name), chdir);
                DIE(!rmdir(name), rmdir);
                DIE(!chroot("."), chroot);
                DIE(!setgid(pw->pw_gid), setgid);
                DIE(!setuid(pw->pw_uid), setuid);
                FATAL(setuid(0) < 0, "Dropping privileges failed");
        }

        struct sigaction sig = { .sa_handler = exit };
        sigemptyset(&sig.sa_mask);
        DIE(!sigaction(SIGINT, &sig, 0) || !sigaction(SIGTERM, &sig, 0), "sigaction");

        for (;;) {
                struct sockaddr_storage ss;
                socklen_t sslen = sizeof (ss);
                ssize_t size = recvfrom(sock, buf, sizeof (buf), 0, (struct sockaddr*)&ss, &sslen);
                if (size < 0) {
                        perror("recvfrom");
                        continue;
                }

                struct dnsheader* h = (struct dnsheader*)buf;
                uint16_t error = 0;
                ASSUME((ntohs(h->flags) & OP_MASK) == OP_QUERY && ntohs(h->qdcount) == 1, NOTIMP);

                char name[512];
                char *q = dns2str(name, sizeof(name), buf + sizeof (struct dnsheader), buf + size);
                ASSUME(q && q + 4 <= buf + size, FORMAT);

                uint16_t qtype = ntohs(*((uint16_t*)q));
                uint16_t qclass = ntohs(*((uint16_t*)q + 1));
                ASSUME(qclass == CLASS_INET, NOTIMP);
                q += 4;

                time_t now = time(0);
                LOG("%10ld Q %-5s %s\n", now, type2str(qtype), name);

                uint16_t ancount = 0, nscount = 0, arcount = 0;
                for (char** domain = argv + optind + 1; *domain; ++domain) {
                        char* r = name + strlen(name) - strlen(*domain);
                        if (!strcmp(r, *domain) && (r == name || (r > name && r[-1] == '.'))) {
                                uint16_t domlabel = sizeof(struct dnsheader) + (r - name);

                                if (qtype == TYPE_AAAA || qtype == TYPE_ANY) {
                                        if (r > name)
                                                *r = 0;
                                        ASSUME(record_aaaa1337(&q, &addr, ttl, sizeof(struct dnsheader), prefix, r > name ? name : 0), SERVER);
                                        ++ancount;
                                        if (verbose > 0) {
                                                inet_ntop(AF_INET6, q - 16, name, sizeof (name));
                                                fprintf(log, "%10ld R AAAA  %s\n", now, name);
                                        }
                                }
                                if (txt && (qtype == TYPE_TXT || qtype == TYPE_ANY)) {
                                        size_t len = strlen(txt);
                                        struct dnsrecord* a = record(&q, sizeof (struct dnsheader), TYPE_TXT, ttl, len + 1);
                                        ASSUME(a, SERVER);
                                        a->rdata[0] = len;
                                        memcpy(a->rdata + 1, txt, len);
                                        ++ancount;
                                        LOG("%10ld R TXT   \"%s\"\n", now, txt);
                                }
                                if (numns > 0) {
                                        uint16_t nslabel[MAX_NS] = {0};
                                        if (r == name) {
                                                if (qtype == TYPE_NS || qtype == TYPE_ANY) {
                                                        for (int i = 0; i < numns; ++i) {
                                                                ASSUME(record_ns(&q, TYPE_NS, 0, ttl, ns[i].name, nslabel + i, domlabel), SERVER);
                                                                LOG("%10ld R NS    %s.\n", now, ns[i].name);
                                                        }
                                                        ancount += numns;
                                                }
                                                if (qtype == TYPE_SOA || qtype == TYPE_ANY) {
                                                        struct dnssoa* s = record_soa(&q, ttl, ns[0].name, nslabel, domlabel);
                                                        ASSUME(s, SERVER);
                                                        ++ancount;
                                                        LOG("%10ld R SOA   %s. %s.%s. %d %d %d %d %d\n",
                                                            now, ns[0].name, SOA_ADMIN, *domain,
                                                            s->serial, s->refresh, s->retry, s->expire, s->minttl);
                                                }
                                        }

                                        if (ancount > 0) {
                                                // Authority record
                                                for (int i = 0; i < numns; ++i)
                                                        ASSUME(record_ns(&q, TYPE_NS, 0, ttl, ns[i].name, nslabel + i, domlabel), SERVER);
                                                nscount += numns;

                                                // Additional records
                                                for (int i = 0; i < numns; ++i) {
                                                        if (ns[i].has6) {
                                                                ASSUME(record_rdata(&q, nslabel[i], TYPE_AAAA, ttl, &ns[i].addr6, 16), SERVER);
                                                                ++arcount;
                                                        }
                                                        if (ns[i].has4) {
                                                                ASSUME(record_rdata(&q, nslabel[i], TYPE_A, ttl, &ns[i].addr4, 4), SERVER);
                                                                ++arcount;
                                                        }
                                                }
                                        } else {
                                                // Authority record
                                                ASSUME(record_soa(&q, ttl, ns[0].name, nslabel, domlabel), SERVER);
                                                ++nscount;
                                        }

                                }

                                break;
                        }
                }

        error:
                if (error) {
                        LOG("%10ld E %d\n", now, error);
                        h->qdcount = ancount = nscount = arcount = 0;
                        q = buf + sizeof (struct dnsheader);
                }
                h->flags |= htons(FLAG_QR | FLAG_AA | error);
                h->flags &= ~htons(FLAG_RD);
                h->ancount = htons(ancount);
                h->nscount = htons(nscount);
                h->arcount = htons(arcount);

                if (sendto(sock, buf, q - buf, 0, (struct sockaddr*)&ss, sslen) < 0)
                        perror("sendto");
        }
}
