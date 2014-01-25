// Hexspeak DNS server by Daniel Mendler <mail@daniel-mendler.de>
#define _BSD_SOURCE
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

#define SOA_ADMIN        "postmaster"
#define DIE(cond, name)  if (!(cond)) { perror(#name); exit(1); }
#define FATAL(cond, msg) if (!(cond)) { fprintf(stderr, "%s\n", msg); exit(1); }
#define ASSUME(cond, e)  if (!(cond)) { error = ERROR_##e; goto error; }
#define LOG(...)         if (verbose > 0) { printf(__VA_ARGS__); }

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
        uint32_t minimum;
} __attribute__ ((packed));

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
                        if (q[1] == 164 || q[1] == 132 || q[1] == 182 || q[1] == 150) {
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
        fprintf(stderr, "Usage: %s [-d] [-p port] [-t ttl] [-x txt] [-n ns] ipv6addr domains...", prog);
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

static struct dnsrecord* record_aaaa(char** q, size_t prefix, const void* addr, uint32_t ttl, const char* name, uint16_t label) {
        struct dnsrecord* a = record(q, label, TYPE_AAAA, ttl, 16);
        if (!a)
                return 0;
        memcpy(a->rdata, addr, 16);
        if (name)
                suffix1337(a->rdata + prefix, 16 - prefix, name);
        return a;
}

static struct dnsrecord* record_ns(char** q, uint16_t type, size_t rdlength, uint32_t ttl, const char* nsname, uint16_t* nslabel, uint16_t label) {
        size_t len = *nslabel ? 2 : strlen(nsname) + 3;
        struct dnsrecord* a = record(q, label, type, ttl, rdlength + len);
        if (!a)
                return 0;
        if (*nslabel) {
                *((uint16_t*)a->rdata) = htons(*nslabel | LABEL_BITS);
        } else {
                *nslabel = a->rdata - buf;
                a->rdata[0] = len - 3;
                memcpy(a->rdata + 1, nsname, len);
                *((uint16_t*)(a->rdata + len - 2)) = htons(label | LABEL_BITS);
        }
        return a;
}

static struct dnssoa* record_soa(char** q, uint32_t ttl, const char* nsname, uint16_t* nslabel, uint16_t label) {
        static struct dnssoa soa = {
                .refresh = 14400,
                .retry   = 1800,
                .expire  = 604800,
                .minimum = 86400,
        };
        time_t now = time(0);
        struct tm* t = localtime(&now);
        soa.serial = 1000000 * (t->tm_year + 1900) + 10000 * (t->tm_mon + 1) + 100 * t->tm_mday + t->tm_hour * 4 + t->tm_min / 15;
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
        s->minimum = htonl(soa.minimum);
        return &soa;
}

int main(int argc, char* argv[]) {
        setvbuf(stdout, NULL, _IONBF, 0);

        uint16_t port = 53;
        uint32_t ttl = 30;
        int daemonize = 0, verbose = 0, numns = 0;
        char c, *ns[MAX_NS], *txt = 0;
        while ((c = getopt(argc, argv, "hvdp:t:n:x:")) != -1) {
                switch (c) {
                case 'p': port = atoi(optarg); break;
                case 't': ttl = atoi(optarg);  break;
                case 'd': daemonize = 1;       break;
                case 'v': ++verbose;           break;
                case 'x':
                        txt = optarg;
                        FATAL(strlen(txt) <= 255, "TXT field too long");
                        break;
                case 'n':
                        FATAL(numns < MAX_NS, "Too many nameservers given");
                        ns[numns++] = optarg;
                        FATAL(!strchr(optarg, '.'), "Nameserver must not contain .");
                        break;
                default:
                        usage(argv[0]);
                        break;
                }
        }

        if (argc - optind < 2)
                usage(argv[0]);

        char* p = strchr(argv[optind], '/');
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
                                        ASSUME(record_aaaa(&q, prefix, &addr, ttl, r > name ? name : 0, sizeof(struct dnsheader)), SERVER);
                                        ++ancount;
                                        if (verbose > 0) {
                                                inet_ntop(AF_INET6, q - 16, name, sizeof (name));
                                                printf("%10ld R AAAA  %s\n", now, name);
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
                                                                ASSUME(record_ns(&q, TYPE_NS, 0, ttl, ns[i], nslabel + i, domlabel), SERVER);
                                                                LOG("%10ld R NS    %s.%s.\n", now, ns[i], *domain);
                                                        }
                                                        ancount += numns;
                                                }
                                                if (qtype == TYPE_SOA || qtype == TYPE_ANY) {
                                                        struct dnssoa* s = record_soa(&q, ttl, ns[0], nslabel, domlabel);
                                                        ASSUME(s, SERVER);
                                                        ++ancount;
                                                        LOG("%10ld R SOA   %s.%s. %s.%s. %d %d %d %d %d\n",
                                                            now, ns[0], *domain, SOA_ADMIN, *domain,
                                                            s->serial, s->refresh, s->retry, s->expire, s->minimum);
                                                }
                                        }
                                        for (int i = 0; i < numns; ++i)
                                                ASSUME(record_ns(&q, TYPE_NS, 0, ttl, ns[i], nslabel + i, domlabel), SERVER);
                                        nscount += numns;
                                        if (qtype == TYPE_MX || qtype == TYPE_A || qtype == TYPE_CNAME) {
                                                ASSUME(record_soa(&q, ttl, ns[0], nslabel, domlabel), SERVER);
                                                ++nscount;
                                        }
                                        for (int i = 0; i < numns; ++i)
                                                ASSUME(record_aaaa(&q, prefix, &addr, ttl, ns[i], nslabel[i]), SERVER);
                                        arcount += numns;
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
