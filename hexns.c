/* Hexspeak DNS server
 * Daniel Mendler <mail@daniel-mendler.de>
 */
#define _BSD_SOURCE
#include <arpa/inet.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <idna.h>
#include <ctype.h>
#include <getopt.h>
#include <pwd.h>
#include <stdarg.h>

#define CLASS_INET    0x01
#define OP_MASK       0x7000
#define OP_QUERY      0x0000
#define FLAG_QR       0x8000
#define FLAG_AA       0x0400
#define FLAG_RD       0x0100
#define LABEL_BITS    0xC000
#define ERROR_FORMAT  0x0001
#define ERROR_SERVER  0x0002
#define ERROR_NOTIMPL 0x0004
#define MAX_NS        4
enum {
        TYPE_A     = 1,
        TYPE_NS    = 2,
        TYPE_CNAME = 5,
        TYPE_SOA   = 6,
        TYPE_MX    = 15,
        TYPE_TXT   = 16,
        TYPE_AAAA  = 28,
        TYPE_ANY   = 255,
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
        uint8_t  rdata[0];
} __attribute__ ((packed));

static const char* type2str(uint16_t type) {
        static char buffer[32];
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
                snprintf(buffer, sizeof (buffer), "%d", type);
                return buffer;
        }
}

static void suffix1337(uint8_t* dst, size_t size, const char* name) {
        uint8_t* out;
        idna_to_unicode_8z8z(name, (char**)&out, 0);

        uint8_t nibs[2 * size];
        uint8_t* p = nibs, *q = out;
        for (; *q && p < nibs + sizeof (nibs); ++q) {
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
                case '0': case 'o':
                        *p++ = 0x0;
                        break;
                case 'l':
                        if (q[1] == 'e' && q[2] == 'e' && q[3] == 't' && p + 3 < nibs + sizeof (nibs)) {
                                *p++ = 1; *p++ = 3; *p++ = 3; *p++ = 7;
                                q += 3;
                                break;
                        }
                        // fall through
                case 'i':
                case 'j': *p++ = 0x1; break;
                case 'g': *p++ = 0x9; break;
                case 'q': *p++ = 0x6; break;
                case 'k':
                case 'z': *p++ = 0xC; break;
                case 's': *p++ = 0x5; break;
                case 'r':
                case 't': *p++ = 0xD; break;
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
        for (uint8_t* q = dst + size - 1; q >= dst; --q) {
                *q = p >= nibs ? *p-- : 0;
                if (p >= nibs)
                        *q |= *p-- << 4;
        }

        free(out);
}

static void fatal(const char* fmt, ...) {
        va_list ap;
        va_start(ap, fmt);
        vfprintf(stderr, fmt, ap);
        va_end(ap);
        exit(1);
}

static void usage(const char* prog) {
        fatal("Usage: %s [-d] [-p port] [-t ttl] [-n ns] ipv6addr domains...\n", prog);
}

static void die(const char* s) {
        perror(s);
        exit(1);
}

static char* dns2str(char* str, size_t size, char* dns, const char* end) {
        size_t n;
        char* p = str;
        while (dns < end && (n = *dns++)) {
                if (n > 63 || p + n + 1 > str + size - 1)
                        return 0;
                if (p != str)
                        *p++ = '.';
                memcpy(p, dns, n);
                p += n;
                dns += n;
        }
        *p = 0;
        return dns;
}

static struct dnsrecord* record(char** q, uint16_t label, uint8_t type, uint32_t ttl, uint16_t rdlength) {
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

#define ASSUME(cond, e) if (!(cond)) { error = ERROR_##e; goto error; }

int main(int argc, char* argv[]) {
        setvbuf(stdout, NULL, _IONBF, 0);

        uint16_t port = 53;
        uint32_t ttl = 30;
        int daemonize = 0, verbose = 0;
        char c;
        char* ns[MAX_NS];
        int numns = 0;
        while ((c = getopt(argc, argv, "hvdp:t:n:")) != -1) {
                switch (c) {
                case 'p':
                        port = atoi(optarg);
                        break;
                case 't':
                        ttl = atoi(optarg);
                        break;
                case 'd':
                        daemonize = 1;
                        break;
                case 'v':
                        ++verbose;
                        break;
                case 'n':
                        if (numns >= MAX_NS)
                                fatal("Too many nameservers given\n");
                        ns[numns++] = optarg;
                        if (strchr(optarg, '.'))
                                fatal("Nameserver must not contain .\n");
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
                if (!p)
                        fatal("Invalid address format, use 1:2::1 or 1:2::/64\n");
                while (p >= argv[optind]) {
                        if (*p-- == ':')
                                prefix += 2;
                }
        }
        if (prefix >= 16)
                fatal("Number of netmask bits must be less than 128\n");

        struct in6_addr addr;
        if (!inet_pton(AF_INET6, argv[optind], &addr))
                fatal("Invalid IPv6 address\n");

        char** domains = argv + optind + 1;

        int sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
        if (sock < 0)
                die("socket");

        struct sockaddr_in6 sa = {
                .sin6_family = AF_INET6,
                .sin6_port = htons(port),
                .sin6_addr = in6addr_any
        };
        if (bind(sock, (struct sockaddr*)&sa, sizeof(sa)) < 0)
                die("bind");

        if (!getuid()) {
                struct passwd* pw = getpwnam("nobody");
                if (!pw)
                        die("getpwnam");
                if (setgid(pw->pw_gid))
                        die("setgid");
                if (setuid(pw->pw_uid))
                        die("setuid");
        }

        if (daemonize && daemon(0, 0) < 0)
                die("daemon");

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
                ASSUME((ntohs(h->flags) & OP_MASK) == OP_QUERY && ntohs(h->qdcount) == 1, NOTIMPL);

                char name[512];
                char *q = dns2str(name, sizeof(name), buf + sizeof (struct dnsheader), buf + size);
                ASSUME(q && q + 4 <= buf + size, FORMAT);

                uint16_t qtype = ntohs(*((uint16_t*)q));
                uint16_t qclass = ntohs(*((uint16_t*)q + 1));
                q += 4;

                ASSUME(qclass == CLASS_INET, NOTIMPL);

                if (verbose > 0)
                        printf("Q %-5s %s\n", type2str(qtype),  name);

                uint16_t ancount = 0, nscount = 0;
                for (char** d = domains; *d; ++d) {
                        char* r = name + strlen(name) - strlen(*d);
                        if ((r == name || (r > name && r[-1] == '.')) && !strcmp(r, *d)) {
                                uint16_t domainlabel = sizeof(struct dnsheader) + (r - name);

                                if (qtype == TYPE_AAAA || qtype == TYPE_ANY) {
                                        if (r > name)
                                                *r = 0;
                                        ASSUME(record_aaaa(&q, prefix, &addr, ttl, r > name ? name : 0, sizeof(struct dnsheader)), SERVER);

                                        if (verbose > 0) {
                                                inet_ntop(AF_INET6, q - 16, name, sizeof (name));
                                                printf("R AAAA  %s\n", name);
                                        }

                                        ++ancount;
                                }
                                if (numns > 0) {
                                        uint16_t nslabel[MAX_NS] = {0};
                                        for (int j = 0; j < 2; ++j) {
                                                if (j == 1 || (r == name && (qtype == TYPE_NS || qtype == TYPE_ANY))) {
                                                        for (int i = 0; i < numns; ++i) {
                                                                size_t len = nslabel[i] ? 2 : strlen(ns[i]) + 3;
                                                                struct dnsrecord* a = record(&q, domainlabel, TYPE_NS, ttl, len);
                                                                ASSUME(q, SERVER);

                                                                if (nslabel[i]) {
                                                                        *((uint16_t*)a->rdata) = htons(nslabel[i] | LABEL_BITS);
                                                                } else {
                                                                        nslabel[i] = (char*)a->rdata - buf;
                                                                        a->rdata[0] = len - 3;
                                                                        memcpy(a->rdata + 1, ns[i], len - 3);
                                                                        *((uint16_t*)(a->rdata + len - 2)) = htons(domainlabel | LABEL_BITS);
                                                                }

                                                                if (j == 0) {
                                                                        if (verbose > 0)
                                                                                printf("R NS    %s.%s\n", ns[i], *d);
                                                                        ++ancount;
                                                                }
                                                        }
                                                }
                                        }
                                        for (int i = 0; i < numns; ++i)
                                                ASSUME(record_aaaa(&q, prefix, &addr, ttl, ns[i], nslabel[i]), SERVER);

                                        nscount = numns;
                                }
                                break;
                        }
                }

        error:
                if (error) {
                        if (verbose > 0)
                                printf("E %d\n", error);
                        ancount = 0;
                        q = buf + sizeof (struct dnsheader);
                }
                h->flags |= htons(FLAG_QR | FLAG_AA | error);
                h->flags &= ~htons(FLAG_RD);
                h->ancount = htons(ancount);
                h->nscount = h->arcount = htons(nscount);

                if (sendto(sock, buf, q - buf, 0, (struct sockaddr*)&ss, sslen) < 0)
                        perror("sendto");
        }
}
