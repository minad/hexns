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

struct dnsanswer {
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
                case 'z': *p++ = 0xC; break;
                case 's': *p++ = 0x5; break;
                case 'r':
                case 't': *p++ = 0x7; break;
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

static void usage(const char* prog) {
        fprintf(stderr, "Usage: %s [-d] [-p port] [-t ttl] [-n ns] ipv6addr domains...\n", prog);
        exit(1);
}

static void die(const char* s) {
        perror(s);
        exit(1);
}

static char* dns2str(char* name, size_t size, char* in, const char* end) {
        size_t n;
        char* p = name;
        while (in < end && (n = *in++)) {
                if (n > 63 || p + n + 1 > name + size - 1)
                        return 0;
                if (p != name)
                        *p++ = '.';
                memcpy(p, in, n);
                p += n;
                in += n;
        }
        *p = 0;
        return in;
}

int main(int argc, char* argv[]) {
        setvbuf(stdout, NULL, _IONBF, 0);

        uint16_t port = 53;
        uint32_t ttl = 30;
        int daemonize = 0, verbose = 0;
        char c;
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
                default:
                        usage(argv[0]);
                        break;
                }
        }

        if (argc - optind < 2)
                usage(argv[0]);

        char* p = strchr(argv[optind], '/');
        size_t bytes = 0;
        if (p) {
                *p++ = 0;
                bytes = atoi(p);
                if (bytes % 8)
                        bytes += 8;
                bytes /= 8;
        } else {
                p = strstr(argv[optind], "::");
                if (!p) {
                        fprintf(stderr, "Invalid address format, use 1:2::1 or 1:2::/64\n");
                        return 1;
                }
                while (p >= argv[optind]) {
                        if (*p-- == ':')
                                bytes += 2;
                }
        }
        if (bytes >= 16) {
                fprintf(stderr, "Number of netmask bits must be less than 128\n");
                return 1;
        }

        struct in6_addr addr;
        if (!inet_pton(AF_INET6, argv[optind], &addr)) {
                fprintf(stderr, "Invalid IPv6 address\n");
                return 1;
        }

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
                perror("daemon");

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
                if ((ntohs(h->flags) & OP_MASK) != OP_QUERY || ntohs(h->qdcount) != 1) {
                        error = ERROR_NOTIMPL;
                        goto error;
                }

                char name[512];
                char *q = dns2str(name, sizeof(name), buf + sizeof (struct dnsheader), buf + size);
                if (!q || q + 4 > buf + size) {
                        error = ERROR_FORMAT;
                        goto error;
                }

                uint16_t qtype = ntohs(*((uint16_t*)q));
                uint16_t qclass = ntohs(*((uint16_t*)q + 1));
                q += 4;

                if (qclass != CLASS_INET) {
                        error = ERROR_NOTIMPL;
                        goto error;
                }

                if (verbose > 0)
                        printf("Q %-5s %s\n", type2str(qtype),  name);

                uint16_t ancount = 0;

                for (char** d = domains; *d; ++d) {
                        char* r = name + strlen(name) - strlen(*d);
                        if ((r == name || (r > name && r[-1] == '.')) && !strcmp(r, *d)) {
                                if (qtype == TYPE_AAAA || qtype == TYPE_ANY) {
                                        struct dnsanswer* a = (struct dnsanswer*)q;
                                        q += sizeof (struct dnsanswer) + 16;
                                        if (q > buf + sizeof (buf)) {
                                                error = ERROR_SERVER;
                                                goto error;
                                        }

                                        a->label = htons(sizeof(struct dnsheader) | LABEL_BITS);
                                        a->type = htons(TYPE_AAAA);
                                        a->class = htons(qclass);
                                        a->ttl = htonl(ttl);
                                        a->rdlength = htons(16);

                                        if (r == name) {
                                                memcpy(a->rdata, &addr, 16);
                                        } else {
                                                *r = 0;
                                                memcpy(a->rdata, &addr, bytes);
                                                suffix1337(a->rdata + bytes, 16 - bytes, name);
                                        }

                                        if (verbose > 0) {
                                                inet_ntop(AF_INET6, a->rdata, name, sizeof (name));
                                                printf("R AAAA  %s\n", name);
                                        }

                                        ++ancount;
                                }
                                if (qtype == TYPE_NS || qtype == TYPE_ANY) {
                                        const char nsname[] = "\7""1800002\4qxqx\2de";

                                        struct dnsanswer* a = (struct dnsanswer*)q;
                                        q += sizeof (struct dnsanswer) + sizeof(nsname);
                                        if (q > buf + sizeof (buf)) {
                                                error = ERROR_SERVER;
                                                goto error;
                                        }

                                        a->label = htons(sizeof(struct dnsheader) | LABEL_BITS);
                                        a->type = htons(TYPE_NS);
                                        a->class = htons(qclass);
                                        a->ttl = htonl(ttl);
                                        a->rdlength = htons(sizeof(nsname));

                                        memcpy(a->rdata, nsname, sizeof(nsname));

                                        if (verbose > 0) {
                                                printf("R NS    %s\n", "duuuu");
                                        }

                                        ++ancount;
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
                h->nscount = h->arcount = 0;

                if (sendto(sock, buf, q - buf, 0, (struct sockaddr*)&ss, sslen) < 0)
                        perror("sendto");
        }
}
