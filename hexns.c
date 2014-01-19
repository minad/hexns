/* Hexspeak DNS server
 * Daniel Mendler <mail@daniel-mendler.de>
 */
#include <arpa/inet.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <idna.h>
#include <ctype.h>
#include <getopt.h>

#define TYPE_AAAA     0x1C
#define TYPE_ANY      0xFF
#define CLASS_INET    0x01
#define CLASS_CHAOS   0x03
#define OP_MASK       0x7000
#define OP_QUERY      0x0000
#define FLAG_QR       0x8000
#define FLAG_AA       0x0400
#define FLAG_RD       0x0100
#define LABEL_BITS    0xC000
#define ERROR_FORMAT  0x0001
#define ERROR_SERVER  0x0002
#define ERROR_NOTIMPL 0x0004

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
                        if (q[1] == 164 || q[1] == 182) {
                                ++q;
                                *p++ = *q == 164 ? 0xA : 0x0;
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
        printf("Usage: %s [-p port] [-t ttl] ip6bits ip6prefix domain\n", prog);
        exit(1);
}

static void die(const char* s) {
        perror(s);
        exit(1);
}

int main(int argc, char* argv[]) {
        setvbuf(stdout, NULL, _IONBF, 0);

        uint16_t port = 53;
        uint32_t ttl = 30;
        char c;
        while ((c = getopt (argc, argv, "p:t:")) != -1) {
                switch (c) {
                case 'p':
                        port = atoi(optarg);
                        break;
                case 't':
                        ttl = atoi(optarg);
                        break;
                default:
                        usage(argv[0]);
                        break;
                }
        }

        if (argc - optind != 3)
                usage(argv[0]);

        size_t bytes = atoi(argv[optind]);
        if (bytes % 8)
                bytes += 8;
        bytes /= 8;
        if (bytes >= 16) {
                printf("Number of prefix bits must be less than 128\n");
                return 1;
        }

        struct in6_addr prefix;
        if (!inet_pton(AF_INET6, argv[optind + 1], &prefix)) {
                printf("Invalid IPv6 address\n");
                return 1;
        }

        const char* domain = argv[optind + 2];

        int sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
        if (sock < 0)
                die("socket");

        struct sockaddr_in6 sa;
        memset(&sa, 0, sizeof (sa));
        sa.sin6_family = AF_INET6;
        sa.sin6_port = htons(port);
        sa.sin6_addr = in6addr_any;

        if (bind(sock, (struct sockaddr*)&sa, sizeof(sa)) < 0)
                die("bind");

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
                char *q = buf + sizeof (struct dnsheader), *qend = buf + size;
                char* p = name, *pend = name + sizeof(name) - 1;
                while (q < qend && *q) {
                        size_t n = *q++;
                        if (n > 63 || p + n + 1 > pend) {
                                error = ERROR_FORMAT;
                                goto error;
                        }
                        if (p != name)
                                *p++ = '.';
                        memcpy(p, q, n);
                        p += n;
                        q += n;
                }
                *p = 0;
                ++q;

                if (q + 4 > qend) {
                        error = ERROR_FORMAT;
                        goto error;
                }

                uint16_t qtype = ntohs(*((uint16_t*)q));
                uint16_t qclass = ntohs(*((uint16_t*)q + 1));
                q += 4;

                if (qclass == CLASS_INET && (qtype == TYPE_AAAA || qtype == TYPE_ANY)) {
                        printf("Q %s %s\n", qtype == TYPE_AAAA ? "AAAA" : "ANY ",  name);
                        char* p = strstr(name, domain);
                        if (p && p > name && *(p-1) == '.') {
                                *(p-1) = 0;

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

                                memcpy(a->rdata, &prefix, bytes);
                                suffix1337(a->rdata + bytes, 16 - bytes, name);

                                inet_ntop(AF_INET6, a->rdata, name, sizeof (name));
                                printf("R AAAA %s\n", name);

                                h->ancount = htons(1);
                        }
                }

        error:
                if (error) {
                        h->ancount = 0;
                        q = buf + sizeof (struct dnsheader);
                }
                h->flags |= htons(FLAG_QR | FLAG_AA | error);
                h->flags &= ~htons(FLAG_RD);
                h->nscount = h->arcount = 0;

                size = sendto(sock, buf, q - buf, 0, (struct sockaddr*)&ss, sslen);
                if (size < 0)
                        perror("sendto");
        }
}
