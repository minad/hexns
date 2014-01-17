#include <arpa/inet.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <idna.h>

#define TYPE_AAAA    0x1C
#define TYPE_ANY     0xFF
#define CLASS_INET   0x01
#define CLASS_CHAOS  0x03
#define FLAG_QR      0x8000
#define LABEL_BITS   0xC000
#define ERROR_FORMAT 0x0001
#define ERROR_SERVER 0x0002
#define ERROR_MASK   0x000F
#define BUFSIZE      0x1000

static char buf[BUFSIZE], ans[BUFSIZE];

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

static void ip6suffix(uint8_t* dst, size_t size, const char* name) {
        uint8_t* out;
        idna_to_unicode_8z8z(name, (char**)&out, 0);

        uint8_t tmp[2 * size];
        uint8_t* p = tmp, *q = out;
        for (; *q && p < tmp + sizeof (tmp); ++q) {
                switch(*q) {
                case '0': case '1': case '2': case '3': case '4':
                case '5': case '6': case '7': case '8': case '9':
                        *p++ = *q - '0';
                        break;
                case 'a': case 'b': case 'c': case 'd': case 'e': case 'f':
                        *p++ = 10 + *q - 'a';
                        break;
                case 'A': case 'B': case 'C': case 'D': case 'E': case 'F':
                        *p++ = 10 + *q - 'A';
                        break;
                case 'o': case 'O':
                        *p++ = 0;
                        break;
                case 'z': case 'Z':
                        *p++ = 12;
                        break;
                case 'i': case 'I': case 'l': case 'L': case 'j': case 'J':
                        *p++ = 1;
                        break;
                case 'g': case 'G': case 'q': case 'Q':
                        *p++ = 6;
                        break;
                case 'p': case 'P':
                        *p++ = 13;
                        break;
                case 's': case 'S':
                        *p++ = 5;
                        break;
                case 't': case 'T':
                        *p++ = 7;
                        break;
                case 195:
                        if (q[1] == 164) {
                                *p++ = 10;
                                if (p < tmp + sizeof (tmp))
                                        *p++ = 14;
                                ++q;
                        } else if (q[1] == 182) {
                                *p++ = 0;
                                if (p < tmp + sizeof (tmp))
                                        *p++ = 14;
                                ++q;
                        }
                        break;
                default:
                        break;
                }
        }
        --p;
        for (uint8_t* q = dst + size - 1; q >= dst; --q) {
                if (p >= tmp) {
                        *q = *p--;
                        if (p >= tmp)
                                *q |= *p-- << 4;
                } else {
                        *q = 0;
                }
        }

        free(out);
}

int main(int argc, char* argv[]) {
        if (argc != 5) {
                printf("Usage: %s port ip6bits ip6prefix domain\n", argv[0]);
                return 1;
        }

        int port = atoi(argv[1]);
        size_t bytes = atoi(argv[2]);
        if (bytes % 8)
                bytes += 8;
        bytes /= 8;
        if (bytes >= 16) {
                printf("Number of prefix bits must be less than 128\n");
                return 1;
        }

        struct in6_addr prefix;
        if (!inet_pton(AF_INET6, argv[3], &prefix)) {
                printf("Invalid IPv6 address\n");
                return 1;
        }

        const char* domain = argv[4];

        int sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
        if (sock < 0) {
                perror("socket");
                return 1;
        }

        struct sockaddr_in6 sa;
        memset(&sa, 0, sizeof (sa));
        sa.sin6_family = AF_INET6;
        sa.sin6_port = htons(port);
        sa.sin6_addr = in6addr_any;

        if (bind(sock, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
                perror("bind");
                return 1;
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
                uint16_t qdcount = ntohs(h->qdcount), ancount = 0, error = 0;
                char *q = buf + sizeof (struct dnsheader), *qend = buf + size, *a = ans;

                for (uint32_t i = 0; i < qdcount && q < qend; ++i) {
                        uint16_t label = q - buf;

                        char name[512];
                        char* p = name, *pend = name + sizeof(name) - 1;
                        while (q < qend && *q) {
                                size_t n = *q++;
                                if (n > 63) {
                                        error = ERROR_FORMAT;
                                        break;
                                }
                                if (p != name && p < pend)
                                        *p++ = '.';
                                size_t m = pend - p;
                                if (m > n)
                                        m = n;
                                if (m > 0) {
                                        memcpy(p, q, m);
                                        p += m;
                                        q += n;
                                }
                        }
                        *p = 0;
                        ++q;

                        if (q + 4 > qend)
                                error = ERROR_FORMAT;
                        if (error)
                                break;

                        uint16_t qtype = ntohs(*((uint16_t*)q));
                        uint16_t qclass = ntohs(*((uint16_t*)q + 1));
                        q += 4;
                        //printf("qtype=%d qclass=%d\n", qtype, qclass);

                        if (qclass == CLASS_INET && (qtype == TYPE_AAAA || qtype == TYPE_ANY)) {
                                printf("Q%d %s %s\n", i, qtype == TYPE_AAAA ? "AAAA" : "ANY",  name);
                                char* p = strstr(name, domain);
                                if (p && p > name && *(p-1) == '.') {
                                        *(p-1) = 0;

                                        struct dnsanswer* s = (struct dnsanswer*)a;
                                        a += sizeof (struct dnsanswer) + 16;
                                        if (a > ans + sizeof (ans)) {
                                                error = ERROR_SERVER;
                                                break;
                                        }

                                        s->label = htons(label | LABEL_BITS);
                                        s->type = htons(TYPE_AAAA);
                                        s->class = htons(qclass);
                                        s->ttl = htonl(30);
                                        s->rdlength = htons(16);

                                        memcpy(s->rdata, &prefix, bytes);
                                        ip6suffix(s->rdata + bytes, 16 - bytes, name);

                                        inet_ntop(AF_INET6, s->rdata, name, sizeof (name));
                                        printf("R%d %s\n", i, name);

                                        ++ancount;
                                }
                        }
                }

                if (!error) {
                        size_t n = a - ans;
                        if (q + n < buf + sizeof (buf)) {
                                memcpy(q, ans, n);
                                q += n;
                        } else {
                                error = ERROR_SERVER;
                        }
                }

                if (error) {
                        ancount = 0;
                        q = buf + sizeof (struct dnsheader);
                }

                h->flags |= htons(FLAG_QR | error);
                h->nscount = h->arcount = 0;
                h->ancount = htons(ancount);

                size = sendto(sock, buf, q - buf, 0, (struct sockaddr*)&ss, sslen);
                if (size < 0)
                        perror("sendto");
        }
}
