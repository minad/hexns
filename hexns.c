#include <arpa/inet.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static char buf[4096];
static char ans[4096];

#define TYPE_AAAA    28
#define FLAG_QR      0x8000
#define LABEL_BITS   0xC000
#define ERROR_FORMAT 0x0001
#define ERROR_SERVER 0x0002
#define ERROR_MASK   0x000F

struct dnsheader {
        uint16_t id;
        uint16_t flags;
        uint16_t qdcount;
        uint16_t ancount;
        uint16_t nscount;
        uint16_t arcount;
};

void die(const char* name) {
        perror(name);
        exit(1);
}

void ip6suffix(char* dst, size_t size, const unsigned char* name) {
        char tmp[strlen(name)];
        char* p = tmp;
        for (; *name; ++name) {
                switch(*name) {
                case '0': case '1': case '2': case '3': case '4':
                case '5': case '6': case '7': case '8': case '9':
                        *p++ = *name - '0';
                        break;
                case 'a': case 'b': case 'c': case 'd': case 'e': case 'f':
                        *p++ = 10 + *name - 'a';
                        break;
                case 'A': case 'B': case 'C': case 'D': case 'E': case 'F':
                        *p++ = 10 + *name - 'A';
                        break;
                case 'o': case 'O':
                        *p++ = 0;
                        break;
                case 'z': case 'Z':
                        *p++ = 12;
                        break;
                case 'i': case 'I':
                case 'l': case 'L':
                case 'j': case 'J':
                        *p++ = 1;
                        break;
                case 'p': case 'P':
                        *p++ = 13;
                        break;
                case 't': case 'T':
                        *p++ = 7;
                        break;
                case 'g': case 'G':
                        *p++ = 6;
                        break;
                case 195:
                        if (name[1] == 164) {
                                *p++ = 10;
                                *p++ = 14;
                                ++name;
                        } else if (name[1] == 182) {
                                *p++ = 0;
                                *p++ = 14;
                                ++name;
                        }
                        break;
                default:
                        break;
                }
        }
        --p;
        for (char* q = dst + size - 1; q >= dst; --q) {
                if (p >= tmp) {
                        *q = *p--;
                        if (p >= tmp)
                                *q |= *p-- << 4;
                } else {
                        *q = 0;
                }
        }
}

int main(int argc, char* argv[]) {
        if (argc != 5) {
                printf("Usage: %s port ip6bits ip6prefix nameprefix\n", argv[0]);
                return 1;
        }

        int port = atoi(argv[1]);
        size_t bytes = atoi(argv[2]);
        if (bytes % 8 != 0)
                bytes += 8;
        bytes /= 8;
        if (bytes >= 16) {
                printf("Bits must be less than 128\n");
                return 1;
        }

        struct in6_addr prefix;
        if (!inet_pton(AF_INET6, argv[3], &prefix)) {
                printf("Invalid IPv6 address\n");
                return 1;
        }

        const char* nameprefix = argv[4];

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
                if (size < 0)
                        perror("recvfrom");

                struct dnsheader* h = (struct dnsheader*)buf;
                uint16_t qdcount = ntohs(h->qdcount), ancount = 0, error = 0;
                char *q = buf + sizeof (struct dnsheader), *bufend = buf + size, *a = ans, *ansend = ans + sizeof (ans);

                for (uint32_t i = 0; i < qdcount && q < bufend; ++i) {
                        char* areset = a;
                        char name[512];

                        if (a + 6 > ansend) {
                                error = ERROR_SERVER;
                                break;
                        }

                        *((uint16_t*)a) = htons((q - buf) | LABEL_BITS);
                        a += 2;

                        char* p = name, *nameend = name + sizeof(name) - 1;

                        while (q < bufend && *q) {
                                int n = *q++;
                                if (p != name && p < nameend)
                                        *p++ = '.';
                                int m = nameend - p;
                                if (m > n)
                                        m = n;
                                memcpy(p, q, m);
                                p += m;
                                q += n;
                        }
                        *p = 0;
                        ++q;

                        if (q + 4 > bufend) {
                                error = ERROR_FORMAT;
                                break;
                        }

                        uint16_t qtype = ntohs(*((uint16_t*)q));
                        *a++ = *q++;
                        *a++ = *q++;
                        //uint16_t qclass = ntohs(*((uint16_t*)q));
                        *a++ = *q++;
                        *a++ = *q++;
                        //printf("qtype=%d qclass=%d\n", qtype, qclass);

                        printf("Q %s\n", name);

                        if (qtype == TYPE_AAAA) {
                                char* p = strstr(name, nameprefix);
                                if (p && p > name && *(p-1) == '.') {
                                        *(p-1) = 0;

                                        if (a + 22 > ansend) {
                                                error = ERROR_SERVER;
                                                break;
                                        }

                                        *((uint32_t*)a) = htonl(30);
                                        a += 4;

                                        *((uint16_t*)a) = htons(16);
                                        a += 2;
                                        memcpy(a, &prefix, bytes);
                                        ip6suffix(a + bytes, 16 - bytes, name);

                                        inet_ntop(AF_INET6, a, name, sizeof (name));
                                        a += 16;
                                        printf("R %s\n", name);

                                        ++ancount;
                                } else {
                                        a = areset;
                                }
                        } else {
                                a = areset;
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
                h->nscount = 0;
                h->arcount = 0;
                h->ancount = htons(ancount);

                size = sendto(sock, buf, q - buf, 0, (struct sockaddr*)&ss, sslen);
                if (size < 0)
                        perror("sendto");
        }
}
