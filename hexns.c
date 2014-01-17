#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>

static char buffer[4096];
static char answer[1024];

#define TYPE_AAAA  28
#define FLAG_QR    0x8000
#define LABEL_BITS 0xC000

struct dnsheader {
        uint16_t id;
        uint16_t flags;
        uint16_t qdcount;
        uint16_t ancount;
        uint16_t nscount;
        uint16_t arcount;
};

int main(int argc, char* argv[]) {
        if (argc != 3) {
                printf("usage: %s port prefix\n", argv[0]);
                return 1;
        }

        int port = atoi(argv[1]);

        struct in6_addr addr;
        if (!inet_pton(AF_INET6, argv[2], &addr)) {
                printf("invalid ipv6 address\n");
                return 1;
        }

        int nibbles = 32;
        while (!addr.s6_addr[nibbles/2 - 1])
                nibbles -= 2;
        if (!(addr.s6_addr[nibbles/2 - 1] & 0xF))
                --nibbles;

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
                ssize_t size = recvfrom(sock, buffer, sizeof (buffer), 0, (struct sockaddr*)&ss, &sslen);
                if (size < 0)
                        perror("recvfrom");

                struct dnsheader* h = (struct dnsheader*)buffer;
                uint16_t qdcount = ntohs(h->qdcount);
                printf("qdcount=%d\n", qdcount);

                char *q = buffer + sizeof (struct dnsheader), *a = answer, *end = buffer + size;
                uint16_t ancount = 0;

                for (uint32_t i = 0; i < qdcount && q < end; ++i) {
                        char* astart = a;

                        *((uint16_t*)a) = htons((q - buffer) | LABEL_BITS);
                        a += 2;

                        int pos = nibbles;
                        struct in6_addr addrtmp = addr;
                        while (q < end && *q) {
                                int n = *q++;
                                for (int i = 0; i < n && pos < 32; ++i, ++pos) {
                                        char c = 15;
                                        switch(q[i]) {
                                        case '0': case '1': case '2': case '3': case '4':
                                        case '5': case '6': case '7': case '8': case '9':
                                                c = q[i] - '0';
                                                break;
                                        case 'a': case 'b': case 'c': case 'd': case 'e': case 'f':
                                                c = 10 + q[i] - 'a';
                                                break;
                                        case 'A': case 'B': case 'C': case 'D': case 'E': case 'F':
                                                c = 10 + q[i] - 'A';
                                                break;
                                        case 'o': case 'O':
                                                c = 0;
                                                break;
                                        case 'z': case 'Z':
                                                c = 12;
                                                break;
                                        case 'i': case 'I':
                                        case 'l': case 'L':
                                        case 'j': case 'J':
                                                c = 1;
                                                break;
                                        }

                                        if (pos % 2)
                                                addrtmp.s6_addr[pos/2] |= c;
                                        else
                                                addrtmp.s6_addr[pos/2] |= c << 4;
                                }
                                q += n;
                        }
                        ++q;

                        if (q + 4 > end) {
                                // todo error
                                break;
                        }

                        uint16_t qtype = ntohs(*((uint16_t*)q));
                        *a++ = *q++;
                        *a++ = *q++;
                        uint16_t qclass = ntohs(*((uint16_t*)q));
                        *a++ = *q++;
                        *a++ = *q++;
                        printf("qtype=%d qclass=%d\n", qtype, qclass);

                        if (qtype == TYPE_AAAA) {
                                *((uint32_t*)a) = htonl(30);
                                a += 4;

                                *((uint16_t*)a) = htons(16);
                                a += 2;
                                memcpy(a, &addrtmp, 16);
                                a += 16;

                                ++ancount;
                        } else {
                                a = astart;
                        }
                }

                h->flags |= htons(FLAG_QR);
                h->ancount = htons(ancount);
                h->nscount = 0;
                h->arcount = 0;

                memcpy(q, answer, a - answer);
                q += a - answer;

                size = sendto(sock, buffer, q - buffer, 0, (struct sockaddr*)&ss, sslen);
                if (size < 0)
                        perror("sendto");
        }
}
