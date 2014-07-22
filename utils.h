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
        TYPE_A       = 1,
        TYPE_NS      = 2,
        TYPE_CNAME   = 5,
        TYPE_SOA     = 6,
        TYPE_MX      = 15,
        TYPE_TXT     = 16,
        TYPE_AAAA    = 28,
        TYPE_ANY     = 255,
};

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

static void drop_privs() {
        if (!getuid()) {
                struct passwd* pw = getpwnam("nobody");
                DIE(pw, getpwname);
                char name[] = "/tmp/sandbox.XXXXXX";
                DIE(mkdtemp(name), mkdtemp);
                DIE(!chdir(name), chdir);
                DIE(!rmdir(name), rmdir);
                DIE(!chroot("."), chroot);
                DIE(!setgid(pw->pw_gid), setgid);
                DIE(!setuid(pw->pw_uid), setuid);
                FATAL(setuid(0) < 0, "Dropping privileges failed");
        }
}

static int subdomain(char* s, const char* domain) {
        int len = strlen(s) - strlen(domain);
        if (len < 0)
                return -1;
        char* r = s + len;
        if (strcmp(r, domain) || (r > s && r[-1] != '.'))
                return -1;
        if (r > s)
                r[-1] = 0;
        return len;
}
