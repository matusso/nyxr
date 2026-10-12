/* Bounded VNET-only FreeBSD fixture. Fixed messages only; no remote shell.
 * Build with: cc -O2 -Wall -Wextra -Werror -o bsd-endpoint bsd-endpoint.c
 * Args: interface local-v4 peer-v4 local-v6 peer-v6 seconds
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/utsname.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <ifaddrs.h>
#include <ctype.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t stopped;
static int original_sack, have_original, listeners[3] = {-1, -1, -1};
static const char *interface, *local4, *peer4, *local6, *peer6;
static char fixture[33];
static const char *condition = "clean";
static int jailed;
static int listen_address(int family, const char *address, int port);
static int configure(const char *mode) {
    /* Changes only this fresh VNET: reserved rules/set/pipe; numeric addresses. */
    if (jailed != 1) return -1;
    char command[1024];
    int n = snprintf(command, sizeof(command),
        "/sbin/ipfw -q delete 60066 60067 2>/dev/null; /sbin/ipfw pipe delete 6066 2>/dev/null; ");
    if (!strcmp(mode, "loss-jitter")) {
        n += snprintf(command + n, sizeof(command) - n,
            "/sbin/ipfw pipe 6066 config bw 100Mbit/s profile /fixture/delay-profile.txt plr 0.05 && "
            "/sbin/ipfw -q add 60066 set 30 pipe 6066 tcp from %s 443 to %s out tcpflags syn,ack && "
            "/sbin/ipfw -q add 60067 set 30 pipe 6066 tcp from %s 443 to %s out tcpflags syn,ack",
            local4, peer4, local6, peer6);
    } else if (!strcmp(mode, "drop")) {
        n += snprintf(command + n, sizeof(command) - n,
            "/sbin/ipfw -q add 60066 set 30 deny tcp from %s 443 to %s out tcpflags syn,ack && "
            "/sbin/ipfw -q add 60067 set 30 deny tcp from %s 443 to %s out tcpflags syn,ack",
            local4, peer4, local6, peer6);
    } else {
        n += snprintf(command + n, sizeof(command) - n, "true");
    }
    if (n < 0 || (size_t)n >= sizeof(command) || system(command)) return -1;
    condition = mode; return 0;
}

static void stop_signal(int sig) { (void)sig; stopped = 1; }
static int sack_value(void) {
    int value = -1;
    size_t size = sizeof(value);
    if (sysctlbyname("net.inet.tcp.sack.enable", &value, &size, NULL, 0)) return -1;
    return value;
}
static int set_sack(int value) {
    if (sysctlbyname("net.inet.tcp.sack.enable", NULL, NULL, &value, sizeof(value))) return -1;
    return sack_value() == value ? 0 : -1;
}
static void close_listeners(void) {
    for (int i = 0; i < 3; i++) if (listeners[i] >= 0) {
        close(listeners[i]); listeners[i] = -1;
    }
}
static void cleanup(void) {
    close_listeners();
    if (jailed == 1 && configure("clean")) fprintf(stderr, "ERROR: shaping cleanup failed\n");
    if (have_original && set_sack(original_sack))
        fprintf(stderr, "ERROR: original SACK setting could not be restored\n");
}
static void quoted(FILE *out, const char *value) {
    fputc('"', out);
    for (const unsigned char *p = (const unsigned char *)value; *p; p++) {
        if (*p == '"' || *p == '\\') { fputc('\\', out); fputc(*p, out); }
        else if (*p < 32) fprintf(out, "\\u%04x", *p);
        else fputc(*p, out);
    }
    fputc('"', out);
}
static void command_json(FILE *out, const char *command) {
    /* All commands are fixed read-only snapshots; interface is alphanumeric. */
    char text[32768];
    FILE *pipe = popen(command, "r");
    if (!pipe) { quoted(out, "snapshot could not start"); return; }
    size_t size = fread(text, 1, sizeof(text) - 1, pipe);
    text[size] = 0;
    int status = pclose(pipe);
    fputs("{\"exit_status\":", out); fprintf(out, "%d,\"text\":", status);
    quoted(out, text); fputc('}', out);
}
static void truth(FILE *out) {
    struct utsname os;
    if (uname(&os)) memset(&os, 0, sizeof(os));
    char command[128];
    fputs("{\"platform\":", out); quoted(out, os.sysname);
    fputs(",\"release\":", out); quoted(out, os.release);
    fputs(",\"architecture\":", out); quoted(out, os.machine);
    fputs(",\"fixture\":", out); quoted(out, fixture);
    fprintf(out, ",\"jailed\":%d,\"condition\":", jailed); quoted(out, condition);
    fputs(",\"interface\":", out); quoted(out, interface);
    fputs(",\"local_v4\":", out); quoted(out, local4);
    fputs(",\"peer_v4\":", out); quoted(out, peer4);
    fputs(",\"local_v6\":", out); quoted(out, local6);
    fputs(",\"peer_v6\":", out); quoted(out, peer6);
    fprintf(out, ",\"port\":443,\"sack\":%d,\"original_sack\":%d,\"listeners_closed\":%s,\"addresses\":",
            sack_value(), original_sack, listeners[0] < 0 && listeners[1] < 0 && listeners[2] < 0 ? "true" : "false");
    snprintf(command, sizeof(command), "/sbin/ifconfig %s 2>&1", interface);
    command_json(out, command);
    fputs(",\"routes\":", out); command_json(out, "/usr/bin/netstat -rn 2>&1");
    fputs(",\"versions\":", out); command_json(out, "/bin/freebsd-version -ru 2>&1");
    fputs(",\"firewall\":", out);
    command_json(out, "/sbin/sysctl net.inet.ip.fw.enable net.inet6.ip6.fw.enable 2>&1 && /sbin/ipfw -a list && /sbin/ipfw pipe show");
    fputs(",\"tcp_settings\":", out);
    command_json(out, "/sbin/sysctl net.inet.tcp.sack.enable net.inet.tcp.rfc1323 net.inet.tcp.syncookies 2>&1");
    fputs("}\n", out); fflush(out);
}
static int private4(const struct in_addr *address) {
    unsigned int value = ntohl(address->s_addr);
    return (value >> 24) == 10 || (value >> 20) == 0xac1 || (value >> 16) == 0xc0a8;
}
static int assigned(int family, const void *address) {
    struct ifaddrs *list;
    if (getifaddrs(&list)) return 0;
    int found = 0;
    for (struct ifaddrs *p = list; p; p = p->ifa_next) {
        if (!p->ifa_addr || strcmp(p->ifa_name, interface) || p->ifa_addr->sa_family != family) continue;
        const void *candidate = family == AF_INET ?
            (void *)&((struct sockaddr_in *)p->ifa_addr)->sin_addr :
            (void *)&((struct sockaddr_in6 *)p->ifa_addr)->sin6_addr;
        if (!memcmp(candidate, address, family == AF_INET ? 4 : 16)) found++;
    }
    freeifaddrs(list); return found == 1;
}
static int listen_address(int family, const char *address, int port) {
    int fd = socket(family, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int reuse = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse))) { close(fd); return -1; }
    int result;
    if (family == AF_INET) {
        struct sockaddr_in addr = {0};
        addr.sin_len = sizeof(addr); addr.sin_family = AF_INET; addr.sin_port = htons(port);
        inet_pton(AF_INET, address, &addr.sin_addr);
        result = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
    } else {
        int only6 = 1;
        if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &only6, sizeof(only6))) { close(fd); return -1; }
        struct sockaddr_in6 addr = {0};
        addr.sin6_len = sizeof(addr); addr.sin6_family = AF_INET6; addr.sin6_port = htons(port);
        inet_pton(AF_INET6, address, &addr.sin6_addr);
        result = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
    }
    if (result || listen(fd, 16)) { close(fd); return -1; }
    return fd;
}
static int allowed_peer(const struct sockaddr_storage *address) {
    if (address->ss_family == AF_INET) {
        struct in_addr expected; inet_pton(AF_INET, peer4, &expected);
        return !memcmp(&expected, &((const struct sockaddr_in *)address)->sin_addr, 4);
    }
    if (address->ss_family == AF_INET6) {
        struct in6_addr expected; inet_pton(AF_INET6, peer6, &expected);
        return !memcmp(&expected, &((const struct sockaddr_in6 *)address)->sin6_addr, 16);
    }
    return 0;
}
int main(int argc, char **argv) {
    if (argc != 7 || geteuid() != 0) { fprintf(stderr, "Root and six explicit fixture arguments required\n"); return 1; }
    interface = argv[1]; local4 = argv[2]; peer4 = argv[3]; local6 = argv[4]; peer6 = argv[5];
    if (!*interface || strlen(interface) > 32) return 1;
    for (const unsigned char *p = (const unsigned char *)interface; *p; p++) if (!isalnum(*p)) return 1;
    char *end;
    long seconds = strtol(argv[6], &end, 10);
    if (*end || seconds < 60 || seconds > 21600) return 1;
    struct in_addr a4, p4; struct in6_addr a6, p6;
    if (inet_pton(AF_INET, local4, &a4) != 1 || inet_pton(AF_INET, peer4, &p4) != 1 ||
        inet_pton(AF_INET6, local6, &a6) != 1 || inet_pton(AF_INET6, peer6, &p6) != 1 ||
        !private4(&a4) || !private4(&p4) || (a6.s6_addr[0] & 254) != 252 || (p6.s6_addr[0] & 254) != 252 ||
        !memcmp(&a4, &p4, 4) || !memcmp(&a6, &p6, 16) || !assigned(AF_INET, &a4) || !assigned(AF_INET6, &a6)) return 1;
    size_t jailed_size = sizeof(jailed);
    if (sysctlbyname("security.jail.jailed", &jailed, &jailed_size, NULL, 0) || jailed != 1) {
        fprintf(stderr, "Fresh operator-owned VNET jail required\n"); return 1;
    }
    original_sack = sack_value();
    if (original_sack != 0 && original_sack != 1) { fprintf(stderr, "Native SACK control unavailable\n"); return 1; }
    have_original = 1; atexit(cleanup);
    signal(SIGINT, stop_signal); signal(SIGTERM, stop_signal); signal(SIGHUP, stop_signal);
    signal(SIGPIPE, SIG_IGN);
    unsigned int random[4]; arc4random_buf(random, sizeof(random));
    snprintf(fixture, sizeof(fixture), "%08x%08x%08x%08x", random[0], random[1], random[2], random[3]);
    listeners[0] = listen_address(AF_INET, local4, 443); listeners[1] = listen_address(AF_INET6, local6, 443);
    listeners[2] = listen_address(AF_INET, local4, 18067);
    if (listeners[0] < 0 || listeners[1] < 0 || listeners[2] < 0) { perror("exclusive fixture bind"); return 1; }
    printf("BSD fixture %s listening; original SACK=%d; bounded to %ld seconds\n", fixture, original_sack, seconds); fflush(stdout);
    time_t deadline = time(NULL) + seconds;
    while (!stopped && time(NULL) < deadline) {
        struct pollfd fds[3] = {{listeners[0], POLLIN, 0}, {listeners[1], POLLIN, 0}, {listeners[2], POLLIN, 0}};
        if (poll(fds, 3, 250) < 0) { if (errno == EINTR) continue; break; }
        for (int i = 0; i < 3 && !stopped; i++) if (fds[i].revents & POLLIN) {
            struct sockaddr_storage peer; socklen_t size = sizeof(peer);
            int fd = accept(listeners[i], (struct sockaddr *)&peer, &size);
            if (fd < 0) continue;
            if (!allowed_peer(&peer)) { close(fd); continue; }
            if (i < 2) { close(fd); continue; } /* Measurement connections carry no control. */
            struct timeval timeout = {2, 0};
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
            setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
            char request[16] = {0}; size_t n = 0;
            while (n < sizeof(request) - 1) {
                ssize_t got = read(fd, request + n, 1);
                if (got != 1 || request[n] == '\n') break;
                n++;
            }
            request[n] = 0;
            if (!strcmp(request, "CLEAN0") || !strcmp(request, "CLEAN1") ||
                !strcmp(request, "IMPAIR0") || !strcmp(request, "IMPAIR1") || !strcmp(request, "DROP1")) {
                const char *mode = request[0] == 'I' ? "loss-jitter" : request[0] == 'D' ? "drop" : "clean";
                int value = request[strlen(request) - 1] - '0';
                if (configure(mode) || set_sack(value)) { close(fd); stopped = 1; break; }
                for (int k = 0; k < 2; k++) { close(listeners[k]); listeners[k] = -1; }
                listeners[0] = listen_address(AF_INET, local4, 443);
                listeners[1] = listen_address(AF_INET6, local6, 443);
                if (listeners[0] < 0 || listeners[1] < 0) { close(fd); stopped = 1; break; }
            } else if (!strcmp(request, "STOP")) {
                cleanup(); stopped = 1;
            } else if (strcmp(request, "TRUTH")) { close(fd); continue; }
            FILE *stream = fdopen(fd, "w");
            if (stream) { truth(stream); fclose(stream); } else close(fd);
        }
    }
    cleanup();
    if (sack_value() != original_sack) return 1;
    puts("BSD fixture stopped; original SACK restored and listeners closed");
    return 0;
}
