/*
 * NetRecon IPSec Scanner v1.4
 * - IPv4 and IPv6 support (dual-stack)
 * - Command-line flags: --ipv4, --ipv6, --timeout, --retries, -f <file>
 * - Basic IKE_SA_INIT probe for UDP/500 and NAT-T probe for UDP/4500
 * - Clear port states: Closed, Open/Filtered, Error
 *
 * Build: gcc -O2 -Wall -o netrecon netrecon.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include <time.h>
#include <stdbool.h>

#define IPSEC_PORT_1 500     // IKE
#define IPSEC_PORT_2 4500    // NAT-T
#define MAX_TARGETS 100
#define DEFAULT_TIMEOUT_MS 1000
#define DEFAULT_RETRIES 1

typedef enum {
    STATE_ERROR = -1,
    STATE_CLOSED = 0,
    STATE_OPEN_FILTERED = 1
} PortState;

typedef struct {
    char ip[INET6_ADDRSTRLEN];
    PortState port_500_state;
    PortState port_4500_state;
    char service_name[64];
    int family_used; // AF_INET or AF_INET6 or AF_UNSPEC
} ScanResult;

typedef struct {
    ScanResult results[MAX_TARGETS];
    int count;
} ScanReport;

typedef struct {
    int family;            // AF_UNSPEC, AF_INET, AF_INET6
    int timeout_ms;        // per recv timeout
    int retries;           // probes per port
    const char* input_file;
    const char* output_file;
} Config;

/* Prototypes */
void parse_args(int argc, char* argv[], Config* cfg, char ip_out[INET6_ADDRSTRLEN], bool* single_target);
int validate_ip_address(const char* ip);
PortState check_port_udp_probe(const char* ip, int port, int family, int timeout_ms, int retries);
void make_ike_sa_init_probe(uint8_t* buf, size_t* len);
void make_natt_probe(uint8_t* buf, size_t* len);
void scan_ipsec_ports(const char* ip, const Config* cfg, ScanResult* result);
void print_report(const ScanReport* report);
void save_report(const ScanReport* report, const char* filename);
const char* state_str(PortState s);

/* Main */
int main(int argc, char* argv[]) {
    printf("=== NetRecon v1.4 (IPv4/IPv6 + IKE probe) ===\n\n");

    Config cfg = {
        .family = AF_UNSPEC,
        .timeout_ms = DEFAULT_TIMEOUT_MS,
        .retries = DEFAULT_RETRIES,
        .input_file = NULL,
        .output_file = "netrecon_report.txt"
    };

    char single_ip[INET6_ADDRSTRLEN] = {0};
    bool single_target = false;

    parse_args(argc, argv, &cfg, single_ip, &single_target);

    if (geteuid() != 0) {
        printf("[!] Warning: Running without root privileges. UDP/ICMP accuracy may be reduced.\n\n");
    }

    ScanReport report = {0};

    if (single_target) {
        if (!validate_ip_address(single_ip)) {
            printf("[-] Error: Invalid IP address: %s\n", single_ip);
            return 1;
        }
        scan_ipsec_ports(single_ip, &cfg, &report.results[0]);
        report.count = 1;
    } else if (cfg.input_file) {
        FILE* file = fopen(cfg.input_file, "r");
        if (!file) {
            perror("[-] Error opening input file");
            return 1;
        }
        char ip_buf[INET6_ADDRSTRLEN];
        while (fgets(ip_buf, sizeof(ip_buf), file) && report.count < MAX_TARGETS) {
            ip_buf[strcspn(ip_buf, "\r\n")] = 0;
            if (ip_buf[0] == '\0') continue;
            if (!validate_ip_address(ip_buf)) {
                fprintf(stderr, "[-] Skipping invalid IP: %s\n", ip_buf);
                continue;
            }
            scan_ipsec_ports(ip_buf, &cfg, &report.results[report.count]);
            report.count++;
        }
        fclose(file);
    } else {
        printf("Usage:\n");
        printf("  %s <target_ip> [--ipv4|--ipv6] [--timeout ms] [--retries n] [-o file]\n", argv[0]);
        printf("  %s -f <file> [--ipv4|--ipv6] [--timeout ms] [--retries n] [-o file]\n", argv[0]);
        return 1;
    }

    printf("\nScan complete.\n");
    print_report(&report);
    save_report(&report, cfg.output_file);
    printf("Report saved to: %s\n", cfg.output_file);

    return 0;
}

/* Argument parsing */
void parse_args(int argc, char* argv[], Config* cfg, char ip_out[INET6_ADDRSTRLEN], bool* single_target) {
    if (argc < 2) return;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--ipv4") == 0) {
            cfg->family = AF_INET;
        } else if (strcmp(argv[i], "--ipv6") == 0) {
            cfg->family = AF_INET6;
        } else if (strcmp(argv[i], "--timeout") == 0 && i + 1 < argc) {
            cfg->timeout_ms = atoi(argv[++i]);
            if (cfg->timeout_ms <= 0) cfg->timeout_ms = DEFAULT_TIMEOUT_MS;
        } else if (strcmp(argv[i], "--retries") == 0 && i + 1 < argc) {
            cfg->retries = atoi(argv[++i]);
            if (cfg->retries < 1) cfg->retries = DEFAULT_RETRIES;
        } else if (strcmp(argv[i], "-f") == 0 && i + 1 < argc) {
            cfg->input_file = argv[++i];
        } else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            cfg->output_file = argv[++i];
        } else if (argv[i][0] != '-') {
            strncpy(ip_out, argv[i], INET6_ADDRSTRLEN - 1);
            ip_out[INET6_ADDRSTRLEN - 1] = '\0';
            *single_target = true;
        }
    }
}

/* IP validation */
int validate_ip_address(const char* ip) {
    struct sockaddr_in sa;
    struct sockaddr_in6 sa6;
    if (inet_pton(AF_INET, ip, &(sa.sin_addr)) == 1) return 1;
    if (inet_pton(AF_INET6, ip, &(sa6.sin6_addr)) == 1) return 1;
    return 0;
}

/* Build a minimal IKE_SA_INIT packet (not full spec, just a harmless probe) */
void make_ike_sa_init_probe(uint8_t* buf, size_t* len) {
    // Minimal IKEv2 header: 28 bytes
    // Initiator Cookie (8), Responder Cookie (8), Next Payload, Version, Exchange Type,
    // Flags, Message ID, Length (4)
    memset(buf, 0, 28);
    // Fake initiator cookie
    for (int i = 0; i < 8; i++) buf[i] = (uint8_t)(0xA0 + i);
    // Responder cookie left zero
    buf[16] = 33;      // Next Payload = SA (33)
    buf[17] = 0x20;    // Version: IKEv2 (major 2 << 4)
    buf[18] = 34;      // Exchange Type = IKE_SA_INIT (34)
    buf[19] = 0x08;    // Flags: Initiator
    // Message ID (4 bytes) = 0
    // Length (4 bytes) = total length
    uint32_t total_len = htonl(28);
    memcpy(buf + 24, &total_len, 4);
    *len = 28;
}

/* NAT-T probe: send non-empty payload; NAT-T usually replies only in context, so treat as generic UDP probe */
void make_natt_probe(uint8_t* buf, size_t* len) {
    // Simple payload to avoid zero-length send being optimized away
    const char* msg = "NATT?";
    memcpy(buf, msg, strlen(msg));
    *len = strlen(msg);
}

/* UDP check with basic probes and dual-stack support */
PortState check_port_udp_probe(const char* ip, int port, int family, int timeout_ms, int retries) {
    struct addrinfo hints, *res = NULL, *rp = NULL;
    char portstr[16];
    snprintf(portstr, sizeof(portstr), "%d", port);

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = family;     // AF_UNSPEC/AF_INET/AF_INET6
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_NUMERICHOST; // ip is a literal

    int gai = getaddrinfo(ip, portstr, &hints, &res);
    if (gai != 0 || !res) {
        return STATE_ERROR;
    }

    // Prepare probes
    uint8_t probe[64];
    size_t probe_len = 0;
    if (port == IPSEC_PORT_1) {
        make_ike_sa_init_probe(probe, &probe_len);
    } else {
        make_natt_probe(probe, &probe_len);
    }

    PortState final_state = STATE_CLOSED;

    for (rp = res; rp != NULL; rp = rp->ai_next) {
        int sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sockfd < 0) {
            final_state = STATE_ERROR;
            continue;
        }

        // Set timeouts
        struct timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        // Connect the UDP socket
        if (connect(sockfd, rp->ai_addr, rp->ai_addrlen) < 0) {
            close(sockfd);
            // Could be filtered or no route; we try next addrinfo
            final_state = (final_state == STATE_ERROR) ? STATE_ERROR : STATE_CLOSED;
            continue;
        }

        // Send a few retries
        PortState addr_state = STATE_CLOSED;
        for (int attempt = 0; attempt < retries; attempt++) {
            ssize_t s = send(sockfd, probe, probe_len, 0);
            if (s < 0) {
                if (errno == ECONNREFUSED) {
                    addr_state = STATE_CLOSED;
                    break;
                } else {
                    addr_state = STATE_ERROR;
                    continue;
                }
            }

            // Try read any response; most services won’t reply to a bare probe
            uint8_t buf[256];
            ssize_t r = recv(sockfd, buf, sizeof(buf), 0);
            if (r > 0) {
                // Received something: treat as open
                addr_state = STATE_OPEN_FILTERED;
                break;
            } else {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    // No response within timeout: Open or filtered (typical for UDP)
                    addr_state = STATE_OPEN_FILTERED;
                } else if (errno == ECONNREFUSED) {
                    addr_state = STATE_CLOSED;
                    break;
                } else {
                    addr_state = STATE_ERROR;
                }
            }
        }

        close(sockfd);

        // Consolidate: if any addrinfo suggests open/filtered, prefer that
        if (addr_state == STATE_OPEN_FILTERED) {
            final_state = STATE_OPEN_FILTERED;
            break; // good enough
        } else if (addr_state == STATE_ERROR) {
            final_state = (final_state == STATE_OPEN_FILTERED) ? STATE_OPEN_FILTERED : STATE_ERROR;
        } else if (addr_state == STATE_CLOSED) {
            // keep looking; do not override OPEN_FILTERED
            if (final_state != STATE_OPEN_FILTERED && final_state != STATE_ERROR)
                final_state = STATE_CLOSED;
        }
    }

    freeaddrinfo(res);
    return final_state;
}

/* Scan one target */
void scan_ipsec_ports(const char* ip, const Config* cfg, ScanResult* result) {
    printf("[*] Scanning: %s\n", ip);
    strncpy(result->ip, ip, INET6_ADDRSTRLEN - 1);
    result->ip[INET6_ADDRSTRLEN - 1] = '\0';
    result->family_used = cfg->family;

    result->port_500_state = check_port_udp_probe(ip, IPSEC_PORT_1, cfg->family, cfg->timeout_ms, cfg->retries);
    result->port_4500_state = check_port_udp_probe(ip, IPSEC_PORT_2, cfg->family, cfg->timeout_ms, cfg->retries);

    // Only suggest service if at least one port seems responsive/open-filtered
    if (result->port_500_state == STATE_OPEN_FILTERED || result->port_4500_state == STATE_OPEN_FILTERED) {
        strcpy(result->service_name, "Possible IPSec/IKE");
    } else {
        strcpy(result->service_name, "None detected");
    }
}

/* Reporting helpers */
const char* state_str(PortState s) {
    switch (s) {
        case STATE_ERROR: return "Error";
        case STATE_CLOSED: return "Closed";
        case STATE_OPEN_FILTERED: return "Open/Filtered";
        default: return "Unknown";
    }
}

void print_report(const ScanReport* report) {
    printf("\n=== Scan Report ===\n");
    for (int i = 0; i < report->count; i++) {
        const ScanResult* r = &report->results[i];
        printf("Target: %-39s | IKE(500): %-14s | NAT-T(4500): %-14s | Service: %s\n",
               r->ip,
               state_str(r->port_500_state),
               state_str(r->port_4500_state),
               r->service_name);
    }
}

void save_report(const ScanReport* report, const char* filename) {
    FILE* file = fopen(filename, "w");
    if (!file) {
        perror("[-] Error saving report");
        return;
    }

    time_t now = time(NULL);
    char timestr[64];
    struct tm* tm = localtime(&now);
    strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", tm);

    fprintf(file, "NetRecon IPSec Report\nGenerated: %s\n\n", timestr);
    for (int i = 0; i < report->count; i++) {
        const ScanResult* r = &report->results[i];
        fprintf(file, "Target: %s | IKE(500): %s | NAT-T(4500): %s | Service: %s\n",
                r->ip,
                state_str(r->port_500_state),
                state_str(r->port_4500_state),
                r->service_name);
    }
    fclose(file);
}
