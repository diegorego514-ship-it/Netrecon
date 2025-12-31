#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include <time.h>

#define IPSEC_PORT_1 500
#define IPSEC_PORT_2 4500
#define MAX_TARGETS 100

typedef struct {
    char ip[INET6_ADDRSTRLEN];
    int port_500_open;
    int port_4500_open;
    char service_name[50];
} ScanResult;

typedef struct {
    ScanResult results[MAX_TARGETS];
    int count;
} ScanReport;

// Function prototypes
int validate_ip_address(const char *ip);
int check_port_udp(const char *ip, int port);
void scan_ipsec_ports(const char *ip, ScanResult *result);
void save_report(const ScanReport *report, const char *filename);
void print_report(const ScanReport *report);

int main(int argc, char *argv[]) {
    printf("=== NetRecon v1.2 (Final Fixed Edition) ===\n\n");
    
    if (argc < 2) {
        printf("Usage: %s <target_ip>\n", argv[0]);
        printf("Usage: %s -f <filename> (for batch scanning)\n", argv[0]);
        return 1;
    }

    if (geteuid() != 0) {
        printf("[!] Warning: Running without root privileges. UDP accuracy may be reduced.\n\n");
    }

    ScanReport report = {0};

    if (strcmp(argv[1], "-f") == 0 && argc >= 3) {
        FILE *file = fopen(argv[2], "r");
        if (!file) {
            perror("[-] Error opening file");
            return 1;
        }

        char ip_buf[INET6_ADDRSTRLEN];
        while (fgets(ip_buf, sizeof(ip_buf), file) && report.count < MAX_TARGETS) {
            ip_buf[strcspn(ip_buf, "\r\n")] = 0; 

            if (validate_ip_address(ip_buf)) {
                scan_ipsec_ports(ip_buf, &report.results[report.count]);
                report.count++;
            }
        }
        fclose(file);
    } else {
        if (!validate_ip_address(argv[1])) {
            printf("[-] Error: Invalid IP address: %s\n", argv[1]);
            return 1;
        }
        scan_ipsec_ports(argv[1], &report.results[0]);
        report.count = 1;
    }

    printf("\nScan Complete.\n");
    print_report(&report);
    save_report(&report, "netrecon_report.txt");
    printf("Report saved to: netrecon_report.txt\n");

    return 0;
}

int validate_ip_address(const char *ip) {
    struct sockaddr_in sa;
    struct sockaddr_in6 sa6;
    if (inet_pton(AF_INET, ip, &(sa.sin_addr)) == 1) return 1;
    if (inet_pton(AF_INET6, ip, &(sa6.sin6_addr)) == 1) return 1;
    return 0;
}

int check_port_udp(const char *ip, int port) {
    int sockfd;
    struct sockaddr_in server_addr;
    
    sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sockfd < 0) return -1;

    sockfd = 1;
    sockfd = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &sockfd, sizeof(sockfd));

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &server_addr.sin_addr);

    // UDP Connect
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        close(sockfd);
        return 0;
    }

    // Attempt a zero-byte send to trigger ICMP errors
    if (send(sockfd, "", 0, 0) < 0) {
        close(sockfd);
        return 0;
    }
    
    char buf[1];
    if (recv(sockfd, buf, 1, 0) < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            close(sockfd);
            return 1; // Open or Filtered
        }
        close(sockfd);
        return 0; // Closed
    }

    close(sockfd);
    return 1;
}

void scan_ipsec_ports(const char *ip, ScanResult *result) {
    printf("[*] Scanning: %s\n", ip);
    strncpy(result->ip, ip, INET6_ADDRSTRLEN - 1);
    result->ip[INET6_ADDRSTRLEN - 1] = '\0';
    
    result->port_500_open = check_port_udp(ip, IPSEC_PORT_1);
    result->port_4500_open = check_port_udp(ip, IPSEC_PORT_2);

    if (result->port_500_open > 0 || result->port_4500_open > 0) {
        strcpy(result->service_name, "IPSec/IKE");
    } else {
        strcpy(result->service_name, "None");
    }
}

void print_report(const ScanReport *report) {
    printf("\n=== Scan Report ===\n");
    for (int i = 0; i < report->count; i++) {
        printf("Target: %-15s | Status: %s\n", 
               report->results[i].ip, 
               (report->results[i].port_500_open > 0) ? "VULNERABLE" : "SECURE");
    }
}

void save_report(const ScanReport *report, const char *filename) {
    FILE *file = fopen(filename, "w");
    if (!file) return;

    time_t now = time(NULL);
    fprintf(file, "NetRecon IPSec Report\nGenerated: %s\n", ctime(&now));
    
    for (int i = 0; i < report->count; i++) {
        fprintf(file, "Target: %s | IKE: %d | NAT-T: %d | Service: %s\n", 
                report->results[i].ip, 
                report->results[i].port_500_open, 
                report->results[i].port_4500_open,
                report->results[i].service_name);
    }
    fclose(file);
}
