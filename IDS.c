#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <regex.h>

void block_ip(const char *ip_address) {
    char *args[] = {"iptables", "-A", "INPUT", "-s", (char *)ip_address, "-j", "DROP", NULL};
    if (fork() == 0) {
        execvp("iptables", args);
        perror("Error executing iptables command");
        exit(1);
    }
    printf("Blocked IP: %s\n", ip_address);
}

void log_alert(const char *alert_msg) {
    FILE *log_file = fopen("ids_alerts.log", "a");
    if (log_file != NULL) {
        fprintf(log_file, "%s\n", alert_msg);
        fclose(log_file);
    } else {
        perror("Error opening log file");
    }
}

int detect_sqli(const char *payload) {
    regex_t regex;
    const char *sqli_pattern = "' OR 1=1|SELECT.*FROM|INSERT.*INTO|UPDATE.*SET.*DELETE.*FROM|DROP.*TABLE|ALTER.*TABLE|CREATE.*TABLE|TRUNCATE.*TABLE";
    if (regcomp(&regex, sqli_pattern, REG_ICASE | REG_EXTENDED) != 0) {
        fprintf(stderr, "Error compiling SQLi regex\n");
        return 0;
    }
    int result = regexec(&regex, payload, 0, NULL, 0);
    regfree(&regex);
    return result == 0;
}

int detect_xss(const char *payload) {
    regex_t regex;
    const char *xss_pattern = "<.*script.*>.*</.*script.*>|<.*script.*>|.*javascript.*";
    if (regcomp(&regex, xss_pattern, REG_ICASE | REG_EXTENDED) != 0) {
        fprintf(stderr, "Error compiling XSS regex\n");
        return 0;
    }
    int result = regexec(&regex, payload, 0, NULL, 0);
    regfree(&regex);
    return result == 0;
}

void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    char alert_msg[256];
    struct ip *ip_header = (struct ip *)(packet + 14);

    if (ip_header->ip_p == IPPROTO_TCP) {
        struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + (ip_header->ip_hl * 4));
        uint16_t src_port = ntohs(tcp_header->source);
        uint16_t dst_port = ntohs(tcp_header->dest);

        if (tcp_header->syn == 1 && tcp_header->ack == 0) {
            snprintf(alert_msg, sizeof(alert_msg), "SYN scan detected: %s -> %s",
                     inet_ntoa(ip_header->ip_src), inet_ntoa(ip_header->ip_dst));
            log_alert(alert_msg);
            printf("%s\n", alert_msg);
            block_ip(inet_ntoa(ip_header->ip_src));
        }

        if (dst_port == 80 || src_port == 80) {
            char *payload = (char *)(packet + 14 + (ip_header->ip_hl * 4) + (tcp_header->doff * 4));
            int payload_len = pkthdr->len - (14 + (ip_header->ip_hl * 4) + (tcp_header->doff * 4));

            if (payload_len > 0) {
                printf("HTTP request detected:\n%s\n", payload);

                if (detect_sqli(payload)) {
                    snprintf(alert_msg, sizeof(alert_msg), "SQL Injection detected from: %s", inet_ntoa(ip_header->ip_src));
                    log_alert(alert_msg);
                    printf("%s\n", alert_msg);
                    block_ip(inet_ntoa(ip_header->ip_src));
                }

                if (detect_xss(payload)) {
                    snprintf(alert_msg, sizeof(alert_msg), "XSS attack detected from: %s", inet_ntoa(ip_header->ip_src));
                    log_alert(alert_msg);
                    printf("%s\n", alert_msg);
                    block_ip(inet_ntoa(ip_header->ip_src));
                }

                snprintf(alert_msg, sizeof(alert_msg), "HTTP Traffic detected: %s:%d -> %s:%d",
                         inet_ntoa(ip_header->ip_src), src_port, inet_ntoa(ip_header->ip_dst), dst_port);
                log_alert(alert_msg);
                printf("%s\n", alert_msg);
            }
        }

        if (dst_port == 443 || src_port == 443) {
            snprintf(alert_msg, sizeof(alert_msg), "HTTPS Traffic detected: %s:%d -> %s:%d",
                     inet_ntoa(ip_header->ip_src), src_port, inet_ntoa(ip_header->ip_dst), dst_port);
            log_alert(alert_msg);
            printf("%s\n", alert_msg);
        }
    }
}

int main() {
    printf("------------------------------AI BASED Intrusion Detection System---------------------------------\n");
    pcap_if_t *alldevs, *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return 1;
    }

    dev = alldevs;
    if (dev == NULL) {
        fprintf(stderr, "No devices found!\n");
        return 1;
    }
    printf("Using device: %s\n", dev->name);

    handle = pcap_open_live(dev->name, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening device: %s\n", errbuf);
        pcap_freealldevs(alldevs);
        return 1;
    }

    if (pcap_loop(handle, 0, packet_handler, NULL) == -1) {
        fprintf(stderr, "Error capturing packets: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        pcap_freealldevs(alldevs);
        return 1;
    }

    pcap_close(handle);
    pcap_freealldevs(alldevs);
    return 0;
}