#include "packet_handler.h"
#include "log.h"
#include "block.h"
#include "sqli.h"
#include "xss.h"
#include <stdio.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

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
