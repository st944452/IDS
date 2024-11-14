#include "packet_handler.h"
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

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
