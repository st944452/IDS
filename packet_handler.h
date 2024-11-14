#ifndef PACKET_HANDLER_H
#define PACKET_HANDLER_H

#include <pcap.h>

void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet);

#endif
