#include "block.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void block_ip(const char *ip_address) {
    char *args[] = {"iptables", "-A", "INPUT", "-s", (char *)ip_address, "-j", "DROP", NULL};
    if (fork() == 0) {
        execvp("iptables", args);
        perror("Error executing iptables command");
        exit(1);
    }
    printf("Blocked IP: %s\n", ip_address);
}
