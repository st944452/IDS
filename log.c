#include "log.h"
#include <stdio.h>

void log_alert(const char *alert_msg) {
    FILE *log_file = fopen("ids_alerts.log", "a");
    if (log_file != NULL) {
        fprintf(log_file, "%s\n", alert_msg);
        fclose(log_file);
    } else {
        perror("Error opening log file");
    }
}
