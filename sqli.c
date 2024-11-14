#include "sqli.h"
#include <stdio.h>
#include <regex.h>

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
