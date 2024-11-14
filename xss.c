#include "xss.h"
#include <stdio.h>
#include <regex.h>

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
