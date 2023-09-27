#include <string.h>

#include "parsers.h"

client_command_t parse_client_input(char *buffer, size_t buflen, char **arg) {
    // Scan for newline
    for (int i = 0; i < buflen; i++) {
        if (buffer[i] == '\n') {
            buffer[i] = 0;
            buflen = i;
            break;
        }
    }
    if (buflen >= 4 && strncmp(buffer, "LIST", 4) == 0) {
        return CLIENT_CMD_LIST;
    }
    else if (buflen >= 7 && strncmp(buffer, "EXAMINE", 7) == 0) {
        char *ptr = &buffer[7];
        char *end = &buffer[buflen];
        // Skip whitespace
        while (ptr < end && (*ptr == ' ' || *ptr == '\t')) ptr++;
        if (ptr == end) {
            return CLIENT_CMD_EXAMINE | CLIENT_CMD_INVALID;
        }
        *arg = ptr;
        return CLIENT_CMD_EXAMINE;
    }
    else if (buflen >= 9 && strncmp(buffer, "EMERGENCY", 9) == 0) {
        return CLIENT_CMD_EMERGENCY;
    }
    else if (buflen >= 4 && strncmp(buffer, "QUIT", 4) == 0) {
        return CLIENT_CMD_QUIT;
    }
    else if (buflen >= 4 && strncmp(buffer, "HELP", 4) == 0) {
        return CLIENT_CMD_HELP;
    }
    else {
        return CLIENT_CMD_UNKNOWN;
    }
}
