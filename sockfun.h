#pragma once

#include <sys/select.h>

#define RSA_EXPONENT 65537
#define RSA_KEY_SIZE 1024
typedef struct {
    int server_fd;
    int control_fd;
    unsigned long maxfds;
    int nfds;
    fd_set readfds;
    // fd_set writefds;
    fd_set exceptfds;
    unsigned char pubkey[RSA_KEY_SIZE/8];
} session_t;