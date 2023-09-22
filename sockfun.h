#pragma once

#include <sys/select.h>

typedef struct {
    int nfds;
    fd_set readfds;
    // fd_set writefds;
    fd_set exceptfds;
    unsigned char pubkey[128];
} session_t;