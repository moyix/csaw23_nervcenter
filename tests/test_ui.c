#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "nervcenter.h"
#include "ui.h"
#include "magi_ui.h"

int random_fdset(fd_set *s, int maxfds) {
    int nfds = 0;
    FD_ZERO(s);
    for (int j = 0; j < maxfds; j++) {
        if (rand() % 2) {
            FD_SET(j, s);
            if (j > nfds) nfds = j;
        }
    }
    return nfds;
}

#define ROUNDS 100

int main(int argc, char **argv) {
    session_t s;
    if (argc < 2) {
        s.maxfds = 1024+64-ROUNDS;
    }
    else {
        s.maxfds = atoi(argv[1]);
    }
    s.nfds = 0;
    pthread_mutex_init(&s.sensor_lock, NULL);
    dprintf(1, "\033[H\033[2J\033[3J");
    dprintf(1, "\033[?25l");            // hide cursor
    for (int i = 0; i < ROUNDS; i++) {
    // Make up three fd_sets by setting random bits
        int n = random_fdset(&s.readfds, s.maxfds);
        if (n > s.nfds) s.nfds = n;
        n = random_fdset(&s.writefds, s.maxfds);
        if (n > s.nfds) s.nfds = n;
        n = random_fdset(&s.exceptfds, s.maxfds);
        if (n > s.nfds) s.nfds = n;
        dprintf(1, "\033[H");
        render_fdsets_cells(&magi_ui, &s);
        render_surface(1, &magi_ui);
        s.maxfds++;
        if (s.maxfds > 1024+64) s.maxfds = 1024;
        usleep(10000);
    };
    dprintf(1, "\033[?25h");            // show cursor
    dprintf(1, "\033[0m");              // reset attributes

    return 0;
}
