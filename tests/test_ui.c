#include <stdio.h>
#include <stdlib.h>

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

int main(int argc, char **argv) {
    session_t s;
    if (argc < 2) {
        s.maxfds = 1024;
    }
    else {
        s.maxfds = atoi(argv[1]);
    }
    s.nfds = 0;
    pthread_mutex_init(&s.sensor_lock, NULL);
    // Make up three fd_sets by setting random bits
    int n = random_fdset(&s.readfds, s.maxfds);
    if (n > s.nfds) s.nfds = n;
    n = random_fdset(&s.writefds, s.maxfds);
    if (n > s.nfds) s.nfds = n;
    n = random_fdset(&s.exceptfds, s.maxfds);
    if (n > s.nfds) s.nfds = n;

    // render_fdset(1, &s);

    render_fdsets_cells(&magi_ui, &s);
    // render_surface(1, &magi_ui);

    return 0;
}
