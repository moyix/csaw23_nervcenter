#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>

#include "ui.h"

void render_fdline(int fd, int i, fd_set *s, int maxfds) {
    // unicode block elements to represent 0..15:
    // ' ', '▘', '▝', '▀', '▖', '▌', '▞', '▛', '▗', '▚', '▐', '▜', '▄', '▙', '▟', '█'
    const unsigned char blocks[16][3] = {
        { 0x00, 0x00, 0x00 },
        { 0xe2, 0x96, 0x98 },
        { 0xe2, 0x96, 0x9d },
        { 0xe2, 0x96, 0x80 },
        { 0xe2, 0x96, 0x96 },
        { 0xe2, 0x96, 0x8c },
        { 0xe2, 0x96, 0x9e },
        { 0xe2, 0x96, 0x9b },
        { 0xe2, 0x96, 0x97 },
        { 0xe2, 0x96, 0x9a },
        { 0xe2, 0x96, 0x90 },
        { 0xe2, 0x96, 0x9c },
        { 0xe2, 0x96, 0x84 },
        { 0xe2, 0x96, 0x99 },
        { 0xe2, 0x96, 0x9f },
        { 0xe2, 0x96, 0x88 },
    };

    // set color to red
    dprintf(fd, "\033[31m");
    for (int j = 0; j < 128; j += 4) {
        int box_idx = 0;
        for (int k = 0; k < 4; k++) {
            if (i + j + k >= maxfds) break;
            if (FD_ISSET(i + j + k, s)) {
                box_idx |= 1 << k;
            }
        }
        if (box_idx == 0) {
            dprintf(fd, " ");
        }
        else {
            write(fd, blocks[box_idx], 3);
        }
    }
    // reset color
    dprintf(fd, "\033[0m");
}

// Draw the three fd_sets using the unicode block elements
void render_fdset(int fd, session_t *s) {
    const unsigned char spacer[32];
    const unsigned char vertical_line[] = { 0xe2, 0x95, 0x91 };
    const unsigned char left_diag[] = { 0xe2, 0x95, 0xb1 };
    const unsigned char right_diag[] = { 0xe2, 0x95, 0xb2 };
    const unsigned char casper[] = { 0xe2, 0x95, 0x94, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0x20, 0x43, 0x41, 0x53, 0x50, 0x45, 0x52, 0x2d, 0x33, 0x20, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x97 };
    const unsigned char balthasar[] = { 0xe2, 0x95, 0x94, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0x20, 0x42, 0x41, 0x4c, 0x54, 0x48, 0x41, 0x53, 0x41, 0x52, 0x2d, 0x32, 0x20, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x97 };
    const unsigned char melchior[] = { 0xe2, 0x95, 0x94, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0x20, 0x4d, 0x45, 0x4c, 0x43, 0x48, 0x49, 0x4f, 0x52, 0x2d, 0x31, 0x20, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x97 };
    const unsigned char bottom[] = { 0xe2, 0x95, 0x9a, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x9d };
    const unsigned char bar[] = { 0xe2, 0x95, 0xa0, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0xa3 };
    memset((void *)spacer, ' ', sizeof(spacer));

    pthread_mutex_lock(&s->sensor_lock);

    // Balthasar
    write(fd, spacer, 24);
    write(fd, balthasar, sizeof(balthasar));
    dprintf(fd, "\n");
    for (int i = 0; i < s->maxfds; i += 128) {
        write(fd, spacer, 24);
        write(fd, vertical_line, sizeof(vertical_line));
        render_fdline(fd, i, &s->readfds, s->maxfds);
        write(fd, vertical_line, sizeof(vertical_line));
        dprintf(fd, "\n");
    }
    write(fd, spacer, 24);
    write(fd, bottom, sizeof(bottom));
    dprintf(fd, "\n");
    // Diagonal connectors
    write(fd, spacer, 31);
    write(fd, left_diag, sizeof(left_diag));
    write(fd, spacer, 18);
    write(fd, right_diag, sizeof(right_diag));
    dprintf(fd, "\n");
    write(fd, spacer, 30);
    write(fd, left_diag, sizeof(left_diag));
    write(fd, spacer, 20);
    write(fd, right_diag, sizeof(right_diag));
    dprintf(fd, "\n");

    // Casper and Melchior
    write(fd, spacer, 2);
    write(fd, casper, sizeof(casper));
    write(fd, spacer, 10);
    write(fd, melchior, sizeof(melchior));
    dprintf(fd, "\n");
    for (int i = 0; i < s->maxfds; i += 128) {
        write(fd, spacer, 2);
        write(fd, vertical_line, sizeof(vertical_line));
        render_fdline(fd, i, &s->writefds, s->maxfds);
        if (i == 512) {
            write(fd, bar, sizeof(bar));
        }
        else {
            write(fd, vertical_line, sizeof(vertical_line));
            write(fd, spacer, 10);
            write(fd, vertical_line, sizeof(vertical_line));
        }
        render_fdline(fd, i, &s->exceptfds, s->maxfds);
        write(fd, vertical_line, sizeof(vertical_line));
        dprintf(fd, "\n");
    }
    write(fd, spacer, 2);
    write(fd, bottom, sizeof(bottom));
    write(fd, spacer, 10);
    write(fd, bottom, sizeof(bottom));
    dprintf(fd, "\n");
    pthread_mutex_unlock(&s->sensor_lock);
}