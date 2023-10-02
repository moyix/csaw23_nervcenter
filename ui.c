#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <stdint.h>
#include <sys/random.h>
#include <sys/time.h>
#include <stdbool.h>

#include "ui.h"
#include "magi_ui.h"
#include "xterm_colors.h"

// void render_fdline(int fd, int i, fd_set *s, int maxfds) {
//     // unicode block elements to represent 0..15:
//     // ' ', '▘', '▝', '▀', '▖', '▌', '▞', '▛', '▗', '▚', '▐', '▜', '▄', '▙', '▟', '█'
//     const unsigned char blocks[16][3] = {
//         { 0x00, 0x00, 0x00 },
//         { 0xe2, 0x96, 0x98 },
//         { 0xe2, 0x96, 0x9d },
//         { 0xe2, 0x96, 0x80 },
//         { 0xe2, 0x96, 0x96 },
//         { 0xe2, 0x96, 0x8c },
//         { 0xe2, 0x96, 0x9e },
//         { 0xe2, 0x96, 0x9b },
//         { 0xe2, 0x96, 0x97 },
//         { 0xe2, 0x96, 0x9a },
//         { 0xe2, 0x96, 0x90 },
//         { 0xe2, 0x96, 0x9c },
//         { 0xe2, 0x96, 0x84 },
//         { 0xe2, 0x96, 0x99 },
//         { 0xe2, 0x96, 0x9f },
//         { 0xe2, 0x96, 0x88 },
//     };

//     // set color to red
//     dprintf(fd, "\033[31m");
//     for (int j = 0; j < 128; j += 4) {
//         int box_idx = 0;
//         for (int k = 0; k < 4; k++) {
//             if (i + j + k >= maxfds) break;
//             if (FD_ISSET(i + j + k, s)) {
//                 box_idx |= 1 << k;
//             }
//         }
//         if (box_idx == 0) {
//             dprintf(fd, " ");
//         }
//         else {
//             write(fd, blocks[box_idx], 3);
//         }
//     }
//     // reset color
//     dprintf(fd, "\033[0m");
// }

// // Draw the three fd_sets using the unicode block elements
// void render_fdset(int fd, session_t *s) {
//     const unsigned char spacer[32];
//     const unsigned char vertical_line[] = { 0xe2, 0x95, 0x91 };
//     const unsigned char left_diag[] = { 0xe2, 0x95, 0xb1 };
//     const unsigned char right_diag[] = { 0xe2, 0x95, 0xb2 };
//     const unsigned char casper[] = { 0xe2, 0x95, 0x94, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0x20, 0x43, 0x41, 0x53, 0x50, 0x45, 0x52, 0x2d, 0x33, 0x20, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x97 };
//     const unsigned char balthasar[] = { 0xe2, 0x95, 0x94, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0x20, 0x42, 0x41, 0x4c, 0x54, 0x48, 0x41, 0x53, 0x41, 0x52, 0x2d, 0x32, 0x20, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x97 };
//     const unsigned char melchior[] = { 0xe2, 0x95, 0x94, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0x20, 0x4d, 0x45, 0x4c, 0x43, 0x48, 0x49, 0x4f, 0x52, 0x2d, 0x31, 0x20, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x97 };
//     const unsigned char bottom[] = { 0xe2, 0x95, 0x9a, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x9d };
//     const unsigned char bar[] = { 0xe2, 0x95, 0xa0, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0x90, 0xe2, 0x95, 0xa3 };
//     memset((void *)spacer, ' ', sizeof(spacer));

//     pthread_mutex_lock(&s->sensor_lock);

//     // Balthasar
//     write(fd, spacer, 24);
//     write(fd, balthasar, sizeof(balthasar));
//     dprintf(fd, "\n");
//     for (int i = 0; i < s->maxfds; i += 128) {
//         write(fd, spacer, 24);
//         write(fd, vertical_line, sizeof(vertical_line));
//         render_fdline(fd, i, &s->readfds, s->maxfds);
//         write(fd, vertical_line, sizeof(vertical_line));
//         dprintf(fd, "\n");
//     }
//     write(fd, spacer, 24);
//     write(fd, bottom, sizeof(bottom));
//     dprintf(fd, "\n");
//     // Diagonal connectors
//     write(fd, spacer, 31);
//     write(fd, left_diag, sizeof(left_diag));
//     write(fd, spacer, 18);
//     write(fd, right_diag, sizeof(right_diag));
//     dprintf(fd, "\n");
//     write(fd, spacer, 30);
//     write(fd, left_diag, sizeof(left_diag));
//     write(fd, spacer, 20);
//     write(fd, right_diag, sizeof(right_diag));
//     dprintf(fd, "\n");

//     // Casper and Melchior
//     write(fd, spacer, 2);
//     write(fd, casper, sizeof(casper));
//     write(fd, spacer, 10);
//     write(fd, melchior, sizeof(melchior));
//     dprintf(fd, "\n");
//     for (int i = 0; i < s->maxfds; i += 128) {
//         write(fd, spacer, 2);
//         write(fd, vertical_line, sizeof(vertical_line));
//         render_fdline(fd, i, &s->writefds, s->maxfds);
//         if (i == 512) {
//             write(fd, bar, sizeof(bar));
//         }
//         else {
//             write(fd, vertical_line, sizeof(vertical_line));
//             write(fd, spacer, 10);
//             write(fd, vertical_line, sizeof(vertical_line));
//         }
//         render_fdline(fd, i, &s->exceptfds, s->maxfds);
//         write(fd, vertical_line, sizeof(vertical_line));
//         dprintf(fd, "\n");
//     }
//     write(fd, spacer, 2);
//     write(fd, bottom, sizeof(bottom));
//     write(fd, spacer, 10);
//     write(fd, bottom, sizeof(bottom));
//     dprintf(fd, "\n");
//     pthread_mutex_unlock(&s->sensor_lock);
// }

void render_cell_style(int fd, ui_cell_t *cell) {
    int n = 0;
    if (cell->flags & UI_SKIP) return;
    if (cell->flags & UI_STYLE_RESET) {
        n = dprintf(fd, ANSI_RESET);
#ifdef CHALDEBUG
        if (n > 0) magi_ui.bytes_written += n;
#endif
    }
    if (cell->flags & UI_STYLE_BOLD) {
        n = dprintf(fd, ANSI_BOLD);
#ifdef CHALDEBUG
        if (n > 0) magi_ui.bytes_written += n;
#endif
    }
    if (cell->flags & UI_STYLE_DIM) {
        n = dprintf(fd, ANSI_DIM);
#ifdef CHALDEBUG
        if (n > 0) magi_ui.bytes_written += n;
#endif
    }
    if (cell->flags & UI_STYLE_ITALIC) {
        n = dprintf(fd, ANSI_ITALIC);
#ifdef CHALDEBUG
        if (n > 0) magi_ui.bytes_written += n;
#endif
    }
    if (cell->flags & UI_STYLE_UNDERLINE) {
        n = dprintf(fd, ANSI_UNDERLINED);
#ifdef CHALDEBUG
        if (n > 0) magi_ui.bytes_written += n;
#endif
    }
    if (cell->flags & UI_STYLE_BLINK) {
        n = dprintf(fd, ANSI_BLINK);
#ifdef CHALDEBUG
        if (n > 0) magi_ui.bytes_written += n;
#endif
    }
    if (cell->flags & UI_STYLE_REVERSE) {
        n = dprintf(fd, ANSI_REVERSE);
#ifdef CHALDEBUG
        if (n > 0) magi_ui.bytes_written += n;
#endif
    }
    if (cell->flags & UI_STYLE_HIDDEN) {
        n = dprintf(fd, ANSI_HIDDEN);
#ifdef CHALDEBUG
        if (n > 0) magi_ui.bytes_written += n;
#endif
    }
    if (cell->flags & UI_STYLE_STRIKETHROUGH) {
        n = dprintf(fd, ANSI_STRIKETHROUGH);
#ifdef CHALDEBUG
        if (n > 0) magi_ui.bytes_written += n;
#endif
    }
    if (cell->flags & UI_STYLE_NONE) {
        n = dprintf(fd, ANSI_RESET);
#ifdef CHALDEBUG
        if (n > 0) magi_ui.bytes_written += n;
#endif
    }
    if (cell->fg >= 0) {
        n = dprintf(fd, ANSI_FGCOLOR_FMT, cell->fg);
#ifdef CHALDEBUG
        if (n > 0) magi_ui.bytes_written += n;
#endif
    }
    if (cell->bg >= 0) {
        n = dprintf(fd, ANSI_BGCOLOR_FMT, cell->bg);
#ifdef CHALDEBUG
        if (n > 0) magi_ui.bytes_written += n;
#endif
    }
}

void render_cell(int fd, ui_cell_t *cell) {
    int n = 0;
    if (cell->flags & UI_SKIP) return;
    render_cell_style(fd, cell);
    n = write(fd, cell->bytes, cell->len);
#ifdef CHALDEBUG
    if (n > 0) magi_ui.bytes_written += n;
#endif
}

void render_surface_naive(int fd, ui_surface_t *surface) {
#ifdef CHALDEBUG
    struct timeval start, end;
    gettimeofday(&start, NULL);
    surface->bytes_written = 0;
#endif
    for (int i = 0; i < surface->width * surface->height; i++) {
        render_cell(fd, &surface->cells[i]);
        int n = dprintf(fd, ANSI_RESET);
#ifdef CHALDEBUG
        if (n > 0) magi_ui.bytes_written += n;
#endif
    }
#ifdef CHALDEBUG
    gettimeofday(&end, NULL);
    surface->last_render = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec);
#endif
}

bool style_eq(ui_cell_t *a, ui_cell_t *b) {
    // if both a and b are NULL return true
    if (!a && !b) return true;
    // if only one is NULL return false
    if (!a || !b) return false;
    return a->flags == b->flags && a->fg == b->fg && a->bg == b->bg;
}

// optimized version of render_surface that tracks whether the
// previous cell's style is the same as the current cell's style
// and only sends the ANSI escape codes when they change
void render_surface_opt(int fd, ui_surface_t *surface) {
#ifdef CHALDEBUG
    struct timeval start, end;
    gettimeofday(&start, NULL);
    surface->bytes_written = 0;
#endif
    int n = 0;
    ui_cell_t *cell = NULL;
    ui_cell_t *prev = NULL;
    for (int i = 0; i < surface->width * surface->height; i++) {
        cell = &surface->cells[i];
        if (cell->flags & UI_SKIP) continue;
        if (!style_eq(cell, prev)) {
            render_cell_style(fd, cell);
        }
        n = write(fd, cell->bytes, cell->len);
#ifdef CHALDEBUG
        if (n > 0) magi_ui.bytes_written += n;
#endif
        prev = cell;
    }
    if (prev) {
        n = dprintf(fd, ANSI_RESET);
    }
#ifdef CHALDEBUG
    if (n > 0) magi_ui.bytes_written += n;
    gettimeofday(&end, NULL);
    surface->last_render = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec);
#endif
}

void update_cell(ui_cell_t *cell, ui_cell_t *other) {
    memcpy(cell->bytes, other->bytes, sizeof(cell->bytes));
    cell->len = other->len;
    cell->fg = other->fg == -1 ? cell->fg : other->fg;
    cell->bg = other->bg == -1 ? cell->bg : other->bg;
    if (other->flags & UI_STYLE_NONE)
        cell->flags |= other->flags;
    else
        cell->flags = other->flags;
}

void render_fdline_cells(ui_surface_t *surface, int row, int col, int i, fd_set *s, int nfds) {
    // unicode block elements to represent 0..15:
    // ' ', '▘', '▝', '▀', '▖', '▌', '▞', '▛', '▗', '▚', '▐', '▜', '▄', '▙', '▟', '█'
    ui_cell_t blocks[16] = {
        { .bytes = { 0x20, 0x00, 0x00 }, .len = 1, .fg = XTERM_COLOR_RED, .bg = -1, .flags = UI_STYLE_NONE },
        { .bytes = { 0xe2, 0x96, 0x98 }, .len = 3, .fg = XTERM_COLOR_RED, .bg = -1, .flags = UI_STYLE_NONE },
        { .bytes = { 0xe2, 0x96, 0x9d }, .len = 3, .fg = XTERM_COLOR_RED, .bg = -1, .flags = UI_STYLE_NONE },
        { .bytes = { 0xe2, 0x96, 0x80 }, .len = 3, .fg = XTERM_COLOR_RED, .bg = -1, .flags = UI_STYLE_NONE },
        { .bytes = { 0xe2, 0x96, 0x96 }, .len = 3, .fg = XTERM_COLOR_RED, .bg = -1, .flags = UI_STYLE_NONE },
        { .bytes = { 0xe2, 0x96, 0x8c }, .len = 3, .fg = XTERM_COLOR_RED, .bg = -1, .flags = UI_STYLE_NONE },
        { .bytes = { 0xe2, 0x96, 0x9e }, .len = 3, .fg = XTERM_COLOR_RED, .bg = -1, .flags = UI_STYLE_NONE },
        { .bytes = { 0xe2, 0x96, 0x9b }, .len = 3, .fg = XTERM_COLOR_RED, .bg = -1, .flags = UI_STYLE_NONE },
        { .bytes = { 0xe2, 0x96, 0x97 }, .len = 3, .fg = XTERM_COLOR_RED, .bg = -1, .flags = UI_STYLE_NONE },
        { .bytes = { 0xe2, 0x96, 0x9a }, .len = 3, .fg = XTERM_COLOR_RED, .bg = -1, .flags = UI_STYLE_NONE },
        { .bytes = { 0xe2, 0x96, 0x90 }, .len = 3, .fg = XTERM_COLOR_RED, .bg = -1, .flags = UI_STYLE_NONE },
        { .bytes = { 0xe2, 0x96, 0x9c }, .len = 3, .fg = XTERM_COLOR_RED, .bg = -1, .flags = UI_STYLE_NONE },
        { .bytes = { 0xe2, 0x96, 0x84 }, .len = 3, .fg = XTERM_COLOR_RED, .bg = -1, .flags = UI_STYLE_NONE },
        { .bytes = { 0xe2, 0x96, 0x99 }, .len = 3, .fg = XTERM_COLOR_RED, .bg = -1, .flags = UI_STYLE_NONE },
        { .bytes = { 0xe2, 0x96, 0x9f }, .len = 3, .fg = XTERM_COLOR_RED, .bg = -1, .flags = UI_STYLE_NONE },
        { .bytes = { 0xe2, 0x96, 0x88 }, .len = 3, .fg = XTERM_COLOR_RED, .bg = -1, .flags = UI_STYLE_NONE },
    };

    int col_offset = 0;
    for (int j = 0; j < 128; j += 4) {
        int box_idx = 0;
        for (int k = 0; k < 4; k++) {
            if (i + j + k >= nfds) break;
            if (FD_ISSET(i + j + k, s)) {
                box_idx |= 1 << k;
            }
        }
        if (box_idx == 0 && i + j > FD_SETSIZE) {
            // skip update
        }
        else {
            update_cell(CELL_AT(surface, row, col+col_offset), &blocks[box_idx]);
        }
        col_offset++;
    }
}

int printf_cells(ui_surface_t *surface, int row, int col,
                 ui_cell_flags_t style, int16_t fg, int16_t bg,
                 char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    // get some scratch space
    char scratch[1024];
    size_t maxlen = surface->width - col;
    if (maxlen > sizeof(scratch)) maxlen = sizeof(scratch);
    int n = vsnprintf(scratch, maxlen, fmt, args);
    va_end(args);
    if (n < 0) return n;
    if (n > maxlen) n = maxlen;
    for (int i = 0; i < n; i++) {
        ui_cell_t *cell = CELL_AT(surface, row, col+i);
        cell->bytes[0] = scratch[i];
        cell->len = 1;
        cell->flags = style;
        cell->fg = fg;
        cell->bg = bg;
    }
    return n;
}

void render_fdset_cells(ui_surface_t *surface, int row, int col, fd_set *s, int nfds) {
    int row_offset = 0;
    for (int i = 0; i < nfds; i += 128) {
        render_fdline_cells(surface, row + row_offset, col, i, s, nfds);
        row_offset++;
    }
}

void blit_surface(ui_surface_t *dst, ui_surface_t *src, int dst_row, int dst_col) {
    for (int i = 0; i < src->height; i++) {
        for (int j = 0; j < src->width; j++) {
            update_cell(CELL_AT(dst, dst_row+i, dst_col+j), CELL_AT(src, i, j));
        }
    }
}

ui_surface_t *create_surface(int width, int height) {
    ui_surface_t *surface = malloc(sizeof(ui_surface_t));
    surface->cells = malloc(sizeof(ui_cell_t) * width * height);
    surface->width = width;
    surface->height = height;
    return surface;
}

ui_surface_t *create_surface_from_cell(int width, int height, ui_cell_t *cell) {
    ui_surface_t *surface = create_surface(width, height);
    // use memcpy to copy the cell to every cell in the surface
    for (int i = 0; i < width * height; i++) {
        memcpy(&surface->cells[i], cell, sizeof(ui_cell_t));
    }
    return surface;
}

void free_surface(ui_surface_t *surface) {
    free(surface->cells);
    free(surface);
}

void debug_dumpflags(uint32_t flags) {
    if (flags == UI_SKIP) { printf("UI_SKIP\n"); return; }
    if (flags & UI_STYLE_RESET) printf("UI_STYLE_RESET ");
    if (flags & UI_STYLE_BOLD) printf("UI_STYLE_BOLD ");
    if (flags & UI_STYLE_DIM) printf("UI_STYLE_DIM ");
    if (flags & UI_STYLE_ITALIC) printf("UI_STYLE_ITALIC ");
    if (flags & UI_STYLE_UNDERLINE) printf("UI_STYLE_UNDERLINE ");
    if (flags & UI_STYLE_BLINK) printf("UI_STYLE_BLINK ");
    if (flags & UI_STYLE_REVERSE) printf("UI_STYLE_REVERSE ");
    if (flags & UI_STYLE_HIDDEN) printf("UI_STYLE_HIDDEN ");
    if (flags & UI_STYLE_STRIKETHROUGH) printf("UI_STYLE_STRIKETHROUGH ");
    if (flags & UI_STYLE_NONE) printf("UI_STYLE_NONE ");
    if (flags & UI_WIDE) printf("UI_WIDE ");
    printf("\n");
}

void debug_dumpcell(ui_surface_t *surface, int row, int col) {
    ui_cell_t *cell = CELL_AT(surface, row, col);
    printf("cell at (%d, %d):\n", row, col);
    printf("  bytes = {");
    for (int i = 0; i < cell->len; i++) {
        unsigned char c = cell->bytes[i];
        printf(" %02x", c);
        if (c >= 0x20 && c <= 0x7e) {
            printf(" '%c'", c);
        }
        printf(",");
    }
    printf(" }\n");
    printf("  bytes(str) = '%.*s'\n", cell->len, cell->bytes);
    int16_t fg = cell->fg;
    int16_t bg = cell->bg;
    render_cell_style(1, cell);
    printf("  fg = %s, bg = %s\n",
        fg == -1 ? "default" : xterm_color_names[fg],
        bg == -1 ? "default" : xterm_color_names[bg]);
    dprintf(1, ANSI_RESET);
    printf("  flags = ");
    debug_dumpflags(cell->flags);
}

void render_fdsets_cells(ui_surface_t *surface, session_t *s) {
    pthread_mutex_lock(&s->sensor_lock);

    // Blank the three display surfaces
    ui_surface_t *blank = create_surface_from_cell(32, 8, CELL_AT(surface, 3, 25));
    blit_surface(surface, blank, 3, 25);
    blit_surface(surface, blank, 14, 3);
    blit_surface(surface, blank, 14, 47);
    free_surface(blank);

    // Balthasar is at (3, 25)
    render_fdset_cells(surface, 3, 25, &s->readfds, s->nfds+1);
    // Casper is at (14, 3)
    render_fdset_cells(surface, 14, 3, &s->writefds, s->nfds+1);
    // Melchior is at (14, 47)
    render_fdset_cells(surface, 14, 47, &s->exceptfds, s->nfds+1);
    // Number of fds is at (5, 14)
    printf_cells(surface, 5, 14, UI_STYLE_BOLD, XTERM_COLOR_DARKORANGE3_1, -1, "%-4d", s->nfds+1);
    // Max fds is at (7, 19)
    printf_cells(surface, 7, 19, UI_STYLE_NONE, XTERM_COLOR_DARKORANGE3_1, -1, "%-4d", s->maxfds);

    // Add the infobox at (10, 70). Two special effects:
    // 1. If the number of fds is > 1024, use the red box instead of the yellow box
    // 2. With some probability, don't render the box at all to give a flickering effect
    ui_surface_t *box;
    if (s->nfds+1 > 1024) {
        box = &magi_ui_red_box;
    }
    else {
         box = &magi_ui_yellow_box;
    }
    // 1 in 8 chance of not rendering the box
    unsigned char r = 0;
    getrandom(&r, 1, 0);
    if (r > 0x10) {
        blit_surface(surface, box, 10, 70);
    }
    else {
        ui_cell_t black_cell = { .bytes = { 0x20, 0x00, 0x00 }, .len = 1, .fg = -1, .bg = -1, .flags = UI_STYLE_NONE };
        ui_surface_t *black_box = create_surface_from_cell(box->width, box->height, &black_cell);
        blit_surface(surface, black_box, 10, 70);
        free_surface(black_box);
    }

    pthread_mutex_unlock(&s->sensor_lock);
}
