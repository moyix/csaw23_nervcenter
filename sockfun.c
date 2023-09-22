#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/time.h>
#include <unistd.h>
#include <sys/resource.h>
#include <stddef.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define BUFFER_SIZE 1024
#define PRIMARY_PORT 2000
#define CONTROL_PORT 2001
#define PREFERRED_MAXFILES 1200
#define KEY_SIZE 1024

#define CHALDEBUG

#include "sockfun.h"
#include "rsautil.h"

unsigned long setup(void) {
    // Try to increase open file limit to PREFERRED_MAXFILES
    // If that fails, return the current limit
    int r;
    rlim_t cur_max;
    struct rlimit rlim;
    r = getrlimit(RLIMIT_NOFILE, &rlim);
    if (r < 0) {
        perror("getrlimit");
        return -1;
    }
    cur_max = rlim.rlim_cur;

    rlim.rlim_cur = PREFERRED_MAXFILES;
    r = setrlimit(RLIMIT_NOFILE, &rlim);
    if (r < 0) {
        perror("setrlimit");
        return cur_max;
    }
    return rlim.rlim_cur;
}

void dump(session_t *s) {
    // hexdump the buffer
    printf("s->pubkey = ");
    for (int i = 0; i < sizeof(s->pubkey); i++) {
        printf("%02x", s->pubkey[i]);
    }
    printf("\n");
}

void dump_fdset(const char *name, fd_set *fds) {
    printf("fd_set[%9s] = [", name);
    for (int i = 0; i < sizeof(fds->__fds_bits) / sizeof(fds->__fds_bits[0]); i++) {
        printf("%lu, ", fds->__fds_bits[i]);
    }
    printf("]\n");
}

int main() {
    // RSA key setup
    session_t sess = {};
    rsa_setup(&sess);

    // echo buffer
    char buffer[BUFFER_SIZE] = {0};

    unsigned long maxfiles = setup();
    printf("[+] Max files is %lu\n", maxfiles);
    int *client_sockets = calloc(maxfiles, sizeof(int));

    int server_fd;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Allow the socket to be reused
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    // Set up the server details
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PRIMARY_PORT);

    // Bind the server socket
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    if (listen(server_fd, 3) < 0) {
        perror("listen failed");
        exit(EXIT_FAILURE);
    }

    printf("[+] Listening on port %d\n", PRIMARY_PORT);

    // Main loop: accept connections, add them to the set, and select
    while(1) {
        FD_ZERO(&sess.readfds);
        FD_SET(server_fd, &sess.readfds);
        sess.nfds = server_fd;

        int i;
        for (i = 0; i < maxfiles; i++) {
            int sd = client_sockets[i];
            if (sd > 0) {
                FD_SET(sd, &sess.readfds);
                FD_SET(sd, &sess.exceptfds);
            }
            if (sd > sess.nfds) sess.nfds = sd;
        }
        int new_socket;
        // This will block until something happens
        int activity = select(sess.nfds + 1, &sess.readfds, NULL, &sess.exceptfds, NULL);
        // If the activity is on the server socket it means we have a new connection
        // Accept it
        if (FD_ISSET(server_fd, &sess.readfds)) {
            if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
                perror("accept");
                goto monitor;
            }
            printf("[+] New connection from %s:%d assigned to fd=%d\n", inet_ntoa(address.sin_addr), ntohs(address.sin_port), new_socket);
            // Find a free slot in the client_sockets array
            for (i = 0; i < maxfiles; i++) {
                if (client_sockets[i] == 0) {
                    client_sockets[i] = new_socket;
                    break;
                }
            }
            if (i == maxfiles) {
                printf("[-] Max connections reached\n");
                exit(EXIT_FAILURE);
            }
        }
monitor:
        for (int i = 0; i < maxfiles; i++) {
            int sd = client_sockets[i];
            if (FD_ISSET(sd, &sess.readfds)) {
                printf("[+] Client fd=%d ready for read\n", sd);
                int valread = read(sd, buffer, BUFFER_SIZE);
                if (valread == 0) {
                    printf("[-] Client fd=%d disconnected\n", sd);
                    close(sd);
                    client_sockets[i] = 0;
                } else {
                    send(sd, buffer, valread, 0);
                }
            }
        }
        // dump_fdset("readfds", &sess.readfds);
        // dump_fdset("exceptfds", &sess.exceptfds);
        dump(&sess);
    }


    // memset(thing.buf, 0, sizeof(thing.buf));
    // printf("libc puts is %p\n", puts);
    // printf("libc system is %p\n", system);
    // // printf("thing.exceptfds is at offset %lu\n", offsetof(thing_t, exceptfds));
    // printf("thing.buf is at offset %lu\n", offsetof(thing_t, buf));
    // printf("thing.print is at offset %lu\n", offsetof(thing_t, print));

    // // Initialize the set of FDs
    // FD_ZERO(&thing.readfds);
    // // FD_ZERO(&thing.writefds);
    // // FD_ZERO(&thing.exceptfds);



    // printf("Before select:\n");
    // dump(&thing);
    // int n = select(2000+1, &thing.readfds, NULL, NULL, NULL);
    // printf("Select returned %d\n", n);
    // if (n < 0)
    //     perror("select");
    // printf("After select:\n");
    // dump(&thing);

    return 0;
}
