#define _POSIX_C_SOURCE 200809L
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
#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include <stdatomic.h>

#define BUFFER_SIZE 1024
#define CONTROL_PORT 2000
#define CLIENT_PORT_BASE 2001
#define PREFERRED_MAXFILES 1200
#define KEY_SIZE 1024

#define CHALDEBUG

#include "sockfun.h"
#include "rsautil.h"

unsigned long increase_fd_limit(unsigned long maxfiles) {
    // Try to increase open file limit
    // If that fails, raise it as high as we can
    int r;
    rlim_t cur_max;
    struct rlimit rlim;
    r = getrlimit(RLIMIT_NOFILE, &rlim);
    if (r < 0) {
        perror("getrlimit");
        return -1;
    }

    rlim.rlim_cur = maxfiles;
    r = setrlimit(RLIMIT_NOFILE, &rlim);
    if (r < 0) {
        printf("[-] Failed to raise max files to preferred %lu\n", maxfiles);
        rlim.rlim_cur = rlim.rlim_max;
        r = setrlimit(RLIMIT_NOFILE, &rlim);
        if (r < 0) {
            perror("setrlimit");
            return -1;
        }
        else {
            printf("[+] Raised max files to %lu\n", rlim.rlim_cur);
        }
    }
    return rlim.rlim_cur;
}

void dump_key(session_t *s) {
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

int open_server_port(int port) {
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
    address.sin_port = htons(port);

    // Bind the server socket
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        // bind failure means the port is already in use
        return -1;
    }
    if (listen(server_fd, 3) < 0) {
        perror("listen failed");
        exit(EXIT_FAILURE);
    }

    printf("[+] Listening on port %d\n", port);
    return server_fd;
}
typedef struct {
    session_t *sess;
    _Atomic int should_exit;
} client_thread_args;

// Thread to handle client connections
void *client_thread(void *arg) {
    char buffer[BUFFER_SIZE] = {0};
    client_thread_args *args = (client_thread_args *)arg;
    session_t *sess = args->sess;
    int *client_sockets = calloc(sess->maxfds, sizeof(int));

    // Main loop: accept connections, add them to the set, and select
    while(1) {
        FD_ZERO(&sess->readfds);
        FD_SET(sess->server_fd, &sess->readfds);
        sess->nfds = sess->server_fd;

        int i;
        for (i = 0; i < sess->maxfds; i++) {
            int sd = client_sockets[i];
            if (sd > 0) {
                FD_SET(sd, &sess->readfds);
                FD_SET(sd, &sess->exceptfds);
            }
            if (sd > sess->nfds) sess->nfds = sd;
        }
        int new_socket;
        // This will block until something happens
        // select timeout
        struct timeval tv = {
            .tv_sec = 0,
            .tv_usec = 100000, // 100ms
        };
        int activity = select(sess->nfds + 1, &sess->readfds, NULL, &sess->exceptfds, &tv);
        // if we timed out, just go back to the top of the loop after checking if we should exit
        if (activity == 0) {
            goto exit_check;
        }

        // If the activity is on the server socket it means we have a new connection
        // Accept it
        struct sockaddr_in address;
        int addrlen = sizeof(address);
        if (FD_ISSET(sess->server_fd, &sess->readfds)) {
            if ((new_socket = accept(sess->server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
                perror("accept");
                goto monitor;
            }
            printf("[+] New connection from %s:%d assigned to fd=%d\n", inet_ntoa(address.sin_addr), ntohs(address.sin_port), new_socket);

            // Make the socket non-blocking
            int flags = fcntl(new_socket, F_GETFL, 0);
            fcntl(new_socket, F_SETFL, flags | O_NONBLOCK);

            // Find a free slot in the client_sockets array
            for (i = 0; i < sess->maxfds; i++) {
                if (client_sockets[i] == 0) {
                    client_sockets[i] = new_socket;
                    break;
                }
            }
            if (i == sess->maxfds) {
                printf("[-] Max connections reached\n");
                pthread_exit(NULL);
            }
        }
monitor:
        for (int i = 0; i < sess->maxfds; i++) {
            int sd = client_sockets[i];
            if (FD_ISSET(sd, &sess->readfds)) {
                printf("[+] Client fd=%d ready for read\n", sd);
                int valread = read(sd, buffer, BUFFER_SIZE);
                if (valread > 0) {
                    send(sd, buffer, valread, 0);
                }
                else if (valread == 0) {
                    printf("[-] Client fd=%d disconnected\n", sd);
                    close(sd);
                    client_sockets[i] = 0;
                } else {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        // This is fine, just means there's no data to read
                    } else {
                        perror("read");
                        close(sd);
                        client_sockets[i] = 0;
                    }
                }
            }
        }
        // dump_fdset("readfds", &sess.readfds);
        // dump_fdset("exceptfds", &sess.exceptfds);
        // dump_key(sess);
exit_check:
        // Check if we should exit
        if (atomic_load(&args->should_exit)) {
            printf("[-] Client thread exiting\n");
            // Cleanup
            for (int i = 0; i < sess->maxfds; i++) {
                if (client_sockets[i] > 0) {
                    close(client_sockets[i]);
            }
            }
            close(sess->server_fd);
            free(client_sockets);
            pthread_exit(NULL);
        }
    }
}

typedef struct {
    int sock;
    unsigned long maxfiles;
} control_thread_args;

void *control_thread(void *arg) {
    control_thread_args *args = (control_thread_args *)arg;
    int new_socket = args->sock;

    // Session setup
    dprintf(new_socket, "Welcome to the NERV Magi System\n");
    dprintf(new_socket, "Setting up session...\n");
    session_t *sess = calloc(1, sizeof(session_t));
    // Generate a new RSA key
    rsa_setup(sess);
    // Send the public key to the client
    char *pubkey = dump_pubkey_ssh(RSA_EXPONENT, sess->pubkey, sizeof(sess->pubkey), "newuser@nerv");
    dprintf(new_socket, "Your public key is:\n%s\n", pubkey);
    free(pubkey);

    // Set their maxfds
    sess->maxfds = args->maxfiles;

    // Find a free port for the client to connect to
    int client_port = CLIENT_PORT_BASE;
    int client_fd = -1;
    while (-1 == (client_fd = open_server_port(client_port))) {
        // Keep trying until we find a free port
        client_port++;
    }
    sess->server_fd = client_fd;
    dprintf(new_socket, "Your very own port is %d\n", client_port);

    // Spawn a thread to handle the client connections
    pthread_t thread;
    client_thread_args *client_args = calloc(1, sizeof(client_thread_args));
    client_args->sess = sess;
    client_args->should_exit = 0;
    pthread_create(&thread, NULL, client_thread, client_args);

    // Server loop
    while (1) {
        dprintf(new_socket, "Main menu:\n");
        dprintf(new_socket, "1. Authenticate\n");
        dprintf(new_socket, "2. Print public key\n");
        dprintf(new_socket, "3. Exit\n");
        dprintf(new_socket, "Enter your choice: ");
        char buffer[BUFFER_SIZE] = {0};
        int rbytes = read(new_socket, buffer, BUFFER_SIZE);
        if (rbytes <= 0) {
            printf("[-] Client disconnected\n");
            goto server_done;
        }
        switch (buffer[0]) {
            case '1': {
                // dprintf(new_socket, "TODO: Implement authentication\n");
                unsigned char challenge[32];
                generate_challenge(challenge, sizeof(challenge));
                dprintf(new_socket, "Challenge: \n");
                for (int i = 0; i < sizeof(challenge); i++) {
                    dprintf(new_socket, "%02x", challenge[i]);
                }
                dprintf(new_socket, "\n");
                dprintf(new_socket, "Response: ");
                // response is an RSA signature of the challenge
                unsigned char response[KEY_SIZE/8];
                int resp_len = read(new_socket, buffer, BUFFER_SIZE);
                if (resp_len < 2*sizeof(response)) {
                    dprintf(new_socket, "Authentication failed: response len (%d) is too short.\n", resp_len);
                    break;
                }
                // Read the response as a hex string
                for (int i = 0; i < sizeof(response); i++) {
                    char byte[3] = {buffer[2*i], buffer[2*i+1], 0};
                    response[i] = strtol(byte, NULL, 16);
                }
                printf("Received response: ");
                for (int i = 0; i < sizeof(response); i++) {
                    printf("%02x", response[i]);
                }
                printf("\n");
                if (validate_challenge(sess, challenge, sizeof(challenge), response, sizeof(response))) {
                    dprintf(new_socket, "Authentication successful!\n");
                } else {
                    dprintf(new_socket, "Authentication failed.\n");
                }
                break;
            }
            case '2':
                pubkey = dump_pubkey_ssh(RSA_EXPONENT, sess->pubkey, sizeof(sess->pubkey), "newuser@nerv");
                dprintf(new_socket, "Your public key is:\n%s\n", pubkey);
                free(pubkey);
                break;
            case '3':
                dprintf(new_socket, "Goodbye!\n");
                goto server_done;
                break;
            default:
                dprintf(new_socket, "Invalid choice\n");
                break;
        }
    }
server_done:
    close(new_socket);
    atomic_store(&client_args->should_exit, 1);
    pthread_join(thread, NULL);
    free(sess);
    free(client_args);
    printf("[-] Control thread exiting\n");
    // Terminate this thread
    pthread_exit(NULL);
    return NULL;
}

int main() {
    // Set max files
    unsigned long maxfiles = increase_fd_limit(PREFERRED_MAXFILES);
    printf("[+] Max files is %lu\n", maxfiles);

    // Ignore SIGPIPE so we don't crash when a client disconnects
    signal(SIGPIPE, SIG_IGN);

    int control_fd;
    printf("[+] Setting up control port\n");
    control_fd = open_server_port(CONTROL_PORT);
    // Accept connections in a loop. For each connection, generate a new RSA key
    // and send the public key to the client, find a free port for the client to
    // connect to, and spawn a thread to handle the client connections.
    while (1) {
        struct sockaddr_in address;
        int addrlen = sizeof(address);
        int new_socket;
        if ((new_socket = accept(control_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
            perror("accept");
            exit(EXIT_FAILURE);
        }
        printf("[+] New control connection from %s:%d assigned to fd=%d\n", inet_ntoa(address.sin_addr), ntohs(address.sin_port), new_socket);

        // Start the control thread
        pthread_t thread;
        control_thread_args *args = calloc(1, sizeof(control_thread_args));
        args->sock = new_socket;
        args->maxfiles = maxfiles;
        pthread_create(&thread, NULL, control_thread, (void *)args);
    }

    return 0;
}
