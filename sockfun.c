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
#include <sys/sendfile.h>

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
    for (int i = 0; i < 16; i++) {
        printf("%02x", s->pubkey[i]);
    }
    printf(" [...]\n");
}

void dump_fdset(const char *name, fd_set *fds) {
    printf("fd_set[%9s] = [", name);
    for (int i = 0; i < sizeof(fds->__fds_bits) / sizeof(fds->__fds_bits[0]); i++) {
        printf("%lu, ", fds->__fds_bits[i]);
    }
    printf("]\n");
}

void sendimg(int fd, const char *path) {
    char fullpath[256] = {0};
    snprintf(fullpath, sizeof(fullpath), "img/%s", path);
    int img = open(path, O_RDONLY);
    if (img < 0) {
        perror("open");
        return;
    }
    int nb = 0;
    do {
        nb = sendfile(fd, img, NULL, 0x1000);
        if (nb < 0) {
            perror("sendfile");
            break;
        }
    } while (nb > 0);
    close(img);
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

    printf("[+] Listening on port %d, fd=%d\n", port, server_fd);
    return server_fd;
}
typedef struct {
    session_t *sess;
    _Atomic int should_exit;
    // Pause condition signaling
    int should_pause;
    pthread_cond_t pause_cond;
    pthread_mutex_t pause_mutex;
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

        // Does the control thread want us to pause?
        int did_pause = 0;
        pthread_mutex_lock(&args->pause_mutex);
        while (args->should_pause) {
            printf("[-] Client thread pausing\n");
            did_pause = 1;
            pthread_cond_wait(&args->pause_cond, &args->pause_mutex);
        }
        pthread_mutex_unlock(&args->pause_mutex);
        if (did_pause) printf("[+] Client thread resuming\n");

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
                // printf("[+] Client fd=%d ready for read\n", sd);
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

int handle_auth(session_t *sess) {
    char buffer[BUFFER_SIZE+1] = {0};
    int new_socket = sess->control_fd;

    unsigned char challenge[32];
    generate_challenge(challenge, sizeof(challenge));
    dprintf(new_socket, "Challenge: ");
    for (int i = 0; i < sizeof(challenge); i++) {
        dprintf(new_socket, "%02x", challenge[i]);
    }
    dprintf(new_socket, "\n");
    dprintf(new_socket, "Response: ");
    // response is an RSA signature of the challenge
    unsigned char response[KEY_SIZE/8];
    int resp_len = read(new_socket, buffer, BUFFER_SIZE);
    buffer[resp_len] = 0;
    // Read the response as a hex string
    int i;
    for (i = 0; i < sizeof(response) && i < resp_len; i++) {
        if (buffer[2*i] == '\n' || buffer[2*i+1] == '\n') {
            break;
        }
        char byte[3] = {buffer[2*i], buffer[2*i+1], 0};
        response[i] = strtol(byte, NULL, 16);
    }
    int resp_len_bytes = i;
    printf("Received response (%d bytes): ", resp_len_bytes);
    for (int i = 0; i < resp_len_bytes; i++) {
        printf("%02x", response[i]);
    }
    printf("\n");
    if (validate_challenge(sess, challenge, sizeof(challenge), response, resp_len_bytes)) {
        dprintf(new_socket, "Authentication successful!\n");
        return 1;
    } else {
        dprintf(new_socket, "Authentication failed.\n");
        sendimg(new_socket, "asuka_pathetic.txt");
        return 0;
    }
}

void *control_thread(void *arg) {
    control_thread_args *args = (control_thread_args *)arg;
    int new_socket = args->sock;

    // Session setup
    sendimg(new_socket, "nerv_wide.txt");
    dprintf(new_socket, "Welcome to the NERV Magi System\n");
    dprintf(new_socket, "Setting up session...\n");
    session_t *sess = calloc(1, sizeof(session_t));
    sess->control_fd = new_socket;
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
    client_args->should_pause = 0;
    pthread_cond_init(&client_args->pause_cond, NULL);
    pthread_mutex_init(&client_args->pause_mutex, NULL);
    pthread_create(&thread, NULL, client_thread, client_args);

    // Server loop
    while (1) {
        dprintf(new_socket, "Main menu:\n");
        dprintf(new_socket, "1. Authenticate\n");
        dprintf(new_socket, "2. Print public key\n");
        dprintf(new_socket, "3. Pause client thread\n");
        dprintf(new_socket, "4. Resume client thread\n");
        dprintf(new_socket, "5. Exit\n");
        dprintf(new_socket, "Enter your choice: ");
        char buffer[BUFFER_SIZE+1] = {0};
        int rbytes = read(new_socket, buffer, BUFFER_SIZE);
        if (rbytes <= 0) {
            printf("[-] Client disconnected\n");
            goto server_done;
        }
        buffer[rbytes] = 0;
        // Parse the choice
        char *endptr;
        unsigned long choice = strtoul(buffer, &endptr, 10);
        if (endptr == buffer) {
            dprintf(new_socket, "Invalid choice\n");
            continue;
        }
        switch (choice) {
            case 1: {
                sess->authenticated = handle_auth(sess);
                break;
            }
            case 2:
                pubkey = dump_pubkey_ssh(RSA_EXPONENT, sess->pubkey, sizeof(sess->pubkey), "newuser@nerv");
                dprintf(new_socket, "Your public key is:\n%s\n", pubkey);
                free(pubkey);
                break;
            case 3:
                pthread_mutex_lock(&client_args->pause_mutex);
                client_args->should_pause = 1;
                pthread_mutex_unlock(&client_args->pause_mutex);
                dprintf(new_socket, "Client thread paused\n");
                break;
            case 4:
                pthread_mutex_lock(&client_args->pause_mutex);
                client_args->should_pause = 0;
                pthread_cond_signal(&client_args->pause_cond);
                pthread_mutex_unlock(&client_args->pause_mutex);
                dprintf(new_socket, "Client thread resumed\n");
                break;
            case 5:
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
    // Unpause the client thread if it's paused
    pthread_mutex_lock(&client_args->pause_mutex);
    client_args->should_pause = 0;
    pthread_cond_signal(&client_args->pause_cond);
    pthread_mutex_unlock(&client_args->pause_mutex);
    // Tell the client thread to exit
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
