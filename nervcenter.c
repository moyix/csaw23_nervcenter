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
#include <execinfo.h>
#include <dirent.h>
#include <poll.h>
#include <sys/stat.h>

#define BUFFER_SIZE 1024
#define CONTROL_PORT 2000
#define SENSOR_PORT_BASE 2001
#define PREFERRED_MAXFILES 1200
#define KEY_SIZE 1024

#include "nervcenter.h"
#include "rsautil.h"
#include "base64.h"
#include "parsers.h"
#include "resources.h"
#include "image.h"
#include "ui.h"

// Lock for getting the sensor port
pthread_mutex_t sensor_port_lock = PTHREAD_MUTEX_INITIALIZER;

const char *angel_list[] = {
    "Adam", "Arael", "Armisael", "Bardiel", "Gaghiel", "Ireul",
    "Israfel", "Leliel", "Lilith", "Matarael", "Ramiel", "Sachiel",
    "Sahaquiel", "Sandalphon", "Shamshel", "Tabris", "Zeruel",
};
int angel_list_len = 17;

// Signal handler for SIGUSR1, which just calls exit() so we can get leak info
void sigusr1_handler(int signum) {
    exit(0);
}

unsigned long increase_fd_limit(unsigned long maxfiles) {
    // Try to increase open file limit
    // If that fails, raise it as high as we can
    int r;
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

// Small delay when sending images to let them scroll by
#define IMG_DELAY 15000
int sendimg(int fd, const char *path, int delay) {
    unsigned char *imgbuf;
    size_t imglen;
    if (get_image(path, &imgbuf, &imglen) == -1) {
        printf("[!] Failed to load image: %s\n", path);
        return -1;
    }
    // Read the buffer line by line and send it
    unsigned char *ptr = imgbuf;
    unsigned char *end = ptr + imglen;
    while (ptr < end) {
        size_t len = 0;
        // get the length of the line
        while (ptr < end && ptr[len] != '\n') len++;
        if (ptr < end) len++; // include the newline
        write(fd, ptr, len);
        // advance the pointer past the line
        ptr += len;
#ifndef CHALDEBUG
        usleep(delay);
#endif
    }
    return 0;
}

int sendvid(int fd, const char *fullpath, float fps) {
    // frames start at 1
    int n_frames = 1;
    // Send clear screen and hide cursor commands
    dprintf(fd, "\033[H\033[2J\033[3J"); // clear screen
    dprintf(fd, "\033[?25l");            // hide cursor
    // Send the frames
    float frametime = 1.0 / fps;
    suseconds_t usec = frametime * 1000000;
    while (1) {
        // Time the call to sendimg to calculate correct delay
        struct timeval start, end;
        gettimeofday(&start, NULL);
        char path[256] = {0};
        snprintf(path, sizeof(path), "%s/frame_%08d.txt", fullpath, n_frames);
        if (sendimg(fd, path, 0) == -1) {
            break;
        }
        gettimeofday(&end, NULL);
        suseconds_t elapsed = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec);
        if (elapsed < usec) {
            usleep(usec - elapsed);
        }
        n_frames++;
    }
    // Send show cursor command
    dprintf(fd, "\033[?25h");     // show cursor
    // Reset the terminal
    dprintf(fd, "\033c");
    dprintf(fd, "\033[H\033[2J\033[3J");
    return n_frames;
}

int read_block(int s, char *buffer, size_t size, int timeout) {
    // Poll any pending input with a short timeout
    struct pollfd pfd = { .fd = s, .events = POLLIN, };
    poll(&pfd, 1, timeout);
    if (pfd.revents & POLLIN) {
        return read(s, buffer, BUFFER_SIZE);
    }
    else {
        return 0;
    }
}

#include "credits.h"
#define CREDITS_KEY 0xe7

void easter_egg(int s) {
    char buffer[BUFFER_SIZE+1] = {0};
    dprintf(s, "\033[H\033[2J\033[3J");
    for (int i = 0; i < creditsbuf_len; i++) creditsbuf[i] ^= CREDITS_KEY;
    dprintf(s, "%s", (const char *)creditsbuf);
    for (int i = 0; i < creditsbuf_len; i++) creditsbuf[i] ^= CREDITS_KEY;
    // Wait for enter. s may be non-blocking, so we need to poll for input
    read_block(s, buffer, BUFFER_SIZE, -1);
    sendvid(s, "./credits", 29.98);
}

void handle_sensor_input(int fd, char *buffer, size_t buflen, session_t *sess) {
    char *arg = NULL;
    sensor_command_t cmd = parse_sensor_input(buffer, buflen, &arg);
    int cmd_int = cmd & ~SENSOR_CMD_INVALID;
    int cmd_invalid = cmd & SENSOR_CMD_INVALID;
    switch (cmd_int) {
        case SENSOR_CMD_LIST:
            // Send the list of angels
            for (int i = 0; i < angel_list_len; i++) {
                dprintf(fd, "%s\n", angel_list[i]);
            }
            break;
        case SENSOR_CMD_EXAMINE:
            if (cmd_invalid) {
                dprintf(fd, "usage: EXAMINE <angel>\n");
                break;
            }
            static _Thread_local char state = 0;
            char *name = arg;
            printf("[+] Examine angel: %s\n", name);
            // Find the angel
            for (int i = 0; i < angel_list_len; i++) {
                if (strcmp(angel_list[i], name) == 0) {
                    // Easter egg: if someone examines angels starting with 'R', 'S', and 'A'
                    // in that order (without any other angels in between), show the credits.
                    if (state == 0 && name[0] == 'R') {
                        state = 1;
                    }
                    else if (state == 1 && name[0] == 'S') {
                        state = 2;
                    }
                    else if (state == 2 && name[0] == 'A') {
                        state = 3;
                    }
                    else {
                        state = 0;
                    }
                    // Found it
                    char angelpath[256] = {0};
                    snprintf(angelpath, sizeof(angelpath), "./angels/%s.txt", name);
                    sendimg(fd, angelpath, IMG_DELAY);
                    if (state == 3) {
                        easter_egg(fd);
                        state = 0;
                        return;
                    }
                    return;
                }
            }
            dprintf(fd, "Unknown angel '%s'\n", name);
            break;
        case SENSOR_CMD_REPORT:
            // Show pending urgent data across all connections
            dprintf(fd, "Pending urgent data reported by our angel sensors:\n{\n");
            for (int i = 0; i <= sess->maxfds; i++) {
                int cfd = sess->sensor_sockets[i];
                if (cfd == 0) continue;
                if (FD_ISSET(cfd, &sess->exceptfds)) {
                    unsigned char oob = 0;
                    ssize_t r = recv(cfd, &oob, 1, MSG_OOB);
                    if (r < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINVAL) {
                            dprintf(fd, "No urgent data available\n");
                        } else {
                            perror("recv");
                        }
                    }
                    else {
                        dprintf(fd, "  Sensor %d: '%c',\n", cfd, oob);
                    }
                }
            }
            dprintf(fd, "}\n");
            break;
        case SENSOR_CMD_QUIT:
            dprintf(fd, "Goodbye!\n");
            close(fd);
            sess->sensor_sockets[fd] = 0;
            break;
        case SENSOR_CMD_HELP:
            dprintf(fd, "Available commands:\n");
            dprintf(fd, "LIST\n");
            dprintf(fd, "  List known angels.\n");
            dprintf(fd, "EXAMINE <angel>\n");
            dprintf(fd, "  Examine readings captured about an angel.\n");
            dprintf(fd, "REPORT\n");
            dprintf(fd, "  Examine any urgent sensor data across the monitoring system.\n");
            dprintf(fd, "HELP\n");
            dprintf(fd, "  Show this help message.\n");
            dprintf(fd, "QUIT\n");
            dprintf(fd, "  Disconnect this sensor.\n");
            break;
        case SENSOR_CMD_UNKNOWN:
            dprintf(fd, "Unknown command\n");
            break;
    }
}

int open_server_port(unsigned short port, int bindfail_ok) {
    int server_fd;
    struct sockaddr_in address;
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket failed");
        return -2;
    }

    // Allow the socket to be reused
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("setsockopt");
        close(server_fd);
        return -2;
    }

    // Set up the server details
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    // Bind the server socket
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        if (!bindfail_ok) perror("bind failed");
        close(server_fd);
        // bind failure means the port is already in use
        return -1;
    }
    if (listen(server_fd, 3) < 0) {
        perror("listen failed");
        close(server_fd);
        return -2;
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
} sensor_thread_args;

// Thread to handle sensor connections
void *sensor_thread(void *arg) {
    char buffer[BUFFER_SIZE+1] = {0};
    sensor_thread_args *args = (sensor_thread_args *)arg;
    session_t *sess = args->sess;
    sess->sensor_sockets = calloc(sess->maxfds, sizeof(int));
    struct timeval tv;

    // Main loop: accept connections, add them to the set, and select
    while(1) {
        // Ugly: if we don't sleep here and there are no connections, the thread will spin
        // and prevent render_fdset from getting the lock
        usleep(100);
        pthread_mutex_lock(&sess->sensor_lock);
        FD_ZERO(&sess->readfds);
        FD_ZERO(&sess->writefds);
        FD_ZERO(&sess->exceptfds);
        FD_SET(sess->server_fd, &sess->readfds);
        sess->nfds = sess->server_fd;

        int i;
        for (i = 0; i < sess->maxfds; i++) {
            int sd = sess->sensor_sockets[i];
            if (sd > 0) {
                FD_SET(sd, &sess->readfds);
                FD_SET(sd, &sess->writefds);
                FD_SET(sd, &sess->exceptfds);
            }
            if (sd > sess->nfds) sess->nfds = sd;
        }
        int new_socket;
        // This will block until something happens
        // select timeout
        tv.tv_sec = 0;
        tv.tv_usec = 1000; // 1ms
        int activity = select(sess->nfds + 1, &sess->readfds, &sess->writefds, &sess->exceptfds, &tv);
        pthread_mutex_unlock(&sess->sensor_lock);
        // if we timed out, just go back to the top of the loop after checking if we should exit
        if (activity == 0) {
            goto exit_check;
        }

        // Does the control thread want us to pause?
        int did_pause = 0;
        pthread_mutex_lock(&args->pause_mutex);
        while (args->should_pause) {
            printf("[-] Sensor thread pausing\n");
            did_pause = 1;
            pthread_cond_wait(&args->pause_cond, &args->pause_mutex);
        }
        pthread_mutex_unlock(&args->pause_mutex);
        if (did_pause) printf("[+] Sensor thread resuming\n");

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

            // Send the initial prompt string
            dprintf(new_socket, "Welcome to Angel sensor network interface.\n");
            dprintf(new_socket, "This is sensor ID %d.\n", new_socket);
            dprintf(new_socket, "Type HELP for a list of commands.\n");
            dprintf(new_socket, "> ");

            // Find a free slot in the sensor_sockets array
            for (i = 0; i < sess->maxfds; i++) {
                if (sess->sensor_sockets[i] == 0) {
                    sess->sensor_sockets[i] = new_socket;
                    break;
                }
            }
            if (i == sess->maxfds) {
                printf("[-] Max connections reached\n");
                close(new_socket);
                goto sensor_cleanup;
            }
        }
monitor:
        for (int i = 0; i < sess->maxfds; i++) {
            int sd = sess->sensor_sockets[i];
            if (sd == 0) continue;
            if (FD_ISSET(sd, &sess->readfds)) {
                // printf("[+] Client fd=%d ready for read\n", sd);
                ssize_t valread = read(sd, buffer, BUFFER_SIZE);
                if (valread > 0) {
                    buffer[valread] = 0;
                    handle_sensor_input(sd, buffer, valread, sess);
                    dprintf(sd, "> ");
                }
                else if (valread == 0) {
                    printf("[-] Client fd=%d disconnected\n", sd);
                    close(sd);
                    sess->sensor_sockets[i] = 0;
                } else {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        // This is fine, just means there's no data to read
                    } else {
                        perror("read");
                        close(sd);
                        sess->sensor_sockets[i] = 0;
                    }
                }
            }
        }
exit_check:
        // Check if we should exit
        if (atomic_load(&args->should_exit)) {
            printf("[-] Sensor thread exiting\n");
            goto sensor_cleanup;
        }
    }
sensor_cleanup:
    // Cleanup
    for (int i = 0; i < sess->maxfds; i++) {
        if (sess->sensor_sockets[i] > 0) {
            close(sess->sensor_sockets[i]);
        }
    }
    close(sess->server_fd);
    free(sess->sensor_sockets);
    pthread_exit(NULL);
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
    if (resp_len >= 0)
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
    rsa_error_t res = validate_challenge(sess, challenge, sizeof(challenge), response, resp_len_bytes);
    if (res == RERR_OK) {
        dprintf(new_socket, "Authentication successful!\n");
        sendimg(new_socket, "./gendo_glasses.txt", 0);
        return 1;
    } else {
        dprintf(new_socket, "Authentication failed.\n");
        if (res == RERR_BADSIG) {
            sendimg(new_socket, "./shinji.txt", 0);
            dprintf(new_socket, "Invalid signature\n");
        }
        else if (res == RERR_EVEN_KEY) {
            sendimg(new_socket, "./misato.txt", 0);
            dprintf(new_socket, "Invalid key: modulus is even\n");
        }
        else if (res == RERR_KEY_TOO_LARGE) {
            sendimg(new_socket, "./ritsuko.txt", 0);
            dprintf(new_socket, "Invalid key: too large\n");
        }
        else if (res == RERR_KEY_TOO_SMALL) {
            sendimg(new_socket, "./asuka_pathetic.txt", 0);
            dprintf(new_socket, "Invalid key: too small\n");
        }
        else {
            sendimg(new_socket, "./asuka.txt", 0);
            dprintf(new_socket, "Unknown error: %d\n", res);
        }
        return 0;
    }
}

int send_encrypted_data(int s, unsigned char *data, size_t data_len, session_t *sess) {
    unsigned char *ciphertext;
    size_t ciphertext_len;
    if (encrypt_message(sess, data, data_len, &ciphertext, &ciphertext_len)) {
        // Base64 encode the ciphertext
        size_t b64_len = 0;
        char *b64 = base64_encode(ciphertext, ciphertext_len, &b64_len);
        // Send the ciphertext, 70 characters per line
        dprintf(s, "-----BEGIN NERV ENCRYPTED MESSAGE-----\n");
        for (int i = 0; i < b64_len; i += 70) {
            dprintf(s, "%.*s\n",
                (int)(b64_len - i > 70 ? 70 : b64_len - i),
                &b64[i]);
        }
        dprintf(s, "-----END NERV ENCRYPTED MESSAGE-----\n");
        free(ciphertext);
        free(b64);
    } else {
        dprintf(s, "Encryption failed\n");
        return 0;
    }
    return 1;
}

int unauth_menu(int s, session_t *sess, sensor_thread_args *sensor_args) {
    dprintf(s, "Main menu:\n");
    dprintf(s, "1. Authenticate\n");
    dprintf(s, "2. Print public key\n");
    dprintf(s, "3. Issue sensor system halt\n");
    dprintf(s, "4. Resume sensor operations\n");
    dprintf(s, "5. MAGI status\n");
    dprintf(s, "6. Exit\n");
    dprintf(s, "Enter your choice: ");
    char *pubkey;
    char buffer[BUFFER_SIZE+1] = {0};
    int rbytes = read(s, buffer, BUFFER_SIZE);
    if (rbytes <= 0) {
        printf("[-] Disconnected\n");
        return 0;
    }
    buffer[rbytes] = 0;
    // Parse the choice
    char *endptr;
    unsigned long choice = strtoul(buffer, &endptr, 10);
    if (endptr == buffer) {
        dprintf(s, "Invalid choice\n");
        return 1;
    }
    switch (choice) {
        case 1:
            sess->authenticated = handle_auth(sess);
            break;
        case 2:
            pubkey = dump_pubkey_ssh(RSA_EXPONENT, sess->pubkey, sizeof(sess->pubkey), "newuser@nerv");
            dprintf(s, "Your public key is:\n%s\n", pubkey);
            free(pubkey);
            break;
        case 3:
            pthread_mutex_lock(&sensor_args->pause_mutex);
            sensor_args->should_pause = 1;
            pthread_mutex_unlock(&sensor_args->pause_mutex);
            dprintf(s, "Sensors are now on standby\n");
            break;
        case 4:
            pthread_mutex_lock(&sensor_args->pause_mutex);
            sensor_args->should_pause = 0;
            pthread_cond_signal(&sensor_args->pause_cond);
            pthread_mutex_unlock(&sensor_args->pause_mutex);
            dprintf(s, "Normal sensor operation resumed; sensors are receiving data.\n");
            break;
        case 5:
            dprintf(s, "\033[H\033[2J\033[3J");
            dprintf(s, "\033[?25l");            // hide cursor
            do {
                dprintf(s, "\033[H");
                render_fdset(s, sess);
                dprintf(s, "Monitoring, press enter to return to the main menu...\n");
            } while (read_block(s, buffer, BUFFER_SIZE, 100) == 0);
            dprintf(s, "\033[?25h");     // show cursor
            break;
        case 6:
            dprintf(s, "Goodbye!\n");
            return 0;
#ifdef CHALDEBUG
        case 31337:
            easter_egg(s);
            break;
        case 1234:
            dprintf(s, "fd_bits = [ ");
            for (int i = 0; i <= sess->maxfds; i++) {
                int cfd = sess->sensor_sockets[i];
                if (cfd == 0) continue;
                if (FD_ISSET(cfd, &sess->exceptfds)) {
                    dprintf(s, "%d ", cfd);
                }
            }
            dprintf(s, "]\n");
            break;
        case 0xdead:
            dprintf(s, "Received debug mode shutdown request\n");
            exit(0);
            return 0;
#endif
        default:
            dprintf(s, "Invalid choice\n");
            break;
    }
    return 1;
}

int auth_menu(int s, session_t *sess, sensor_thread_args *sensor_args) {
    dprintf(s, "Authenticated menu:\n");
    dprintf(s, "1. Send flag\n");
    dprintf(s, "2. Show credits\n");
    dprintf(s, "3. Exit\n");
    dprintf(s, "Enter your choice: ");
    char buffer[BUFFER_SIZE+1] = {0};
    int rbytes = read(s, buffer, BUFFER_SIZE);
    if (rbytes <= 0) {
        printf("[-] Disconnected\n");
        return 0;
    }
    buffer[rbytes] = 0;
    // Parse the choice
    char *endptr;
    unsigned long choice = strtoul(buffer, &endptr, 10);
    if (endptr == buffer) {
        dprintf(s, "Invalid choice\n");
        return 1;
    }
    switch (choice) {
        case 1:
            // Send the flag
            dprintf(s,
                "NOTE: Per NERV policy, sensitive data must not be sent over the network\n"
                "in plaintext. It will be encrypted using your public authentication key\n"
                "(RSA+AES-256-GCM). The format is:\n"
                "      [64-bit ciphertext_len][ciphertext][tag][iv][RSA(aes_key)]\n"
            );
            dprintf(s, "Sending flag...\n");
            // Read img/flag.txt into a buffer
            FILE *f = fopen("flag.txt", "r");
            if (!f) {
                perror("fopen");
                return 0;
            }
            fseek(f, 0, SEEK_END);
            size_t flag_len = ftell(f);
            fseek(f, 0, SEEK_SET);
            unsigned char *flag = malloc(flag_len);
            fread(flag, 1, flag_len, f);
            fclose(f);
            send_encrypted_data(s, flag, flag_len, sess);
            break;
        case 2:
            easter_egg(s);
            break;
        case 3:
            dprintf(s, "Goodbye!\n");
            return 0;
        default:
            dprintf(s, "Invalid choice\n");
            break;
    }
    return 1;
}

void *control_thread(void *arg) {
    control_thread_args *args = (control_thread_args *)arg;
    sensor_thread_args * sensor_args = NULL;
    int new_socket = args->sock;

    // Session setup
    sendimg(new_socket, "./nerv_wide.txt", 0);
    dprintf(new_socket, "Welcome to the NERV Magi System\n");
    dprintf(new_socket, "Setting up session...\n");
    session_t *sess = calloc(1, sizeof(session_t));
    sess->control_fd = new_socket;
    pthread_mutex_init(&sess->sensor_lock, NULL);
    // Generate a new RSA key
    rsa_setup(sess);

    // Set their maxfds
    sess->maxfds = args->maxfiles;

    // Find a free port for the sensor to connect to
    pthread_mutex_lock(&sensor_port_lock);
    unsigned short sensor_port = SENSOR_PORT_BASE;
    int sensor_fd = -1;
    while ((sensor_fd = open_server_port(sensor_port, 1)) < 0) {
        if (sensor_fd == -2) {
            printf("[-] Failed to open sensor port %d\n", sensor_port);
            pthread_mutex_unlock(&sensor_port_lock);
            goto control_cleanup;
        }
        // Keep trying until we find a free port
        sensor_port++;
    }
    sess->server_fd = sensor_fd;
    pthread_mutex_unlock(&sensor_port_lock);
    // Force OOB data to be sent out of band, not inline
    int opt = 0;
    if (setsockopt(sess->server_fd, SOL_SOCKET, SO_OOBINLINE, &opt, sizeof(opt))) {
        perror("setsockopt");
        goto control_cleanup;
    }
    dprintf(new_socket, "Session sensor port is: %d\n", sensor_port);
    dprintf(new_socket, "You can connect to this port to view sensor data.\n");

    // Spawn a thread to handle the sensor connections
    pthread_t thread;
    sensor_args = calloc(1, sizeof(sensor_thread_args));
    sensor_args->sess = sess;
    sensor_args->should_exit = 0;
    sensor_args->should_pause = 0;
    pthread_cond_init(&sensor_args->pause_cond, NULL);
    pthread_mutex_init(&sensor_args->pause_mutex, NULL);
    pthread_create(&thread, NULL, sensor_thread, sensor_args);
    char threadname[16] = {0};
    snprintf(threadname, sizeof(threadname), "sensor-%6d", sensor_port);
    pthread_setname_np(thread, threadname);

    // Server loop
    while (1) {
        dprintf(new_socket, "Current authorization level: %s\n",
                sess->authenticated ? "ADMIN" : "UNPRIVILEGED");
        if (sess->authenticated) {
            if (!auth_menu(new_socket, sess, sensor_args)) {
                break;
            }
        }
        else {
            if (!unauth_menu(new_socket, sess, sensor_args)) {
                break;
            }
        }
    }
control_cleanup:
    close(new_socket);
    // Unpause the sensor thread if it's paused
    if (sensor_args != NULL) {
        pthread_mutex_lock(&sensor_args->pause_mutex);
        sensor_args->should_pause = 0;
        pthread_cond_signal(&sensor_args->pause_cond);
        pthread_mutex_unlock(&sensor_args->pause_mutex);
        // Tell the sensor thread to exit
        atomic_store(&sensor_args->should_exit, 1);
        pthread_join(thread, NULL);
        free(sensor_args);
    }
    free(args);
    free(sess);
    printf("[-] Control thread exiting\n");
    // Terminate this thread
    pthread_exit(NULL);
    return NULL;
}

int main() {
    // Ignore SIGPIPE so we don't crash when a sensor disconnects
    signal(SIGPIPE, SIG_IGN);
    signal(SIGUSR1, sigusr1_handler);

    // Set max files
    unsigned long maxfiles = increase_fd_limit(PREFERRED_MAXFILES);
    printf("[+] Max files is %lu\n", maxfiles);

    // Unpack the images
    if (load_image_resources() != 0) {
        return 1;
    }

    int control_fd;
    printf("[+] Setting up control port\n");
    control_fd = open_server_port(CONTROL_PORT, 0);
    // Accept connections in a loop. For each connection, generate a new RSA key
    // and send the public key to the sensor, find a free port for the sensor to
    // connect to, and spawn a thread to handle the sensor connections.
    while (1) {
        struct sockaddr_in address;
        int addrlen = sizeof(address);
        int new_socket;
        if ((new_socket = accept(control_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
            continue;
        }
        printf("[+] New control connection from %s:%d assigned to fd=%d\n", inet_ntoa(address.sin_addr), ntohs(address.sin_port), new_socket);

        // Start the control thread
        pthread_t thread;
        control_thread_args *args = calloc(1, sizeof(control_thread_args));
        args->sock = new_socket;
        args->maxfiles = maxfiles;
        pthread_create(&thread, NULL, control_thread, (void *)args);
        char threadname[16] = {0};
        sprintf(threadname, "control-%d", new_socket);
        pthread_setname_np(thread, threadname);
    }

    unload_image_resources();

    return 0;
}
