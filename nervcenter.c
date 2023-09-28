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

#define BUFFER_SIZE 1024
#define CONTROL_PORT 2000
#define CLIENT_PORT_BASE 2001
#define PREFERRED_MAXFILES 1200
#define KEY_SIZE 1024

#include "nervcenter.h"
#include "rsautil.h"
#include "base64.h"
#include "parsers.h"

// Lock for getting the client port
pthread_mutex_t client_port_lock = PTHREAD_MUTEX_INITIALIZER;

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

char *angel_list[32];
int angel_list_len = 0;
void setup_angel_list() {
    DIR *d;
    struct dirent *dir;
    d = opendir(IMGDIR "/angels");
    if (d) {
        while ((dir = readdir(d)) != NULL) {
            if (dir->d_type != DT_REG) continue;
            // Strip off the .txt extension
            char *ext = strstr(dir->d_name, ".txt");
            if (ext) *ext = 0;
            angel_list[angel_list_len++] = strdup(dir->d_name);
        }
        closedir(d);
    }
}

int strptrcmp(const void *a, const void *b) {
    return strcmp(*(char **)a, *(char **)b);
}

// Small delay when sending images to let them scroll by
#define IMG_DELAY 15000
void sendimg(int fd, const char *path, int delay) {
    // printf("[+] Sending image %s\n", path);
    FILE *img = fopen(path, "r");
    if (!img) {
        fprintf(stderr, "[-] Failed to open %s: ", path);
        perror("fopen");
        return;
    }
    // Read the file line by line with getline and send it
    char *line = NULL;
    size_t len = 0;
    ssize_t nread;
    while ((nread = getline(&line, &len, img)) != -1) {
        // printf("Sending line: %s", line);
        dprintf(fd, "%s", line);
        if (delay) usleep(delay);
    }
    fclose(img);
}

void sendvid(int fd, const char *fullpath, float fps) {
    // list the files in the directory
    int n_frames = 0;
    int capacity = 0;
    char **framelist = NULL;
    DIR *d;
    struct dirent *dir;
    d = opendir(fullpath);
    if (d) {
        while ((dir = readdir(d)) != NULL) {
            if (dir->d_type != DT_REG) continue;
            // Skip non-.txt files
            if (strstr(dir->d_name, ".txt") == NULL) continue;
            if (n_frames == capacity) {
                if (capacity == 0)
                    capacity = 16;
                else
                    capacity *= 2;
                framelist = realloc(framelist, capacity * sizeof(char *));
            }
            // Save the name as the full path so we don't have to keep appending it
            char *name = malloc(strlen(fullpath) + strlen(dir->d_name) + 2);
            snprintf(name, strlen(fullpath) + strlen(dir->d_name) + 2, "%s/%s", fullpath, dir->d_name);
            framelist[n_frames++] = name;
        }
        closedir(d);
    }
    // Sort the frames
    qsort(framelist, n_frames, sizeof(char *), strptrcmp);
    // Send clear screen and hide cursor commands
    dprintf(fd, "\033[H\033[2J\033[3J"); // clear screen
    dprintf(fd, "\033[?25l");            // hide cursor
    // Send the frames
    float frametime = 1.0 / fps;
    suseconds_t usec = frametime * 1000000;
    for (int i = 0; i < n_frames; i++) {
        // Time the call to sendimg to calculate correct delay
        struct timeval start, end;
        gettimeofday(&start, NULL);
        sendimg(fd, framelist[i], 0);
        gettimeofday(&end, NULL);
        suseconds_t elapsed = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec);
        if (elapsed < usec) {
            usleep(usec - elapsed);
        }
    }
    // Send show cursor command
    dprintf(fd, "\033[?25h");     // show cursor
    // Reset the terminal
    dprintf(fd, "\033c");
    dprintf(fd, "\033[H\033[2J\033[3J");

    // Free the framelist
    for (int i = 0; i < n_frames; i++) {
        free(framelist[i]);
    }
    free(framelist);
}

void read_block(int s, char *buffer, size_t size, int timeout) {
    // Poll any pending input with a short timeout
    struct pollfd pfd = { .fd = s, .events = POLLIN, };
    poll(&pfd, 1, timeout);
    if (pfd.revents & POLLIN) {
        read(s, buffer, BUFFER_SIZE);
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
    sendvid(s, IMGDIR "/credits", 29.98);
}

void handle_client_input(int fd, char *buffer, size_t buflen, session_t *sess) {
    char *arg = NULL;
    client_command_t cmd = parse_client_input(buffer, buflen, &arg);
    int cmd_int = cmd & ~CLIENT_CMD_INVALID;
    int cmd_invalid = cmd & CLIENT_CMD_INVALID;
    switch (cmd_int) {
        case CLIENT_CMD_LIST:
            // Send the list of angels
            for (int i = 0; i < angel_list_len; i++) {
                dprintf(fd, "%s\n", angel_list[i]);
            }
            break;
        case CLIENT_CMD_EXAMINE:
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
                    snprintf(angelpath, sizeof(angelpath), IMGDIR "/angels/%s.txt", name);
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
        case CLIENT_CMD_EMERGENCY:
            // Show pending urgent data across all connections
            dprintf(fd, "Pending urgent data reported by our angel sensors:\n{\n");
            for (int i = 0; i <= sess->maxfds; i++) {
                int cfd = sess->client_sockets[i];
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
                        dprintf(fd, "  fd=%04d: '%c',\n", cfd, oob);
                    }
                }
            }
            dprintf(fd, "}\n");
            break;
        case CLIENT_CMD_QUIT:
            dprintf(fd, "Goodbye!\n");
            close(fd);
            sess->client_sockets[fd] = 0;
            break;
        case CLIENT_CMD_HELP:
            dprintf(fd, "Available commands:\n");
            dprintf(fd, "LIST\n");
            dprintf(fd, "  List known angels.\n");
            dprintf(fd, "EXAMINE <angel>\n");
            dprintf(fd, "  Examine an angel.\n");
            dprintf(fd, "EMERGENCY\n");
            dprintf(fd, "  Examine any urgent data.\n");
            dprintf(fd, "HELP\n");
            dprintf(fd, "  Show this help message.\n");
            dprintf(fd, "QUIT\n");
            dprintf(fd, "  Disconnect this client.\n");
            break;
        case CLIENT_CMD_UNKNOWN:
            dprintf(fd, "Unknown command\n");
            break;
    }
}

int open_server_port(unsigned short port) {
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
        return -2;
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
} client_thread_args;

// Thread to handle client connections
void *client_thread(void *arg) {
    char buffer[BUFFER_SIZE+1] = {0};
    client_thread_args *args = (client_thread_args *)arg;
    session_t *sess = args->sess;
    sess->client_sockets = calloc(sess->maxfds, sizeof(int));

    // Main loop: accept connections, add them to the set, and select
    while(1) {
        FD_ZERO(&sess->readfds);
        FD_ZERO(&sess->exceptfds);
        FD_SET(sess->server_fd, &sess->readfds);
        sess->nfds = sess->server_fd;

        int i;
        for (i = 0; i < sess->maxfds; i++) {
            int sd = sess->client_sockets[i];
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

            // Send the initial prompt string
            dprintf(new_socket, "Welcome to Emergency Angel Response interface.\n");
            dprintf(new_socket, "Type HELP for a list of commands.\n");
            dprintf(new_socket, "> ");

            // Find a free slot in the client_sockets array
            for (i = 0; i < sess->maxfds; i++) {
                if (sess->client_sockets[i] == 0) {
                    sess->client_sockets[i] = new_socket;
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
            int sd = sess->client_sockets[i];
            if (sd == 0) continue;
            if (FD_ISSET(sd, &sess->readfds)) {
                // printf("[+] Client fd=%d ready for read\n", sd);
                ssize_t valread = read(sd, buffer, BUFFER_SIZE);
                if (valread > 0) {
                    buffer[valread] = 0;
                    handle_client_input(sd, buffer, valread, sess);
                    dprintf(sd, "> ");
                }
                else if (valread == 0) {
                    printf("[-] Client fd=%d disconnected\n", sd);
                    close(sd);
                    sess->client_sockets[i] = 0;
                } else {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        // This is fine, just means there's no data to read
                    } else {
                        perror("read");
                        close(sd);
                        sess->client_sockets[i] = 0;
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
                if (sess->client_sockets[i] > 0) {
                    close(sess->client_sockets[i]);
            }
            }
            close(sess->server_fd);
            free(sess->client_sockets);
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
    if (validate_challenge(sess, challenge, sizeof(challenge), response, resp_len_bytes)) {
        dprintf(new_socket, "Authentication successful!\n");
        sendimg(new_socket, IMGDIR "/gendo_glasses.txt", 0);
        return 1;
    } else {
        dprintf(new_socket, "Authentication failed.\n");
        sendimg(new_socket, IMGDIR "/asuka_pathetic.txt", 0);
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

int unauth_menu(int s, session_t *sess, client_thread_args *client_args) {
    dprintf(s, "Main menu:\n");
    dprintf(s, "1. Authenticate\n");
    dprintf(s, "2. Print public key\n");
    dprintf(s, "3. Pause client thread\n");
    dprintf(s, "4. Resume client thread\n");
    dprintf(s, "5. Exit\n");
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
            pthread_mutex_lock(&client_args->pause_mutex);
            client_args->should_pause = 1;
            pthread_mutex_unlock(&client_args->pause_mutex);
            dprintf(s, "Client thread paused\n");
            break;
        case 4:
            pthread_mutex_lock(&client_args->pause_mutex);
            client_args->should_pause = 0;
            pthread_cond_signal(&client_args->pause_cond);
            pthread_mutex_unlock(&client_args->pause_mutex);
            dprintf(s, "Client thread resumed\n");
            break;
        case 5:
            dprintf(s, "Goodbye!\n");
            return 0;
#ifdef CHALDEBUG
        case 31337:
            easter_egg(s);
            break;
        case 1234:
            dprintf(s, "fd_bits = [ ");
            for (int i = 0; i <= sess->maxfds; i++) {
                int cfd = sess->client_sockets[i];
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

int auth_menu(int s, session_t *sess, client_thread_args *client_args) {
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
            FILE *f = fopen(IMGDIR "/flag.txt", "r");
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
    int new_socket = args->sock;

    // Session setup
    sendimg(new_socket, IMGDIR "/nerv_wide.txt", 0);
    dprintf(new_socket, "Welcome to the NERV Magi System\n");
    dprintf(new_socket, "Setting up session...\n");
    session_t *sess = calloc(1, sizeof(session_t));
    sess->control_fd = new_socket;
    // Generate a new RSA key
    rsa_setup(sess);

    // Set their maxfds
    sess->maxfds = args->maxfiles;

    // Find a free port for the client to connect to
    pthread_mutex_lock(&client_port_lock);
    unsigned short client_port = CLIENT_PORT_BASE;
    int client_fd = -1;
    while ((client_fd = open_server_port(client_port)) < 0) {
        if (client_fd == -2) {
            printf("[-] Failed to open client port %d\n", client_port);
            pthread_mutex_unlock(&client_port_lock);
            pthread_exit(NULL);
        }
        // Keep trying until we find a free port
        client_port++;
    }
    sess->server_fd = client_fd;
    pthread_mutex_unlock(&client_port_lock);
    // Force OOB data to be sent out of band, not inline
    int opt = 0;
    if (setsockopt(sess->server_fd, SOL_SOCKET, SO_OOBINLINE, &opt, sizeof(opt))) {
        perror("setsockopt");
        pthread_exit(NULL);
    }
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
    char threadname[16] = {0};
    snprintf(threadname, sizeof(threadname), "client-%6d", client_port);
    pthread_setname_np(thread, threadname);

    // Server loop
    while (1) {
        dprintf(new_socket, "Current authorization level: %s\n",
                sess->authenticated ? "ADMIN" : "UNPRIVILEGED");
        if (sess->authenticated) {
            if (!auth_menu(new_socket, sess, client_args)) {
                break;
            }
        }
        else {
            if (!unauth_menu(new_socket, sess, client_args)) {
                break;
            }
        }
    }

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

    // Set up the angel list
    setup_angel_list();

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
            pthread_exit(NULL);
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

    return 0;
}
