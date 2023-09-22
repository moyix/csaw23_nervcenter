#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <fcntl.h>
#include <unistd.h>

// inotify
#include <sys/inotify.h>
#include <poll.h>
// for CLOCK_MONOTONIC
#include <time.h>
#include <sys/stat.h>

// Silence deprecation warnings since we want to use the RSA primitives
#define OPENSSL_SUPPRESS_DEPRECATED 1
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include "rsautil.h"
#include "base64.h"

int wait_for_decryption(char *dir, char *filename) {
    // Check if it already exists
    char path[1024];
    sprintf(path, "%s/%s", dir, filename);
    if (access(path, F_OK) != -1) {
        printf("%s exists, exiting.\n", path);
        return 1;
    }
    struct timespec start, current;
    clock_gettime(CLOCK_MONOTONIC, &start);

    int fd = inotify_init();
    if (fd == -1) {
        perror("inotify_init");
        return -1;
    }

    int wd = inotify_add_watch(fd, dir, IN_CREATE);
    if (wd == -1) {
        perror("inotify_add_watch");
        return -1;
    }

    struct pollfd pfd = {fd, POLLIN, 0};
    int timeout = 65000;  // Full timeout in milliseconds
    char buffer[1024];
    int file_found = 0;

    char progress_bar[66];
    memset(progress_bar, ' ', sizeof(progress_bar));
    progress_bar[65] = '\0';

    while (1) {
        // Poll for events; use a shorter timeout here so we can display the progress bar
        int ret = poll(&pfd, 1, 1000);

        clock_gettime(CLOCK_MONOTONIC, &current);
        int elapsed = (current.tv_sec - start.tv_sec) * 1000 + (current.tv_nsec - start.tv_nsec) / 1000000;

        if (ret == -1) {
            perror("poll");
            return -1;
        } else if (ret == 0) {
            if (elapsed >= 65000) {
                printf("\nTimeout reached, exiting.\n");
                break;
            }
            else {
                // Update progress bar
                int progress = elapsed * 65 / 65000;
                if (progress > 65) progress = 65;
                memset(progress_bar, '#', progress);
                printf("\r[%s]", progress_bar);
                fflush(stdout);
            }
        } else {
            // printf("Something happened, checking for file...\n");
            int len = read(fd, buffer, sizeof(buffer));
            if (len == -1) {
                perror("read");
                return -1;
            }

            for (int i = 0; i < len;) {
                struct inotify_event *event = (struct inotify_event *)&buffer[i];
                // __builtin_dump_struct(event, &printf);
                if (event->len && strcmp(event->name, filename) == 0) {
                    printf("\n%s/%s exists, exiting.\n", dir, filename);
                    file_found = 1;
                    break;
                }
                i += sizeof(struct inotify_event) + event->len;
            }

            if (file_found) {
                break;
            }

            // Update remaining timeout
            timeout = 65000 - elapsed;
            if (timeout < 0) {
                printf("\nTimeout reached, exiting.\n");
                break;
            }
        }
    }
    printf("\n");

    inotify_rm_watch(fd, wd);
    close(fd);

    if (file_found) {
        printf("File found, waiting to make sure it's fully written...\n");
        // Wait until it has non-zero size
        struct stat st;
        while (1) {
            if (stat(path, &st) == 0 && st.st_size > 0) {
                break;
            }
            sleep(1);
        }
    }

    return file_found;
}

int rsa_setup(session_t *s) {
    int failed = 0;
    RSA *rsa;
    RSA *new_rsa;
    RSA *new_rsa_priv;
    BIGNUM *n;
    BIGNUM *new_n;
    BIGNUM *e = BN_new();
    BN_set_word(e, 65537);
    BIGNUM *d;
    FILE *savedpk = fopen("/tmp/tamper.txt", "r");
    FILE *savedpk_d = fopen("/tmp/tamper_d.txt", "r");
    int have_key = 0;
    if (!savedpk || !savedpk_d) {
        printf("[-] Failed to open existing key ; will generate a fresh RSA key\n");
        if (savedpk) fclose(savedpk);
        if (savedpk_d) fclose(savedpk_d);
    }
    else {
        printf("[+] Found existing key, reading it\n");
        char pubkey_n[1024] = {};
        char privkey[1024] = {};
        // pub key format is e n
        fscanf(savedpk, "%*d %s\n", pubkey_n);
        // priv key format is d
        fscanf(savedpk_d, "%s\n", privkey);
        printf("[+] Public key:\n");
        printf("N = %s\n", pubkey_n);
        printf("[+] Private key:\n");
        printf("D = %s\n", privkey);
        // Convert the public key to a BIGNUM
        n = BN_new();
        BN_dec2bn(&n, pubkey_n);
        // Convert the private key to a BIGNUM
        d = BN_new();
        BN_dec2bn(&d, privkey);
        // Store the keys in the RSA struct
        rsa = RSA_new();
        RSA_set0_key(rsa, BN_dup(n), BN_dup(e), NULL);
        new_rsa = RSA_new();
        RSA_set0_key(new_rsa, BN_dup(n), BN_dup(e), BN_dup(d));
        new_rsa_priv = RSA_new();
        RSA_set0_key(new_rsa_priv, BN_dup(n), BN_dup(e), BN_dup(d));
        fclose(savedpk);
        fclose(savedpk_d);
        have_key = 1;
    }

    while (!have_key) {
        // Generate a 1024 bit key with e = 65537
        rsa = RSA_new();
        RSA_generate_key_ex(rsa, 1024, e, NULL);
        // Get the public key modulus
        const BIGNUM *n = RSA_get0_n(rsa);
        int pubkey_len = BN_num_bytes(n);
        unsigned char *pubkey = calloc(pubkey_len, sizeof(unsigned char));
        BN_bn2bin(n, pubkey);
        // Decimal version for printing
        char * n_dec = BN_bn2dec(n);
        // dump the public modulus
        printf("[+] Public key modulus (hex):\n");
        printf("N = ");
        for (int i = 0; i < pubkey_len; i++) {
            printf("%02X", pubkey[i]);
        }
        printf("\n");
        printf("[+] Public key modulus (dec):\n");
        printf("N = %s\n", n_dec);
        OPENSSL_free(n_dec);

        // Tamper with the public key
        printf("[+] Tampering with public key\n");

        int which_byte = 0; // MSB
        // int which_byte = pubkey_len - 1; // LSB
        // Set the byte randomly
        RAND_bytes(pubkey+which_byte, 1);

        // Flip a random bit
        // int bit = rand() % (pubkey_len * 8);
        // pubkey[bit / 8] ^= 1 << (bit % 8);

        // Key has to remain odd for montgomery multiplication
        pubkey[pubkey_len-1] |= 1;

        // Store the tampered public key back into the RSA struct
        printf("[+] Storing tampered public key back into RSA struct\n");
        new_n = BN_new();
        new_rsa = RSA_new();
        BN_bin2bn(pubkey, pubkey_len, new_n);
        // NB: set0 takes ownership of the BIGNUMs so we need to dup them
        RSA_set0_key(new_rsa, BN_dup(new_n), BN_dup(e), NULL);

        // Print the tampered public key modulus
        printf("[+] Tampered public key modulus (hex):\n");
        n = RSA_get0_n(new_rsa);
        printf("N = ");
        BN_print_fp(stdout, n);
        printf("\n");
        printf("[+] Tampered public key modulus (dec):\n");
        n_dec = BN_bn2dec(n);
        printf("N = %s\n", n_dec);

        // Write the tampered e and n to a file
        FILE *f = fopen("/tmp/tamper.txt", "w");
        fprintf(f, "%d %s\n", 65537, n_dec);
        fclose(f);
        OPENSSL_free(n_dec);
        printf("[+] Wrote tampered public key to /tmp/tamper.txt\n");

        // Wait 65 seconds and then try to read the key from /tmp/tamper_d.txt
        FILE *f2 = NULL;
        printf("[+] Waiting up to 65 seconds for attack to run...\n");
        int res = wait_for_decryption("/tmp", "tamper_d.txt");
        if (res != 1) {
            printf("[-] Attack failed\n");
            goto cleanup_continue;
        }
        printf("[+] Waiting 5 seconds to make sure the file is fully written...\n");
        sleep(5);
        printf("[+] Reading private key from /tmp/tamper_d.txt\n");
        f2 = fopen("/tmp/tamper_d.txt", "r");
        if (f2 == NULL) {
            printf("[-] Failed to open /tmp/tamper_d.txt\n");
            goto cleanup_continue;
        }
        char privkey[1024] = {};
        fgets(privkey, sizeof(privkey), f2);
        printf("[+] Read %s from /tmp/tamper_d.txt\n", privkey);
        // If the user doesn't provide a key, reset the loop
        if (strlen(privkey) < 2) {
            printf("[-] No key provided, will start over.\n");
            goto cleanup_continue;
        }
        // Remove the newline
        privkey[strlen(privkey)-1] = '\0';
        printf("[+] Private key:\n");
        printf("D = %s\n", privkey);
        // Convert the private key to a BIGNUM
        d = BN_new();
        BN_dec2bn(&d, privkey);
        // Store the private key in the RSA struct
        new_rsa_priv = RSA_new();
        RSA_set0_key(new_rsa_priv, BN_dup(new_n), BN_dup(e), d);
        break;
    cleanup_continue:
        if (f2) {
            fclose(f2);
            f2 = NULL;
        }
        free(pubkey);
        RSA_free(rsa);
        RSA_free(new_rsa);
        BN_free(new_n);
    }

    // Disable blind signing
    RSA_blinding_off(new_rsa);
    RSA_blinding_off(new_rsa_priv);

    unsigned char *msg = (unsigned char *)"Welcome to the RSA challenge!\n";

    // Create a digest of the message
    unsigned char *digest = calloc(EVP_MAX_MD_SIZE, sizeof(unsigned char));
    unsigned int digest_len;
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(mdctx, msg, strlen((char*)msg));
    EVP_DigestFinal_ex(mdctx, digest, &digest_len);
    EVP_MD_CTX_free(mdctx);

    // Dump the digest
    printf("Digest = ");
    for (int i = 0; i < digest_len; i++) {
        printf("%02X", digest[i]);
    }
    printf("\n");

    // Sign the message digest
    int res;
    unsigned char *sig = calloc(RSA_size(new_rsa_priv), sizeof(unsigned char));
    unsigned int sig_len = 0;
    res = RSA_sign(NID_sha256, digest, digest_len, sig, &sig_len, new_rsa_priv);
    if (res != 1) {
        printf("[-] Signing failed\n");
        char err[256];
        ERR_error_string(ERR_get_error(), err);
        printf("[-] Error: %s\n", err);
        failed = 1;
    }
    // Dump the signature
    printf("Signature = ");
    for (int i = 0; i < sig_len; i++) {
        printf("%02X", sig[i]);
    }
    printf("\n");
    // Verify the signature
    res = RSA_verify(NID_sha256, digest, digest_len, sig, sig_len, new_rsa);
    printf("Verified = %d\n", res);
    if (res != 1) {
        printf("[-] Signature verification failed\n");
        printf("[-] Error: ");
        ERR_print_errors_fp(stdout);
        failed = 1;
    }

    // Dump the public key in SSH format
    const BIGNUM *n_print = RSA_get0_n(new_rsa);
    int pubkey_len = BN_num_bytes(n_print);
    unsigned char *pubkey = calloc(pubkey_len, sizeof(unsigned char));
    BN_bn2bin(n_print, pubkey);
    printf("%s", dump_pubkey_ssh(65537, pubkey, pubkey_len, "gendo@nerv"));

    // Set up the session
    if (pubkey_len > sizeof(s->pubkey)) {
        printf("[-] Public key is too large\n");
        failed = 1;
    }
    else {
        printf("[+] Setting up session, pubkey_len = %d\n", pubkey_len);
        memcpy(s->pubkey, pubkey, pubkey_len);
    }
    return !failed;
}

char * dump_pubkey_ssh(int e, unsigned char *pubkey, unsigned int pubkey_len, char *comment) {
    unsigned char keybuf[1024] = {};
    int keybuf_len = 0;
    // key type
    memcpy(keybuf, "\x00\x00\x00\x07ssh-rsa", 11);
    keybuf_len += 11;
    // exponent size, big endian
    keybuf[keybuf_len++] = 0;
    keybuf[keybuf_len++] = 0;
    keybuf[keybuf_len++] = 0;
    keybuf[keybuf_len++] = 3;
    // exponent
    unsigned char exponent[3];
    exponent[0] = (e >> 16) & 0xFF;
    exponent[1] = (e >> 8) & 0xFF;
    exponent[2] = e & 0xFF;
    memcpy(&keybuf[keybuf_len], exponent, 3);
    keybuf_len += 3;
    // modulus size, big endian
    // Note: from RFC 4251:
    //    mpint
    //   Represents multiple precision integers in two's complement format,
    //   stored as a string, 8 bits per byte, MSB first.  Negative numbers
    //   have the value 1 as the most significant bit of the first byte of
    //   the data partition.  If the most significant bit would be set for
    //   a positive number, the number MUST be preceded by a zero byte.
    //   Unnecessary leading bytes with the value 0 or 255 MUST NOT be
    //   included.  The value zero MUST be stored as a string with zero
    //   bytes of data.
    // So we need to check if the MSB is set and add a leading zero if so
    int real_size = pubkey_len;
    if (pubkey[0] & 0x80) {
        real_size++;
    }
    keybuf[keybuf_len++] = (real_size >> 24) & 0xFF;
    keybuf[keybuf_len++] = (real_size >> 16) & 0xFF;
    keybuf[keybuf_len++] = (real_size >> 8) & 0xFF;
    keybuf[keybuf_len++] = real_size & 0xFF;
    // modulus
    if (pubkey[0] & 0x80) {
        keybuf[keybuf_len++] = 0;
    }
    memcpy(&keybuf[keybuf_len], pubkey, pubkey_len);
    keybuf_len += pubkey_len;

    // Base64 encode the key
    size_t b64_len = 0;
    char *b64 = base64_encode(keybuf, keybuf_len, &b64_len);

    // Dump the public key in SSH format
    char *ssh = calloc(7 + 1 + b64_len + 1 + strlen(comment) + 1 + 1, sizeof(char));
    sprintf(ssh, "ssh-rsa %s gendo@nerv\n", b64);
    free(b64);
    return ssh;
}