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

int rsa_setup(session_t *s) {
    int failed = 0;
    RSA *rsa;
    BIGNUM *e = BN_new();
    BN_set_word(e, RSA_EXPONENT);

    // Generate a RSA_KEY_SIZE bit key with e = RSA_EXPONENT
    rsa = RSA_new();
    RSA_generate_key_ex(rsa, RSA_KEY_SIZE, e, NULL);

    // Get the public key modulus
    const BIGNUM *n = RSA_get0_n(rsa);
    int pubkey_len = BN_num_bytes(n);
    unsigned char *pubkey = calloc(pubkey_len, sizeof(unsigned char));
    BN_bn2bin(n, pubkey);
    // Decimal version for printing
    char * n_dec = BN_bn2dec(n);
    printf("[+] Public key modulus\n");
    printf("N = %s\n", n_dec);
    OPENSSL_free(n_dec);

    // Print the private exponent d
    const BIGNUM *d = RSA_get0_d(rsa);
    // Decimal version for printing
    char * d_dec = BN_bn2dec(d);
    printf("[+] Private exponent:\n");
    printf("D = %s\n", d_dec);
    OPENSSL_free(d_dec);

    // Print p and q
    const BIGNUM *p = RSA_get0_p(rsa);
    const BIGNUM *q = RSA_get0_q(rsa);
    // Decimal version for printing
    char * p_dec = BN_bn2dec(p);
    char * q_dec = BN_bn2dec(q);
    printf("[+] p and q:\n");
    printf("p = %s\n", p_dec);
    printf("q = %s\n", q_dec);
    OPENSSL_free(p_dec);
    OPENSSL_free(q_dec);

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
    int size = snprintf(NULL, 0, "ssh-rsa %s %s", b64, comment);
    char *ssh = calloc(size+1, sizeof(char));
    snprintf(ssh, size+1, "ssh-rsa %s %s", b64, comment);
    free(b64);
    return ssh;
}

// Generate a challenge string
void generate_challenge(unsigned char *challenge, size_t challenge_len) {
    // Generate a random challenge
    RAND_bytes(challenge, challenge_len);
}

// Validate challenge response
int validate_challenge(session_t *sess,
    unsigned char *challenge, size_t challenge_len,
    unsigned char *response, size_t response_len) {
    // Create an RSA key from the public key in the session
    RSA *rsa = RSA_new();
    BIGNUM *n = BN_new();
    BN_bin2bn(sess->pubkey, sizeof(sess->pubkey), n);
    BIGNUM *e = BN_new();
    BN_set_word(e, RSA_EXPONENT);
    RSA_set0_key(rsa, n, e, NULL);

    printf("[+] Public key modulus for validation:\n");
    char * n_hex = BN_bn2hex(n);
    printf("N = %s\n", n_hex);
    OPENSSL_free(n_hex);

    // Verify the signature
    int res = RSA_verify(NID_sha256, challenge, challenge_len, response, response_len, rsa);
    printf("Verified = %d\n", res);
    if (res != 1) {
        printf("[-] Signature verification failed\n");
        printf("[-] Error: ");
        ERR_print_errors_fp(stdout);
        return 0;
    }
    else {
        printf("[+] Signature verified\n");
        return 1;
    }
}

    // // test...
    // unsigned char *msg = (unsigned char *)"Welcome to the RSA challenge!\n";

    // // Create a digest of the message
    // unsigned char *digest = calloc(EVP_MAX_MD_SIZE, sizeof(unsigned char));
    // unsigned int digest_len;
    // EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    // EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    // EVP_DigestUpdate(mdctx, msg, strlen((char*)msg));
    // EVP_DigestFinal_ex(mdctx, digest, &digest_len);
    // EVP_MD_CTX_free(mdctx);

    // // Dump the digest
    // printf("Digest = ");
    // for (int i = 0; i < digest_len; i++) {
    //     printf("%02X", digest[i]);
    // }
    // printf("\n");

    // // Sign the message digest
    // int res;
    // unsigned char *sig = calloc(RSA_size(rsa), sizeof(unsigned char));
    // unsigned int sig_len = 0;
    // res = RSA_sign(NID_sha256, digest, digest_len, sig, &sig_len, rsa);
    // if (res != 1) {
    //     printf("[-] Signing failed\n");
    //     char err[256];
    //     ERR_error_string(ERR_get_error(), err);
    //     printf("[-] Error: %s\n", err);
    //     failed = 1;
    // }
    // // Dump the signature
    // printf("Signature = ");
    // for (int i = 0; i < sig_len; i++) {
    //     printf("%02X", sig[i]);
    // }
    // printf("\n");