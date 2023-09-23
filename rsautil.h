#pragma once

#include "sockfun.h"

int rsa_setup(session_t *thing);
char * dump_pubkey_ssh(int e, unsigned char *pubkey, unsigned int pubkey_len, char *comment);
void generate_challenge(unsigned char *challenge, size_t challenge_len);
int validate_challenge(session_t *sess,
    unsigned char *challenge, size_t challenge_len,
    unsigned char *response, size_t response_len
);
