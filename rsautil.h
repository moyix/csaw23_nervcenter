#pragma once

#include "sockfun.h"

int rsa_setup(session_t *thing);
char * dump_pubkey_ssh(int e, unsigned char *pubkey, unsigned int pubkey_len, char *comment);