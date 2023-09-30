#pragma once

#include <sys/select.h>

#include "nervcenter.h"

void render_fdset(int fd, session_t *s);
