#pragma once

typedef enum {
    CLIENT_CMD_LIST         = 1,
    CLIENT_CMD_EXAMINE      = 2,
    CLIENT_CMD_EMERGENCY    = 4,
    CLIENT_CMD_QUIT         = 8,
    CLIENT_CMD_HELP         = 16,
    CLIENT_CMD_UNKNOWN      = 32, // Unknown command
    CLIENT_CMD_INVALID      = 64, // Known command, but invalid arguments
} client_command_t;

client_command_t parse_client_input(char *buffer, size_t buflen, char **arg);
