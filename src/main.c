#include <string.h>
#include <stdbool.h>
#include "client/main_client.h"
#include "server/main_server.h"

static bool is_server(int argc, char **argv)
{
    for (int i = 1; i < argc; i++)
        if (!strcmp(argv[i], "--serve") || !strcmp(argv[i], "-s"))
            return true;
    return false;
}

int main(int argc, char **argv)
{
    if (is_server(argc, argv))
        return main_server(argc, argv);
    return main_client(argc, argv);
}
