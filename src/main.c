#include "lib/basic.h"
#include "client/main_client.h"
#include "server/main_server.h"

static b8 is_server(int argc, char **argv)
{
    for (int i = 1; i < argc; i++) {
        string arg = ZT2S(argv[i]);
        if (streq(arg, S("--serve")) ||
            streq(arg, S("-s")))
            return true;
    }
    return false;
}

int main(int argc, char **argv)
{
    if (is_server(argc, argv))
        return main_server(argc, argv);
    return main_client(argc, argv);
}
