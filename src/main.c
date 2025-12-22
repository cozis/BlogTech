#include <stdio.h>

#include "main_client.h"
#include "main_server.h"

#include "lib/basic.h"

static b8 have_flag(int argc, char **argv, string f)
{
    for (int i = 1; i < argc; i++) {
        string arg = ZT2S(argv[i]);
        if (streq(arg, f))
            return true;
    }
    return false;
}

static void print_usage(FILE *stream, char *name)
{
    fprintf(stream,
        "Usage:\n"
        "  %s { --help | -h }\n"
        "  %s { --serve | -s } [ options ]\n"
        "  %s { --get | -g | --put | -p | --delete } [ options ] file1.txt file2.txt ...\n"
        "\n", name, name, name);
    fprintf(stream,
        "General options:\n"
        "  --help                      Show this message\n"
        "  --config=<path>             Load options from a config file. If the\n"
        "                              blogtech.conf file is present in the CWD,\n"
        "                              it is loaded implicitly.\n"
        "  --no-config                 The default config file is ignored\n"
        "  --trace-bytes               Dump all I/O to stdout\n"
        "  --serve, -s                 Run BlogTech as an HTTP(S) server\n"
        "  --get, -g                   Download files from a remote BlogTech server\n"
        "  --put, -p                   Upload files to a remote BlogTech server\n"
        "  --delete                    Remove files from a remote BlogTech server\n"
        "  --auth-password-file=<path> Path to file containing the authentication password\n"
        "  --skip-auth-check           Skip authentication (for development only)\n"
        "\n"
        "Server options (compatible with --serve/-s):\n"
        "  --document-root=<path>      Root folder of the web content\n"
        "  --http-addr=<addr>          Local interface the HTTP server will listen on\n"
        "                              Optional. Default value is 127.0.0.1\n"
        "  --http-port=<port>          Port number the HTTP server will listen on\n"
        "                              Optional. Default value is 8080\n"
        "                              Required for PUT/DELETE requests. Password must be\n"
        "                              at least 32 characters.\n"
        "  --https-enabled             Enables HTTPS\n"
        "  --acme-enabled              Enables the ACME client for automatic\n"
        "                              certificate management. Requires --https-enabled\n"
        "  --request-log-file          File where request logs will be written\n"
        "  --request-log-buffer        Size of the in-memory buffer of the request logger\n"
        "  --request-log-timeout       Interval in milliseconds between flushes of the\n"
        "                              request logger\n"
        "  --auth-log-file             File where authentication logs will be written\n"
        "  --auth-log-buffer           Size of the in-memory buffer of the authentication\n"
        "                              logger\n"
        "  --auth-log-timeout          Interval in milliseconds between flushes of the\n"
        "                              authentication logger\n"
        "\n"
        "The following flags must be used alongside --https-enabled:\n"
        "  --https-addr=<addr>         Local interface the HTTPS server will listen on\n"
        "                              Optional, the default value is 127.0.0.1\n"
        "  --https-port=<port>         Port number the HTTPS server will listen on\n"
        "                              Optional. Default value is 8443\n"
        "  --cert-file=<path>          x509 certificate file path\n"
        "  --cert-key-file=<path>      Private key file associate to the certificate\n"
        "                              file\n"
        "  --extra-cert=<domain>,<cert path>,<key path>\n"
        "                              Add an extra HTTPS certificate\n"
        "\n"
        "The following flags must be used alongside --acme-enabled:\n"
        "  --acme-key-file=<path>      File containing the ACME account private key\n"
        "                              Optional. Default value is acme_key.pem\n"
        "  --acme-agree-tos            Agree to the CA's terms of service\n"
        "  --acme-url=<URL>            URL of the ACME server's directory endpoint\n"
        "                              Optional. Default value refers to Let's Encrypt\n"
        "  --acme-email=<str>          E-Mail address to be associated with the ACME\n"
        "                              account and any issued certificates\n"
        "  --acme-country=<str>        Country associated to any issued certificates\n"
        "  --acme-org=<str>            Organization associated to any issued certificates\n"
        "  --acme-domain=<str>         Domain to be certified. You can specify this\n"
        "                              option multiple times to certify multiple domains\n"
        "  --acme-log-file             File where ACME logs will be written\n"
        "  --acme-log-buffer           Size of the in-memory buffer of the ACME logger\n"
        "  --acme-log-timeout          Interval in milliseconds between flushes of the\n"
        "                              ACME logger\n"
        "\n"
        "Client Options (compatible with --get/-g, --put/-p, --delete):\n"
        "  --remote=<url>              The URL of the target website for the uploads\n"
        "  --verbose                   Write extra logs to stderr\n"
        "  --no-file                   Write response contents to stdout instead of files\n"
    );
}

int main(int argc, char **argv)
{
    if (have_flag(argc, argv, S("--serve")) || have_flag(argc, argv, S("-s")))
        return main_server(argc, argv);

    if (have_flag(argc, argv, S("--get")) || have_flag(argc, argv, S("-g")) ||
        have_flag(argc, argv, S("--put")) || have_flag(argc, argv, S("-p")) ||
        have_flag(argc, argv, S("--delete")))
        return main_client(argc, argv);

    if (have_flag(argc, argv, S("--help")) || have_flag(argc, argv, S("-h"))) {
        print_usage(stdout, argv[0]);
        return 0;
    }
    print_usage(stderr, argv[0]);
    return -1;
}
