# BlogTech
BlogTech is a toolkit for managing small to medium websites. It supports HTTPS, virtual hosts, automatic certificate management (via ACME) and a client for remote management of the server.

⚠️ BlogTech is still in development! ⚠️

(If you are coming for the old, single-file version of BlogTech refer to the single_file branch.)

## Table of Contents
- [Quick Start](#quick-start)
- [Authentication](#authentication)
- [Virtual Hosts](#virtual-hosts)
- [Enabling HTTPS](#enabling-https)
- [Enabling ACME](#enabling-acme)
- [Testing the ACME Client](#testing-the-acme-client)
- [Configuration Files](#configuration-files)
- [Crash Logger](#crash-logger)

## Quick Start

BlogTech runs on Linux and Windows (with limitations, see the HTTPS section). To compile it on Linux, you need to install the OpenSSL development library:

```sh
# Ubuntu/Debian
sudo apt install libssl-dev gcc
```

To compile on Windows, you need to install clang.

Once you're done installing, you can build BlogTech by running

```sh
# Linux
./build.sh

# Windows
.\build.bat
```

This will create the `blogtech` (Linux) or `blogtech.exe` (Windows) executable.

You can start a BlogTech server by running:

```sh
mkdir docroot

# Linux
./blogtech --serve --document-root=docroot --skip-auth-check

# Windows
.\blogtech.exe --serve --document-root=docroot --skip-auth-check
```

This will start an HTTP server listening on `127.0.0.1:8080` and serving content from the `docroot` directory (which, is still empty).

You can view the website by opening a web browser and visiting `http://127.0.0.1:8080/`. Of course you will get a code 404 since there is nothing there yet!

So let's upload a file! Open a second terminal (to keep the server running) and create an HTML file by running the following:

```sh
# Linux
echo "<b>Hello, world</b>" > index.html

# Windows
"<b>Hello, world</b>" | Out-File index.html
```

Now you can use BlogTech in "client mode" to upload the file

```sh
# Linux
./blogtech --upload --remote=http://127.0.0.1:8080 index.html

# Windows
.\blogtech.exe --upload --remote=http://127.0.0.1:8080 index.html
```

You should now find the text "<b>Hello, world</b>" when visiting `http://127.0.0.1:8080/`!

Note that even though we ran client and server on the same machine, this would have worked the same if the server was running on a remote machine.

## Authentication

### Authentication Options

Requests that would modify resources on the server are digitally signed using an HMAC/SHA256 signature. For this to work, client and server must share the same secret key, which is by convention stored in a `admin.pwd` file.

The password is specified using the `--auth-password-file` option:
```sh
./blogtech --serve  --auth-password-file=admin.pwd --document-root=docroot
./blogtech --upload --auth-password-file=admin.pwd --remote=http://127.0.0.1:8080 index.html

# (Use .\blogtech.exe if you are Windows)
```

Without a password file, all requests that would require authentication will be rejected. Also, empty passwords will be rejected.

During development, it's useful to allow all requests to be automatically be regarded as authenticated. You can do so with the `--skip-auth-check`, in which case the `--auth-password-file` option will be ignored if present. Of course you should use this with caution!

### Authentication Headers
An authenticated HTTP request looks like this:
```
PUT /index.html HTTP/1.1\r\n
Host: 127.0.0.1:8080\r\n
Connection: Close\r\n
Content-Length: 22\r\n
X-BlogTech-Nonce: 80I5x5gfNC6yVTigxGf8xMDt+iVg3Nl6gjBi9Z4gaqE=\r\n
X-BlogTech-Timestamp: 1765730409\r\n
X-BlogTech-Expire: 300\r\n
X-BlogTech-Signature: S1jP/V6lTXqdjr2Mfk0N2C+0bCNsOxscifrUtRgJCw0=\r\n
\r\n
I'm a signed request!\n
```

The `X-BlogTech-` headers ensure that the request was not forged or used in a replay attack. More specifically:

* `X-BlogTech-Nonce` contains a token chosen at random by the client
* `X-BlogTech-Timestamp` contains the UNIX timestamp of when the request was first signed
* `X-BlogTech-Expire` contains the number of seconds the request is valid from the time it is signed
* `X-BlogTech-Signature` contains the Base64-encoded HMAC of the request information.

The signature is obtained by calculating the canonical version of the request string:
```
<method>\n
<path>\n
<host>\n
<unix time>\n
<expiration seconds>\n
<nonce>\n
<content length>\n
<SHA256 hash of the payload encoded as hex>\n
```
And calculating its HMAC/SHA256 using the authentication password as key. The result is then Base64-encoded (with padding).

Note that the nonces previously seen by the server are stored in-memory. This means that if the server reloads it will forget all previously seen nonces. This allows requests that are not expired to be replayed.

## Virtual Hosts

BlogTech allows you to host multiple websites on the same server. For this to work you just need to specify the domain names using the `--domain` option:

```sh
./blogtech --serve --document-root=docroot --domain=websiteA.com --domain=websiteB.com
```

BlogTech will then generate a directory per domain inside the document root

```
docroot
  default
  websiteA.com
  websiteB.com
```

Requests directed to a host will refer to the directory associated to that host. If a request isn't associated to a specific folder, it refers to the default one.

For instance, the following commands
```
./blogtech --upload --remote=http://websiteA.com file1.html
./blogtech --upload --remote=http://websiteB.com file2.html
./blogtech --upload --remote=http://other.com file3.html
```

Will store the files as:

```
docroot/websiteA/file1.html
docroot/websiteB/file2.html
docroot/default/file3.html
```


## Enabling HTTPS

HTTPS is only supported on Linux as the underlying HTTP library [cHTTP](https://github.com/cozis/cHTTP) implements HTTPS using OpenSSL. If you are on Windows, only HTTP is available for both client and servers.

To enable HTTPS, you need use the `--https-enabled` flag and load the certificate and private key using the `--cert-file` and `--cert-key-file` options.
```sh
./blogtech --serve --https-enabled --cert-file=cert.pem --cert-key-file=key.pem
```
By default, the server will listen on `127.0.0.1:8443`, but you can change this using the `--https-addr=<addr>` and `--https-port=<port>` flags.

If you're not familiar with this process, the certificate is usually issued by a Certificate Authority (such as Let's Encrypt) after demonstrating the you own a domain. During development, it's useful to use a self-signed certificate, which can be generated with the following commands:

```sh
openssl genpkey -algorithm RSA -out key.pem -pkeyopt rsa_keygen_bits:2048
openssl req -new -x509 -key key.pem -out cert.pem -days 365
```

Note that browser won't allow you to navigate to HTTPS servers that use self-signed certificates, while cURL only allows you to do so with the `--insecure` flag.

If you happen to need more than one certificate, you can pass additional certificates using the `--extra-cert` option:

```sh
./blogtech --serve --https-enabled --cert-file=cert1.pem --cert-key-file=key1.pem --extra-cert=domain2.com,cert2.pem,key2.pem --extra-cert=domain3.com,cert3.pem,key3.pem
```

The certificate provided using the `--cert-file` and `--cert-key` options is served to clients by default, while the extra certificates are used when clients ask for specific domains (`domain2.com` and `domain3.com` in the example).

(Note: the command is quite long, but you can move command-line options to a configuration file)

## Enabling ACME

The ACME protocol allows web servers to automatically request certificate authorities to issue a certificate. You can basically start the server in HTTPS mode without a certificate, and a couple seconds later.. there is the certificate!! It's pretty magic if you ask me.

If you're running this in production, be sure to:
- Run the HTTP server on port 80
- Create a DNS record that associated the domain the machine running the server
If you want to run the ACME client locally, refer to the [Testing the ACME client](#testing-the-acme-client) section to run an ACME server locally.

Enable ACME using the `--acme-enabled` flag alongside the HTTPS flags. Unlike regular HTTPS mode, the server expects the certificate not to exist. You also need to provide some values required to compile the certificate, such as the domain to certify, email, country code, organization name, and that you agree to the CA's terms of service:

```sh
./blogtech --serve --https-enabled --cert-file=cert.pem --cert-key-file=key.pem --acme-enabled --acme-domain=example.com --acme-email=your@email.com --acme-country=IT --acme-organization=me --acme-agree-tos
```

(Note: the command is quite long, but you can move command-line options to a configuration file)

If all goes well, you should find that the following files are generated:
- `acme_key.pem`: The secret key associated to the ACME account
- `cert.pem` (or whatever you pass to `--cert-file`): The issued certificate
- `key.pem` (or whatever you pass to `--cert-key-file`): The private key associated to the certificate

If anything goes wrong, error messages are logged to the `acme.log` file.

Note that you can let ACME handle multiple domains by simply passing multiple `--acme-domain` options. The resulting certificate will include all domains.

## Testing the ACME client

To test the ACME client on Linux you will need to install Docker and clone the [Pebble ACME server](https://github.com/letsencrypt/pebble).

Modify the `docker-compose.yml` file to add the following lines:

```dockerfile
version: "3"
services:
  pebble:
    image: ghcr.io/letsencrypt/pebble:latest
    command: -config test/config/pebble-config.json -strict
    ports:
      - 14000:14000 # HTTPS ACME API
      - 15000:15000 # HTTPS Management API
    networks:
      acmenet:
        ipv4_address: 10.30.50.2
    extra_hosts:
      - "local-test-websiteA.com:host-gateway"  <--- These ones
      - "local-test-websiteB.com:host-gateway"  <---
      - "local-test-websiteC.com:host-gateway"  <---
 ...
```

And add the following lines to the `/etc/hosts` file:

```
127.0.0.1 local-test-websiteA.com
127.0.0.1 local-test-websiteB.com
127.0.0.1 local-test-websiteC.com
```

Now you can start the ACME server by running

```sh
cd pebble
docker compose up
```

You can then start the BlogTech instance by running:

```sh
./blogtech -s --config=misc/pebble_blogtech.conf
```

You should see al interactions with the ACME server being dumped by BlogTech on stdout and, if all goes well, the `acme_key.pem`, `cert.pem` and `key.pem` generated.

If you want to test certificate renewal, you can change the expirations by modifying these fields in `pebble/test/config/pebble-config.json`:

```
{
  "pebble": {

    ... other fields ...

    "profiles": {
      "default": {
        "description": "The profile you know and love",
        "validityPeriod": 7776000 <--- This one
      },
      "shortlived": {
        "description": "A short-lived cert profile, without actual enforcement",
        "validityPeriod": 518400 <--- And this one
      }
    }
  }
}
```

## Configuration Files

BlogTech allows you to move any number of command-line arguments to a configuration file.

Say you have the following very verbose command:

```sh
./blogtech --serve --https-enabled --cert-file=cert.pem --cert-key-file=key.pem --acme-enabled --acme-domain=example.com --acme-email=your@email.com --acme-country=IT --acme-organization=me --acme-agree-tos
```

You can run the same command by creating the following `blogtech_server.conf` file

```
https-enabled     yes
cert-file         cert.pem
cert-key-file     key.pem
acme-enabled      yes
acme-domain       example.com
acme-email        your@email.com
acme-country      IT
acme-organization me
acme-agree-tos    yes
```

and running BlogTech as:

```sh
./blogtech --serve --config=blogtech_server.conf
```

BlogTech will automatically load a configuration file if named exactly `blogtech.conf`, which means you can do simply:

```sh
./blogtech --serve
```

If you want to ignore the implicit config file, use the `--no-config` flag:

```sh
./blogtech --serve --no-config
```

## Crash Logger

When BlogTech crashes while in server mode, it will generate `crash.bin`, a binary file with the location of the crash. The next time the server is started, the `crash.bin` file will be translated into `crash.log`, a human-readable stack trace. Note that the translation of addresses to symbol names/line numbers might be a bit wonky.