# BlogTech

BlogTech is a static file server and file upload utiliy for easy website management. It supports authenticated PUT/DELETE requests, automatic HTTPS certificate generation via the built-in ACME client.

## Quick Start

If you are on Linux, you'll need OpenSSL and gcc to be installed on your machine. You can install them by running:

```sh
# Ubuntu/Debian
sudo apt install libssl-dev gcc
```

Now we can build BlogTech:

```sh
# Linux
./build.sh

# Windows
.\build.bat
```

You should find the `blogtech` (or `blogtech.exe`) executable in the local directory.

Let's make a password file:

```sh
# Linux
echo "Super secret password" > admin.pwd

# Windows
"Super secret password" | Out-File admin.pwd
```

We then make a directory for all our web pages and run the server:

```sh

mkdir docroot

# Linux
./blogtech --serve --document-root=docroot --auth-password-file=admin.pwd

# Windows
.\blogtech.exe --serve --document-root=docroot --auth-password-file=admin.pwd
```

You can visit the website at `http://127.0.0.1:8080/` but we haven't added any files yet.

Let's create the first file of our website:

```sh
# Linux
echo "<b>Hello, world</b>" > index.html

# Windows
"<b>Hello, world</b>" | Out-File index.html
```

Note how we didn't create it into the document root of our server. That's because we are going to upload it there over HTTP! We can do so using blogtech itself running in upload mode:

```sh
# Linux
./blogtech --upload --auth-password-file=admin.pwd --remote=http://127.0.0.1:8080 index.html

# Windows
.\blogtech.exe --upload --auth-password-file=admin.pwd --remote=http://127.0.0.1:8080 index.html
```

You should now find the text "<b>Hello, world!</b>" when visiting `http://127.0.0.1:8080/`!

By the way, that's a lot of parameters! Let's move them to a blogtech.conf file:

```
document-root      docroot
auth-password-file admin.pwd
remote             http://127.0.0.1:8080
```

`blogtech` will automatically use parameters from a `blogtech.conf` file if present in the current directory. If you want ignore it, pass `--no-config`, and if you want a different configuration file pass `--config=<path>`. Also, note that `-s` and `-u` are shorthands for `--serve` and `--upload`, which means we can now do:

```sh
# Start the server
./blogtech -s

# Upload a file
./blogtech -u index.html
```

## Enabling HTTPS

Let's continue our guide by enabling HTTPS. Note that this is only available on Linux. Windows builds will only be able to serve plaintext HTTP traffic.

In production you'll have your own certificate issued by a certification authority (CA). Since we are just trying things out we can use a simple self-signed certificate:

```sh
openssl genpkey -algorithm RSA -out key.pem -pkeyopt rsa_keygen_bits:2048
openssl req -new -x509 -key key.pem -out cert.pem -days 365
```

Now start the server in HTTPS mode:

```sh
./blogtech --serve --https-enabled=yes --cert-file=cert.pem --cert-key-file=key.pem --document-root=docroot
```

Done! You should be able to see `index.html` over HTTPS now by visiting `https://127.0.0.1/index.html`.

## Enabling ACME for automatic certificate generation

The self-signed certificate won't work in production. As I mentioned, we need a properly signed certificate issued by a certification authority like [Let's Encrypt](https://letsencrypt.org/). BlogTech is able to talk to a CA that implements the ACME protocol to automatically generate a certificate.

For this to work, you'll need to configure BlogTech to handle HTTP traffic on port 80 and set the following options:
```
--acme-enabled --acme-agree-tos --acme-country=<country code> --acme-org=<organization name> --acme-email=<your email> --acme-domain=example.com
```
These should be set alongside the HTTPS options (but you can start the server without a certificate or key file). Also make sure the server is reachable at the given domain from the public internet.

The next time you run `blogtech`, the file `acme_key.pem` will be generated and the certificate and certificate key specified alongside the HTTPS options will be generated too. From that point on, the server will be available over HTTPS. Note that you don't need to restart BlogTech during this process.
