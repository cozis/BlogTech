# BlogTech
A minimal static file server with automatic HTTPS via ACME (Let's Encrypt), plus a client for uploading content.

## Building
Requires the OpenSSL development libraries
```sh
# Ubuntu/Debian
sudo apt install libssl-dev

# Then build
make
```
This produces a single `blogtech` binary.

## Quick Start

1. Create a directory for your web content:
```sh
mkdir docroot
echo "<h1>Hello, world!</h1>" > docroot/index.html
```

2. Start the server:
```sh
./blogtech --serve --document-root=docroot
```

3. Visit `http://localhost:8080/index.html`

## Usage

BlogTech operates in two modes: `server` mode and `upload` (client) mode.

### Server Mode
```sh
./blogtech --serve [options]
```
Or use `-s` as shorthand for `--serve`

### Upload Mode
```
./blogtech --upload --remote=http://your-server.com file1.html file2.html
```
Or use `-u` as shorthand for `--upload`. This PUTs each file to the remote server at the corresponding path.

## Configuration

Options can be specified via command line or configuration file. By default, BlogTech looks for `blogtech.conf` in the current directory
```
# Use a specific config file
./blogtech --serve --config=/path/to/config.conf

# Ignore default config file
./blogtech --serve --no-config
```

### Configuration File Format
```
# Lines starting with # are comments
# Use "---" for empty/unset values

document-root       /var/www/html
http-addr           0.0.0.0
http-port           8080
auth-password-file  /path/to/password.txt
```

## Authentication

PUT and DELETE requests require authentication. To enable authenticated uploads:

1. Create a password file with at least 32 characters:
```sh
openssl rand -base64 48 > password.txt
```

2. Configure the server to use it:
```sh
./blogtech --serve --document-root=docroot --auth-password-file=password.txt
```

Requests are authenticated using HMAC-SHA256 signatures. The client must include the following headers:
- `X-BlogTech-Timestamp`: Unix epoch seconds when the request was created
- `X-BlogTech-Expire`: Seconds until the request expires
- `X-BlogTech-Nonce`: Unique value to prevent replay attacks
- `X-BlogTech-Signature`: HMAC-SHA256 signature of the request

If no password file is configured or the password is shorter than 32 characters, all PUT/DELETE requests will be rejected.
