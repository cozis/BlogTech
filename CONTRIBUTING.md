# Testing the ACME client

Requires: Linux, Docker

You need to download the [Pebble ACME server](https://github.com/letsencrypt/pebble).

Then, modify the `docker-compose.yml` file to add the following lines:

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

Then, add the following lines to the `/etc/hosts` file:

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
