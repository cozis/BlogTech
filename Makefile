all:
	gcc src/chttp.c src/json.c src/file_system.c src/config.c src/path.c src/jws.c src/acme.c src/auth.c src/main.c -o blogtech -lcrypto -lssl -I3p -Isrc -ggdb -DHTTPS_ENABLED -lssl -lcrypto
