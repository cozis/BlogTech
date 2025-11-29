all:
	gcc 3p/chttp.c 3p/json.c src/file_system.c src/path.c src/jws.c src/acme.c src/auth.c src/main.c -o blogtech -lcrypto -lssl -I3p -Isrc -ggdb -DHTTPS_ENABLED -lssl -lcrypto
