all:
	gcc 3p/chttp.c src/file_system.c src/path.c src/main.c -o blogtech -lcrypto -lssl -I3p -ggdb
