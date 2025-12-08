all:
	gcc $(shell find src -name "*.c") -o blogtech -lcrypto -lssl -I3p -Isrc -ggdb -DHTTPS_ENABLED -lssl -lcrypto
