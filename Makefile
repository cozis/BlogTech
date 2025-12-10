LINUX_FLAGS = -DHTTPS_ENABLED -lssl -lcrypto
WINDOWS_FLAGS = -lws2_32 -lbcrypt

all:
	gcc $(shell find src -name "*.c") -o blogtech -I3p -Isrc -ggdb -funwind-tables $(WINDOWS_FLAGS)
