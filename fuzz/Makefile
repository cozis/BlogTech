# Fuzzing Makefile for blogtech parsers
#
# Build targets:
#   make libfuzzer      - Build with libFuzzer (requires clang with runtime)
#   make afl            - Build with AFL++ support
#   make standalone     - Build standalone test binaries (with sanitizers)
#   make standalone-plain - Build standalone without sanitizers (always works)
#   make asan           - Build with AddressSanitizer only (no fuzzing)
#   make clean          - Remove built artifacts

# Use gcc by default since it has better sanitizer support on most systems
CC ?= gcc
AFL_CC ?= afl-clang-fast

# Common flags
CFLAGS_COMMON = -g -O1 -I../src/lib

# libFuzzer flags
CFLAGS_LIBFUZZER = $(CFLAGS_COMMON) -fsanitize=fuzzer,address,undefined

# AFL flags
CFLAGS_AFL = $(CFLAGS_COMMON) -fsanitize=address,undefined

# Standalone flags (for manual testing)
CFLAGS_STANDALONE = $(CFLAGS_COMMON) -fsanitize=address,undefined -DSTANDALONE

# Standalone flags without sanitizers (always works)
CFLAGS_STANDALONE_PLAIN = $(CFLAGS_COMMON) -DSTANDALONE

# ASAN-only flags
CFLAGS_ASAN = $(CFLAGS_COMMON) -fsanitize=address,undefined

FUZZERS = fuzz_json fuzz_http fuzz_config

.PHONY: all libfuzzer afl standalone standalone-plain asan clean corpus run-json run-http run-config

all: libfuzzer

# Build with libFuzzer
libfuzzer: $(addsuffix _libfuzzer,$(FUZZERS))

fuzz_json_libfuzzer: fuzz_json.c
	$(CC) $(CFLAGS_LIBFUZZER) $< -o $@

fuzz_http_libfuzzer: fuzz_http.c
	$(CC) $(CFLAGS_LIBFUZZER) $< -o $@

fuzz_config_libfuzzer: fuzz_config.c
	$(CC) $(CFLAGS_LIBFUZZER) $< -o $@

# Build with AFL++
afl: $(addsuffix _afl,$(FUZZERS))

fuzz_json_afl: fuzz_json.c
	$(AFL_CC) $(CFLAGS_AFL) $< -o $@

fuzz_http_afl: fuzz_http.c
	$(AFL_CC) $(CFLAGS_AFL) $< -o $@

fuzz_config_afl: fuzz_config.c
	$(AFL_CC) $(CFLAGS_AFL) $< -o $@

# Build standalone test binaries
standalone: $(addsuffix _standalone,$(FUZZERS))

fuzz_json_standalone: fuzz_json.c
	$(CC) $(CFLAGS_STANDALONE) $< -o $@

fuzz_http_standalone: fuzz_http.c
	$(CC) $(CFLAGS_STANDALONE) $< -o $@

fuzz_config_standalone: fuzz_config.c
	$(CC) $(CFLAGS_STANDALONE) $< -o $@

# Build standalone without sanitizers (fallback if sanitizers unavailable)
# NOTE: Using sanitizers is strongly recommended for fuzzing!
standalone-plain: $(addsuffix _plain,$(FUZZERS))

fuzz_json_plain: fuzz_json.c
	$(CC) $(CFLAGS_STANDALONE_PLAIN) $< -o $@

fuzz_http_plain: fuzz_http.c
	$(CC) $(CFLAGS_STANDALONE_PLAIN) $< -o $@

fuzz_config_plain: fuzz_config.c
	$(CC) $(CFLAGS_STANDALONE_PLAIN) $< -o $@

# Build ASAN-only (for testing without fuzzing)
asan: $(addsuffix _asan,$(FUZZERS))

fuzz_json_asan: fuzz_json.c
	$(CC) $(CFLAGS_ASAN) -DSTANDALONE $< -o $@

fuzz_http_asan: fuzz_http.c
	$(CC) $(CFLAGS_ASAN) -DSTANDALONE $< -o $@

fuzz_config_asan: fuzz_config.c
	$(CC) $(CFLAGS_ASAN) -DSTANDALONE $< -o $@

# Create corpus directories and seed files
corpus:
	mkdir -p corpus_json corpus_http corpus_config
	# JSON seeds
	echo '{}' > corpus_json/empty_object.json
	echo '[]' > corpus_json/empty_array.json
	echo 'null' > corpus_json/null.json
	echo 'true' > corpus_json/true.json
	echo 'false' > corpus_json/false.json
	echo '0' > corpus_json/zero.json
	echo '-1' > corpus_json/neg_one.json
	echo '3.14' > corpus_json/float.json
	echo '"hello"' > corpus_json/string.json
	echo '{"key": "value"}' > corpus_json/simple_object.json
	echo '[1, 2, 3]' > corpus_json/simple_array.json
	echo '{"a": {"b": {"c": 1}}}' > corpus_json/nested.json
	echo '{"arr": [1, "two", true, null]}' > corpus_json/mixed.json
	echo '"escape\\n\\t\\r"' > corpus_json/escapes.json
	# HTTP seeds
	printf 'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n' > corpus_http/get_request.txt
	printf 'POST /api HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 0\r\n\r\n' > corpus_http/post_request.txt
	printf 'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n' > corpus_http/response_200.txt
	printf 'HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n' > corpus_http/response_404.txt
	printf 'GET /path?query=value HTTP/1.1\r\nHost: test.com\r\n\r\n' > corpus_http/with_query.txt
	printf 'GET http://example.com/path HTTP/1.1\r\nHost: example.com\r\n\r\n' > corpus_http/absolute_uri.txt
	printf 'CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n' > corpus_http/connect.txt
	printf 'OPTIONS * HTTP/1.1\r\nHost: example.com\r\n\r\n' > corpus_http/options_star.txt
	# Config seeds
	printf 'port 8080\n' > corpus_config/simple.conf
	printf '# comment\nhost localhost\n' > corpus_config/with_comment.conf
	printf 'port 443\nssl yes\n' > corpus_config/multiple.conf
	printf 'timeout 30000\nbuffer_size 65536\n' > corpus_config/numbers.conf
	printf 'cert domain.com, cert.pem, key.pem\n' > corpus_config/extra_cert.conf
	printf 'option ---\n' > corpus_config/empty_value.conf
	@echo "Corpus directories created with seed inputs"

# Run fuzzers (libFuzzer)
run-json: fuzz_json_libfuzzer corpus
	./fuzz_json_libfuzzer corpus_json/ -max_len=65536

run-http: fuzz_http_libfuzzer corpus
	./fuzz_http_libfuzzer corpus_http/ -max_len=65536

run-config: fuzz_config_libfuzzer corpus
	./fuzz_config_libfuzzer corpus_config/ -max_len=65536

# Clean build artifacts
clean:
	rm -f *_libfuzzer *_afl *_standalone *_plain *_asan
	rm -rf corpus_json corpus_http corpus_config
	rm -rf crash-* leak-* timeout-* oom-*

# Help target
help:
	@echo "Fuzzing Makefile for blogtech parsers"
	@echo ""
	@echo "Targets:"
	@echo "  libfuzzer       - Build with libFuzzer (requires clang with runtime)"
	@echo "  afl             - Build with AFL++ support"
	@echo "  standalone      - Build standalone test binaries (with ASAN/UBSAN)"
	@echo "  standalone-plain- Build standalone without sanitizers"
	@echo "  asan            - Build with AddressSanitizer only"
	@echo "  corpus          - Create seed corpus directories"
	@echo "  run-json        - Run JSON fuzzer with libFuzzer"
	@echo "  run-http        - Run HTTP fuzzer with libFuzzer"
	@echo "  run-config      - Run config fuzzer with libFuzzer"
	@echo "  clean           - Remove all built artifacts"
	@echo ""
	@echo "Examples:"
	@echo "  # Quick test with sanitizers (recommended):"
	@echo "  CC=gcc make standalone && make corpus"
	@echo "  for f in corpus_json/*; do ./fuzz_json_standalone \$$f; done"
	@echo ""
	@echo "  # libFuzzer continuous fuzzing:"
	@echo "  CC=clang make libfuzzer && make run-json"
	@echo ""
	@echo "  # AFL++ fuzzing:"
	@echo "  make afl && afl-fuzz -i corpus_json -o findings ./fuzz_json_afl"
