# Fuzzing Harnesses for blogtech Parsers

This directory contains fuzz testing harnesses for the parsing code in blogtech:

- `fuzz_json.c` - Fuzzes the JSON parser (`src/lib/json.c`)
- `fuzz_http.c` - Fuzzes the HTTP parser (`src/lib/chttp.c`)
- `fuzz_config.c` - Fuzzes the config file parser (`src/config_reader.c`)

## Building

### Prerequisites

For libFuzzer:
- Clang compiler with libFuzzer support

For AFL++:
- AFL++ installed (`apt install afl++` on Debian/Ubuntu)

### Build Commands

```bash
# Build with libFuzzer (requires clang)
make libfuzzer

# Build with AFL++ support
make afl

# Build standalone test binaries (for manual testing)
make standalone

# Build with ASAN only (for regression testing)
make asan
```

## Running

### Using libFuzzer

```bash
# Create seed corpus
make corpus

# Run JSON fuzzer
./fuzz_json_libfuzzer corpus_json/ -max_len=65536

# Run HTTP fuzzer
./fuzz_http_libfuzzer corpus_http/ -max_len=65536

# Run config fuzzer
./fuzz_config_libfuzzer corpus_config/ -max_len=65536
```

### Using AFL++

```bash
# Build AFL targets
make afl

# Create seed corpus
make corpus

# Run with AFL++
afl-fuzz -i corpus_json -o findings_json -- ./fuzz_json_afl
afl-fuzz -i corpus_http -o findings_http -- ./fuzz_http_afl
afl-fuzz -i corpus_config -o findings_config -- ./fuzz_config_afl
```

### Manual Testing

```bash
# Build standalone binaries
make standalone

# Test a specific input file
./fuzz_json_standalone test_input.json
./fuzz_http_standalone test_request.txt
./fuzz_config_standalone test_config.conf
```

## Analyzing Crashes

When a fuzzer finds a crash, it saves the input to a file like `crash-<hash>`.

To analyze:

```bash
# Reproduce with ASAN
./fuzz_json_standalone crash-abc123

# Get more details
ASAN_OPTIONS=symbolize=1 ./fuzz_json_standalone crash-abc123
```

## Coverage

To build with coverage:

```bash
clang -fsanitize=fuzzer,address -fprofile-instr-generate -fcoverage-mapping \
    fuzz_json.c -o fuzz_json_cov

./fuzz_json_cov corpus_json/ -runs=0
llvm-profdata merge -sparse default.profraw -o default.profdata
llvm-cov show ./fuzz_json_cov -instr-profile=default.profdata
```

## What's Being Tested

### JSON Parser (`fuzz_json.c`)
- `json_decode()` - Main parsing function
- `json_get_type()`, `json_get_bool()`, `json_get_int()`, etc. - Accessor functions
- `json_get_field()` - Object field lookup
- `json_match()` - Pattern matching (via `json_match_impl()`)

### HTTP Parser (`fuzz_http.c`)
- `chttp_parse_request()` - HTTP request parsing
- `chttp_parse_response()` - HTTP response parsing
- `chttp_parse_url()` - URL parsing
- `chttp_parse_ipv4()` - IPv4 address parsing
- `chttp_parse_ipv6()` - IPv6 address parsing
- Header parsing and validation

### Config Parser (`fuzz_config.c`)
- Config file tokenization
- Comment handling
- Value parsing (yes/no, ports, time intervals, buffer sizes)
- Extra certificate triplet parsing
