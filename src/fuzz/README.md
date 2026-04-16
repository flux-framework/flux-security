# AFL++ Fuzzing Harnesses

Fuzzing harnesses for security-critical parsers that process user data
in privileged contexts.

## Overview

flux-security processes user-controlled data in privileged contexts
(IMP privilege separation). Parser bugs could lead to privilege
escalation. Fuzzing targets:

1. **`flux_sign_unwrap()`** - Parses `HEADER.PAYLOAD.SIGNATURE` format
   in privileged IMP parent
2. **`kv_decode()`** - Parses privsep pipe communication
3. **`cf_update()`** - Parses TOML configuration files for IMP

## Quick Start

```bash
# 1. Install AFL++
git clone https://github.com/AFLplusplus/AFLplusplus
cd AFLplusplus && make && sudo make install

# 2. Build with AFL
cd flux-security
CC=afl-clang-fast ./configure --enable-fuzzing
make

# 3. Start all fuzzers (auto-generates corpus if missing)
./scripts/fuzz.py start

# 4. Monitor progress
./scripts/fuzz.py watch
```

## Fuzzing Harnesses

### fuzz_sign_unwrap_noverify (PRIMARY)
- **Target**: Sign/unwrap parser without crypto overhead
- **Speed**: ~180k execs/sec
- **Priority**: Run this first and longest
- **Attack Surface**: Base64 decoding, header parsing, payload extraction

### fuzz_kv
- **Target**: KV format parser (privsep communication)
- **Speed**: ~200k execs/sec
- **Priority**: High - direct privilege boundary
- **Attack Surface**: Key-value parsing, type handling, buffer boundaries

### fuzz_sign_unwrap
- **Target**: Full sign/unwrap with signature verification
- **Speed**: ~20-50k execs/sec (slower due to crypto)
- **Priority**: Medium - tests crypto integration
- **Attack Surface**: Full signature verification flow, mechanism handling

### fuzz_cf
- **Target**: Configuration (cf) interface for TOML parsing
- **Speed**: ~100-150k execs/sec
- **Priority**: High - IMP config parsing is security-critical
- **Attack Surface**: TOML parsing, schema validation, type coercion, pattern matching

## Parallel Fuzzing

The `fuzz.py` tool automatically starts 4 fuzzers in parallel:

```bash
# Start all fuzzers in a single tmux session
./scripts/fuzz.py start

# Attach to tmux session to see fuzzer output
tmux attach -t fuzzing

# Switch between fuzzer windows: Ctrl+b then 0/1/2/3
# Detach from tmux: Ctrl+b then d

# Stop all fuzzers
./scripts/fuzz.py stop
```

## Monitoring Progress

```bash
# Live dashboard (refreshes every 5 seconds)
./scripts/fuzz.py watch

# Check progress with AFL's tool
afl-whatsup findings/

# View crashes and hangs
ls findings/*/crashes/
ls findings/*/hangs/
```

## Coverage Expectations

AFL reports coverage as % of ALL instrumented code (including
libraries). Expected ranges:

- **fuzz_sign_unwrap_noverify**: 3-5% (parser code only,
  ~4,346 edge map)
- **fuzz_sign_unwrap**: 3-5% with "none" mechanism; 10-15% with
  curve/munge
- **fuzz_kv**: 10-15% (smaller ~511 edge map = higher %)

**⚠️ If coverage is <1%, config may not be loading!** Check that
`conf.d/sign.toml` exists and is readable. Set `FUZZ_CONFIG_PATH`
to override the default location.

## Crash Triage

When crashes are found, use the interactive triage tool:

```bash
# Interactive crash triage
./scripts/fuzz.py triage

# Triage crashes from alternate findings directory
./scripts/fuzz.py triage --findings-dir findings-alternate
```

The triage tool provides options to:
1. Quick test all crashes (identifies which still reproduce)
2. Full triage with ASAN/UBSAN (detailed error reports)
3. View crash inputs (hexdump)

### Manual Crash Reproduction

```bash
# Reproduce a specific crash (FUZZ_DEBUG=1 shows error output)
FUZZ_DEBUG=1 src/fuzz/fuzz_sign_unwrap_noverify < \
    findings/fuzzer01/crashes/id:000000...

# With full sanitizer output
FUZZ_DEBUG=1 \
ASAN_OPTIONS=symbolize=1:abort_on_error=0 \
UBSAN_OPTIONS=print_stacktrace=1:symbolize=1 \
    src/fuzz/fuzz_sign_unwrap_noverify < crash_file
```

**Note**: Always use `FUZZ_DEBUG=1` when debugging crashes. This
prevents the harness from closing stderr, allowing you to see ASAN
reports and error messages.

### Understanding Signal Codes

Crash filenames include signal codes:
- `sig:06` = SIGABRT (assertion failure / abort)
- `sig:11` = SIGSEGV (segmentation fault / null pointer)
- `sig:05` = SIGTRAP (UBSAN/ASAN caught an error)
- `sig:04` = SIGILL (illegal instruction)
- `sig:08` = SIGFPE (floating point exception)

### Minimizing Crashes

```bash
# Make crash input smaller for easier analysis
afl-tmin -i crash_file -o minimized.txt -- \
    ./src/fuzz/fuzz_sign_unwrap_noverify
```

## Interpreting Results

### When to Stop Fuzzing

**Stop fuzzing when:**
- No new paths discovered in 24+ hours
- Corpus size stabilizes for 12+ hours
- Coverage plateau reached

**Before release:**
- Run for minimum 48 hours
- Must find 0 crashes
- Review all hangs

### Expected Bugs

Fuzzing is designed to catch:
- Buffer overflows in base64 decoder
- Integer overflows in size calculations  
- Format string bugs in error handling
- Invalid KV format handling
- Header validation bypass
- NULL pointer dereferences
- Use-after-free

## Security Notes

### Input Size Limits
All harnesses limit input to 1MB to prevent memory exhaustion attacks
during fuzzing.

### Configuration
Harnesses require `conf.d/sign.toml` for initialization. Set
`FUZZ_CONFIG_PATH` environment variable to override default location.

### Sanitizers
Build with `--enable-sanitizers` for better bug detection:
```bash
CC=afl-clang-fast \
CFLAGS="-fsanitize=address -fsanitize=undefined" \
./configure --enable-fuzzing --enable-sanitizers
```

**Note**: AFL++ and ASAN can conflict on some kernels (OrbStack),
producing false-positive SIGTRAP crashes. Test suspected crashes in
an ASAN-only build (without AFL) to verify.

## Integration

For continuous fuzzing, consider:

### ClusterFuzzLite
GitHub Actions integration for PR fuzzing and batch fuzzing:
- [ClusterFuzzLite](https://github.com/google/clusterfuzzlite)
- Run fuzzing on every PR (5-10 min)
- Nightly batch fuzzing (6+ hours)

### OSS-Fuzz
Long-running continuous fuzzing infrastructure:
- [OSS-Fuzz](https://github.com/google/oss-fuzz) submission
- Free for open source projects
- Runs 24/7 with dedicated resources
- Automatic bug reporting

### CI/CD Integration
```bash
# Quick smoke test (5 minutes) - run on every PR
make -C src/fuzz smoke-test

# Full campaign (12-24 hours) - run nightly
make -C src/fuzz fuzz-all
```

## References

- [AFL++ Documentation](https://aflplus.plus/)
- [Fuzzing at Scale (Google)](https://security.googleblog.com/2016/08/guided-in-process-fuzzing-of-chrome.html)
- [ClusterFuzzLite](https://github.com/google/clusterfuzzlite)
- [OSS-Fuzz](https://google.github.io/oss-fuzz/)
