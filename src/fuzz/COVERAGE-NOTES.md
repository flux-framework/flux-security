# AFL++ Coverage Analysis Notes

## Expected Coverage Ranges

The AFL++ bitmap coverage percentage can be misleading because it's
measured against ALL instrumented code in the linked libraries, not
just the target code.

### What Gets Instrumented

When you link against:
- `libflux-security.la` (~4000 edges)
- `libutil.la` (~200 edges)
- `libtomlc99.la` (~100 edges)
- Plus dependencies (jansson, libsodium, etc.)

**Total: ~4,300-4,500 instrumented edges**

### Parser-Only Fuzzing (NOVERIFY)

**fuzz_sign_unwrap_noverify**: Expect **3-5% coverage**
- Exercises: Base64 decode, KV parse, format validation
- Skips: Signature verification, crypto operations
- This is CORRECT - we're testing 150-200 edges of parsing code
- Map size: ~4,346 instrumented edges (all linked libraries)

### Full Verification Fuzzing

**fuzz_sign_unwrap**: Expect **3-5% coverage with "none" mechanism**
- With "none": Same as noverify (3.61% observed)
- With curve/munge + valid keys: 10-15% (includes crypto
  operations)
- Default config uses "none" for simplicity
- Map size: ~4,346 instrumented edges

### KV Format Fuzzing

**fuzz_kv**: Expect **10-15% coverage**
- Exercises: Pure KV parser (13.31% observed)
- Higher % because smaller map size: only ~511 instrumented edges
- Links only libutil.la, not full security stack
- Focused target with minimal dependencies

## Troubleshooting Low Coverage (<1%)

If you see coverage below 1%, something is wrong:

### 1. Config Not Loading (MOST COMMON)
**Symptom**: Coverage 0.5-0.7%, corpus doesn't grow
**Cause**: `flux_security_configure()` failing silently
**Fix**: Harnesses now auto-detect config in multiple locations

**Verify**:
```bash
# Should find config automatically
./src/fuzz/fuzz_sign_unwrap_noverify < /dev/null
# Should exit 0 or 1, NOT print "FATAL: Could not load config"

# If it fails, try:
FUZZ_CONFIG_PATH="src/fuzz/conf.d/*.toml" \
    ./src/fuzz/fuzz_sign_unwrap_noverify < /dev/null
```

### 2. Corpus Too Similar
**Symptom**: Coverage plateaus quickly, low path diversity
**Solution**: Generate better seed corpus with
`scripts/generate-fuzz-corpus.sh`

### 3. AFL Not Instrumenting
**Symptom**: AFL complains "no instrumentation detected"
**Solution**: Rebuild with `CC=afl-clang-fast`

## Improving Coverage

### 1. Test All Mechanisms
Create seeds for curve and munge mechanisms (requires
infrastructure):
```bash
# Generate real signed payloads
flux-security-sign-tool --mech=curve input.txt > \
    corpus/curve-001.txt
flux-security-sign-tool --mech=munge input.txt > \
    corpus/munge-001.txt
```

### 2. Use Full Verification Harness
```bash
# Higher coverage but slower
afl-fuzz -i corpus/sign-none -o findings -- \
    src/fuzz/fuzz_sign_unwrap
```

### 3. Dictionary-Based Fuzzing
Create `sign.dict`:
```
"."
".."
"..."
"version"
"mechanism"
"userid"
"none"
"curve"
"munge"
```

Run with: `afl-fuzz -x sign.dict ...`

### 4. Combine Multiple Harnesses
Run all three in parallel for comprehensive coverage.

## Interpreting Results

**Good fuzzing run**:
- Coverage: 3-15% (depending on harness)
- Corpus grows steadily for first 1-2 hours
- Plateaus after 12-24 hours
- Path discovery continues occasionally

**Problem indicators**:
- Coverage < 1%
- Corpus = initial size (no growth)
- Very high exec/sec (>500k) with no discoveries
- AFL reports "no new paths in 24h" within first hour

## Coverage vs. Security

**Important**: Coverage percentage ≠ security thoroughness

- 5% coverage of a parser = 100% of that parser's code
- The other 95% is unrelated functionality
- Quality of inputs matters more than coverage %
- Edge cases and malformed inputs are what find bugs

Focus on:
1. ✅ Corpus growth (new paths discovered)
2. ✅ Crashes found
3. ✅ Execution speed (>100k/sec)
4. ⚠️ Coverage % (informational only)
