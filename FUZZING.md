# Fuzzing flux-security

Complete fuzzing documentation is available in [src/fuzz/README.md](src/fuzz/README.md).

## Quick Start

```bash
# Install AFL++
git clone https://github.com/AFLplusplus/AFLplusplus
cd AFLplusplus && make && sudo make install

# Build and fuzz
cd flux-security
CC=afl-clang-fast ./configure --enable-fuzzing
make
./scripts/fuzz.py start  # Auto-generates corpus if missing

# Monitor progress
./scripts/fuzz.py watch

# Triage crashes
./scripts/fuzz.py triage
```

See [src/fuzz/README.md](src/fuzz/README.md) for:
- Detailed harness descriptions
- Coverage expectations
- Crash triage workflow
- Integration with CI/CD
- ClusterFuzzLite and OSS-Fuzz setup
