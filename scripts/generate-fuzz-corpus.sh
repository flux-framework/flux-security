#!/bin/bash
#
# Generate seed corpus for AFL fuzzing
#
# Usage: ./generate-fuzz-corpus.sh [corpus-dir]
#

set -e

CORPUS_DIR="${1:-corpus}"
mkdir -p "$CORPUS_DIR"/{sign-none,sign-curve,sign-munge,kv,toml}

echo "=== Generating fuzzing corpus ==="

# KV format examples (binary format: key\0Tvalue\0...)
echo "Creating KV format seeds..."
printf "key1\0svalue1\0" > "$CORPUS_DIR/kv/01-simple-string.bin"
printf "num\0i42\0" > "$CORPUS_DIR/kv/02-int64.bin"
printf "flag\0btrue\0" > "$CORPUS_DIR/kv/03-bool.bin"
printf "k1\0sv1\0k2\0i123\0k3\0bfalse\0" > "$CORPUS_DIR/kv/04-multi.bin"
printf "double\0d3.14159\0" > "$CORPUS_DIR/kv/05-double.bin"
printf "time\0t1234567890\0" > "$CORPUS_DIR/kv/06-timestamp.bin"

# Edge cases
printf "\x00\x00\x00\x00" > "$CORPUS_DIR/kv/edge-nulls.bin"
printf "k\0s\0" > "$CORPUS_DIR/kv/edge-empty-value.bin"
printf "long_key_name_here\0slong_value_string_content_here\0" > "$CORPUS_DIR/kv/edge-long.bin"
printf "version\0i1\0mechanism\0snone\0userid\0i1000\0" > "$CORPUS_DIR/kv/header-like.bin"

# Format is: HEADER.PAYLOAD.SIGNATURE
# HEADER = base64(kv with: version, mechanism, userid)
# PAYLOAD = base64(arbitrary data)
# SIGNATURE = mechanism-specific string

echo "Creating sign format seeds..."

# Example with "none" mechanism (simplest - no real signature)
# Header KV: version=1, mechanism=none, userid=1000
# Base64(version\0i1\0mechanism\0snone\0userid\0i1000\0) = dmVyc2lvbgBpMQBtZWNoYW5pc20Ac25vbmUAdXNlcmlkAGkxMDAwAA==
# Payload: "hello" -> Base64 = aGVsbG8=
# Signature for "none": just the string "none"
cat > "$CORPUS_DIR/sign-none/01-minimal.txt" << 'EOF'
dmVyc2lvbgBpMQBtZWNoYW5pc20Ac25vbmUAdXNlcmlkAGkxMDAwAA==.aGVsbG8=.none
EOF

# Empty payload
cat > "$CORPUS_DIR/sign-none/02-empty-payload.txt" << 'EOF'
dmVyc2lvbgBpMQBtZWNoYW5pc20Ac25vbmUAdXNlcmlkAGkxMDAwAA==..none
EOF

# Different userid
cat > "$CORPUS_DIR/sign-none/03-user-5000.txt" << 'EOF'
dmVyc2lvbgBpMQBtZWNoYW5pc20Ac25vbmUAdXNlcmlkAGk1MDAwAA==.dGVzdA==.none
EOF

# Longer payload
cat > "$CORPUS_DIR/sign-none/04-long-payload.txt" << 'EOF'
dmVyc2lvbgBpMQBtZWNoYW5pc20Ac25vbmUAdXNlcmlkAGkxMDAwAA==.VGhpcyBpcyBhIGxvbmdlciBwYXlsb2FkIHRoYXQgY29udGFpbnMgbW9yZSBkYXRhIGZvciB0ZXN0aW5n.none
EOF

# Malformed examples for robustness
echo "Creating malformed seeds..."
echo "not.enough.parts" > "$CORPUS_DIR/sign-none/bad-01-missing-part.txt"
echo "......" > "$CORPUS_DIR/sign-none/bad-02-only-dots.txt"
echo "A.B." > "$CORPUS_DIR/sign-none/bad-03-empty-sig.txt"
echo "A.B.C.D" > "$CORPUS_DIR/sign-none/bad-04-extra-part.txt"
echo "invalid-base64!@#$.data.sig" > "$CORPUS_DIR/sign-none/bad-05-invalid-b64.txt"
echo ".." > "$CORPUS_DIR/sign-none/bad-06-empty-parts.txt"
echo "A." > "$CORPUS_DIR/sign-none/bad-07-missing-payload-sig.txt"
echo ".B.C" > "$CORPUS_DIR/sign-none/bad-08-empty-header.txt"

# Variations with valid base64 but invalid KV content
BAD_KV_HEADER=$(printf "invalid-kv-no-nulls" | base64)
echo "${BAD_KV_HEADER}.aGVsbG8=.none" > "$CORPUS_DIR/sign-none/bad-09-invalid-kv.txt"

# Single character components
echo "A.B.C" > "$CORPUS_DIR/sign-none/bad-10-minimal-valid-format.txt"

# TOML configuration format examples
echo "Creating TOML configuration seeds..."

# Minimal valid TOML
cat > "$CORPUS_DIR/toml/01-minimal.toml" << 'EOF'
key = "value"
EOF

# IMP-like configuration
cat > "$CORPUS_DIR/toml/02-imp-config.toml" << 'EOF'
allow-sudo = true

[exec]
allowed-users = ["testuser"]
allowed-shells = ["/bin/sh", "/bin/bash"]

[sign]
max-ttl = 3600
default-type = "none"
allowed-types = ["none"]
EOF

# Nested tables and arrays
cat > "$CORPUS_DIR/toml/03-nested.toml" << 'EOF'
[database]
server = "192.168.1.1"
ports = [8001, 8001, 8002]
connection_max = 5000
enabled = true

[database.credentials]
user = "admin"
password = "secret"

[[products]]
name = "Hammer"
sku = 738594937

[[products]]
name = "Nail"
sku = 284758393
EOF

# Various data types
cat > "$CORPUS_DIR/toml/04-types.toml" << 'EOF'
# Strings
string1 = "basic string"
string2 = 'literal string'
string3 = """
multi-line
basic string
"""
string4 = '''
multi-line
literal string
'''

# Numbers
int1 = 42
int2 = -17
int3 = 1_000_000
float1 = 3.14159
float2 = -0.01
float3 = 5e+22

# Booleans
bool1 = true
bool2 = false

# Dates and times
date1 = 1979-05-27T07:32:00Z
date2 = 1979-05-27
EOF

# String escaping edge cases
cat > "$CORPUS_DIR/toml/05-escaping.toml" << 'EOF'
escaped = "line1\nline2\ttab\"quote\\"
unicode = "unicode: \u03B1 \U0001F600"
path = "C:\\Users\\test\\file.txt"
EOF

# Arrays of different types
cat > "$CORPUS_DIR/toml/06-arrays.toml" << 'EOF'
integers = [1, 2, 3]
colors = ["red", "yellow", "green"]
nested = [[1, 2], [3, 4, 5]]
mixed = [[1, 2], ["a", "b", "c"]]
EOF

# Empty and minimal values
cat > "$CORPUS_DIR/toml/07-empty.toml" << 'EOF'
empty_string = ""
empty_array = []
[empty_table]
EOF

# Inline tables
cat > "$CORPUS_DIR/toml/08-inline.toml" << 'EOF'
name = {first = "Tom", last = "Preston-Werner"}
point = {x = 1, y = 2}
animal = {type.name = "pug"}
EOF

# Comments
cat > "$CORPUS_DIR/toml/09-comments.toml" << 'EOF'
# This is a comment
key = "value"  # inline comment

[section]  # section comment
# Multiple
# comment
# lines
option = true
EOF

# Malformed examples
echo "Creating malformed TOML seeds..."

# Syntax errors
cat > "$CORPUS_DIR/toml/bad-01-unclosed-string.toml" << 'EOF'
key = "value
EOF

cat > "$CORPUS_DIR/toml/bad-02-invalid-key.toml" << 'EOF'
= "no key"
EOF

cat > "$CORPUS_DIR/toml/bad-03-duplicate-key.toml" << 'EOF'
key = "value1"
key = "value2"
EOF

cat > "$CORPUS_DIR/toml/bad-04-invalid-table.toml" << 'EOF'
[table
EOF

cat > "$CORPUS_DIR/toml/bad-05-type-mismatch.toml" << 'EOF'
arr = [1, 2, "mixed"]
EOF

cat > "$CORPUS_DIR/toml/bad-06-invalid-unicode.toml" << 'EOF'
str = "\uZZZZ"
EOF

cat > "$CORPUS_DIR/toml/bad-07-invalid-escape.toml" << 'EOF'
str = "\q"
EOF

# Edge cases
echo "" > "$CORPUS_DIR/toml/edge-01-empty.toml"
echo "a=1" > "$CORPUS_DIR/toml/edge-02-minimal.toml"
printf "\n\n\n" > "$CORPUS_DIR/toml/edge-03-only-newlines.toml"
printf "###" > "$CORPUS_DIR/toml/edge-04-only-comments.toml"

echo ""
echo "==============================================="
echo "Corpus generated in $CORPUS_DIR/"
echo ""
echo "Directory structure:"
ls -lR "$CORPUS_DIR"
echo ""
echo "To use with AFL:"
echo "  afl-fuzz -i $CORPUS_DIR/sign-none -o findings -- ./src/fuzz/fuzz_sign_unwrap_noverify"
echo "  afl-fuzz -i $CORPUS_DIR/kv -o findings -- ./src/fuzz/fuzz_kv"
echo "  afl-fuzz -i $CORPUS_DIR/toml -o findings -- ./src/fuzz/fuzz_cf"
echo ""
echo "NOTE: For curve/munge mechanism seeds, you'll need to:"
echo "  1. Use existing flux-security test fixtures (if available)"
echo "  2. Generate real signed payloads with those mechanisms"
echo ""
