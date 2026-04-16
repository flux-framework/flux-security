/************************************************************\
 * Copyright 2017 Lawrence Livermore National Security, LLC
 * (c.f. AUTHORS, NOTICE.LLNS, COPYING)
 *
 * This file is part of the Flux resource manager framework.
 * For details, see https://github.com/flux-framework.
 *
 * SPDX-License-Identifier: LGPL-3.0
\************************************************************/

#if HAVE_CONFIG_H
#include "config.h"
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <jansson.h>

#include "src/libtap/tap.h"
#include "src/libtomlc99/toml.h"
#include "tomltk.h"

/* simple types only */
const char *t1 = \
"i = 1\n" \
"d = 3.14\n" \
"s = \"foo\"\n" \
"b = true\n" \
"ts = 1979-05-27T07:32:00Z\n";

/* table and array */
const char *t2 = \
"[t]\n" \
"ia = [1, 2, 3]\n";

/* sub-table and value */
const char *t3 = \
"[t]\n" \
"[t.a]\n" \
"i = 42\n";

/* bad on line 4 */
const char *bad1 = \
"# line 1\n" \
"# line 2\n" \
"# line 3\n" \
"'# line 4 <- unbalanced tic\n"
"# line 5\n";

static void jdiag (const char *prefix, json_t *obj)
{
    char *s = json_dumps (obj, JSON_INDENT(2));
    if (!s)
        BAIL_OUT ("json_dumps: %s", strerror (errno));
    diag ("%s: %s", prefix, s);
    free (s);
}

/* Check whether json object represents to ISO 8601 time string.
 */
static bool check_ts (json_t *ts, const char *timestr)
{
    time_t t;
    struct tm tm;
    char buf[80];

    if (tomltk_json_to_epoch (ts, &t) < 0)
        return false;
    if (!gmtime_r (&t, &tm))
        return false;
    if (strftime (buf, sizeof (buf), "%Y-%m-%dT%TZ", &tm) == 0)
        return false;
    diag ("%s: %s ?= %s", __FUNCTION__, buf, timestr);
    return !strcmp (buf, timestr);
}

void test_json_ts(void)
{
    time_t t, t2;
    json_t *obj;

    /* Encode the current time, then decode and ensure it matches.
     */
    if (time (&t) < 0)
        BAIL_OUT ("time: %s", strerror (errno));
    obj = tomltk_epoch_to_json (t);
    ok (obj != NULL,
        "tomltk_epoch_to_json works");

    ok (tomltk_json_to_epoch (obj, &t2) == 0 && t == t2,
        "tomltk_json_to_epoch works, correct value");

    json_decref (obj);
}

void test_tojson_t1 (void)
{
    toml_table_t *tab;
    json_t *obj;
    json_int_t i;
    double d;
    const char *s;
    json_t *ts;
    int b;
    int rc;
    struct tomltk_error error;

    tab = tomltk_parse (t1, strlen (t1), &error);
    ok (tab != NULL,
        "t1: tomltk_parse works");
    if (!tab)
        BAIL_OUT ("t1: parse error line %d: %s", error.lineno, error.errbuf);

    obj = tomltk_table_to_json (tab);
    ok (obj != NULL,
        "t1: tomltk_table_to_json works");
    jdiag ("t1", obj);
    rc = json_unpack (obj, "{s:I s:f s:s s:b s:o}",
                     "i", &i,
                     "d", &d,
                     "s", &s,
                     "b", &b,
                     "ts", &ts);
    ok (rc == 0,
        "t1: unpack successful");
    ok (i == 1 && d == 3.14 && s != NULL && !strcmp (s, "foo") && b != 0
        && check_ts (ts, "1979-05-27T07:32:00Z"),
        "t1: has expected values");
    json_decref (obj);
    toml_free (tab);
}

void test_tojson_t2 (void)
{
    toml_table_t *tab;
    json_t *obj;
    json_int_t ia[3];
    int rc;
    struct tomltk_error error;

    tab = tomltk_parse (t2, strlen (t2), &error);
    ok (tab != NULL,
        "t2: tomltk_parse works");
    if (!tab)
        BAIL_OUT ("t2: parse error line %d: %s", error.lineno, error.errbuf);

    obj = tomltk_table_to_json (tab);
    ok (obj != NULL,
        "t2: tomltk_table_to_json works");
    jdiag ("t2", obj);
    rc = json_unpack (obj, "{s:{s:[I,I,I]}}",
                     "t",
                       "ia", &ia[0], &ia[1], &ia[2]);
    ok (rc == 0,
        "t2: unpack successful");
    ok (ia[0] == 1 && ia[1] == 2 && ia[2] == 3,
        "t2: has expected values");
    json_decref (obj);
    toml_free (tab);
}

void test_tojson_t3 (void)
{
    toml_table_t *tab;
    json_t *obj;
    json_int_t i;
    int rc;
    struct tomltk_error error;

    tab = tomltk_parse (t3, strlen (t3), &error);
    ok (tab != NULL,
        "t3: tomltk_parse works");
    if (!tab)
        BAIL_OUT ("t3: parse error line %d: %s", error.lineno, error.errbuf);

    obj = tomltk_table_to_json (tab);
    ok (obj != NULL,
        "t3: tomltk_table_to_json works");
    jdiag ("t3", obj);
    rc = json_unpack (obj, "{s:{s:{s:I}}}",
                     "t",
                       "a",
                         "i", &i);
    ok (rc == 0,
        "t3: unpack successful");
    ok (i == 42,
        "t3: has expected values");
    json_decref (obj);
    toml_free (tab);
}

void test_parse_lineno (void)
{
    toml_table_t *tab;
    struct tomltk_error error;

    errno = 0;
    tab = tomltk_parse (bad1, strlen (bad1), &error);
    if (!tab)
        diag ("filename='%s' lineno=%d msg='%s'", error.filename,
              error.lineno, error.errbuf);
    ok (tab == NULL && errno == EINVAL,
        "bad1: parse failed");
    ok (strlen (error.filename) == 0,
        "bad1: error.filename is \"\"");
    ok (error.lineno == 4,
        "bad1: error.lineno is 4");
    const char *msg = "unterminated s-quote";
    ok (!strcmp (error.errbuf, msg),
        "bad1: error is \"%s\"", msg); // no "line %d: " prefix
}

void test_corner (void)
{
    time_t t;
    json_t *obj;

    if (!(obj = tomltk_epoch_to_json (time (NULL))))
        BAIL_OUT ("tomltk_epoch_to_json now: %s", strerror (errno));

    errno = 0;
    ok (tomltk_parse_file (NULL, NULL) == NULL && errno == EINVAL,
        "tomltk_parse_file filename=NULL fails with EINVAL");
    errno = 0;
    ok (tomltk_parse ("foo", -1, NULL) == NULL  && errno == EINVAL,
        "tomltk_parse len=-1 fails with EINVAL");
    errno = 0;
    ok (tomltk_table_to_json (NULL) == NULL && errno == EINVAL,
        "tomltk_table_to_json NULL fails with EINVAL");

    errno = 0;
    ok (tomltk_json_to_epoch (NULL,  &t) < 0 && errno == EINVAL,
        "tomltk_json_to_epoch obj=NULL fails with EINVAL");

    errno = 0;
    ok (tomltk_ts_to_epoch (NULL, NULL) < 0 && errno == EINVAL,
        "tomltk_ts_to_epoch ts=NULL fails with EINVAL");

    errno = 0;
    ok (tomltk_epoch_to_json (-1) == NULL && errno == EINVAL,
        "tomltk_epoch_to_json t=-1 fails with EINVAL");

    errno = 0;
    ok (tomltk_parse_file (NULL, NULL) == NULL && errno == EINVAL,
        "tomltk_parse_file filename=NULL fails with EINVAL");
    errno = 0;
    ok (tomltk_parse_file ("/noexist", NULL) == NULL && errno == ENOENT,
        "tomltk_parse_file filename=(noexist) fails with ENOENT");

    json_decref (obj);
}

/* Test security fixes for heap-use-after-free in JSON conversion.
 * The bug was calling json_decref() after json_*_new() functions
 * failed, but those functions already decref on failure.
 */
void test_json_conversion (void)
{
    toml_table_t *tab;
    json_t *json;
    struct tomltk_error error;

    /* Test with valid nested structure to exercise array_to_json()
     * and table_to_json() code paths. This ensures the fix for the
     * heap-use-after-free (removing incorrect json_decref() calls)
     * doesn't break valid conversions.
     */
    const char *nested = "arr = [[1, 2], [3, 4]]\n[tab]\na = 1\n";
    tab = tomltk_parse (nested, strlen (nested), &error);
    ok (tab != NULL,
        "Nested structure parses successfully");
    if (tab) {
        json = tomltk_table_to_json (tab);
        ok (json != NULL,
            "JSON conversion handles nested arrays and tables");
        if (json)
            json_decref (json);
        else
            diag ("JSON conversion failed");
        toml_free (tab);
    }

    /* Test with array of arrays (exercises array_to_json recursion) */
    const char *array_of_arrays = "matrix = [[1, 2, 3], [4, 5, 6]]\n";
    tab = tomltk_parse (array_of_arrays, strlen (array_of_arrays), &error);
    ok (tab != NULL,
        "Array of arrays parses successfully");
    if (tab) {
        json = tomltk_table_to_json (tab);
        ok (json != NULL,
            "JSON conversion handles array of arrays");
        if (json)
            json_decref (json);
        toml_free (tab);
    }

    /* Test error path: invalid array (mixed types) triggers error in jansson */
    const char *mixed_array = "mixed = [1, \"string\"]\n";
    tab = tomltk_parse (mixed_array, strlen (mixed_array), &error);
    /* libtomlc99 parses this (TOML allows mixed arrays), but JSON may not
     * accept it. The important thing is no crash (heap-use-after-free).
     */
    if (tab) {
        json = tomltk_table_to_json (tab);
        /* Don't care if it succeeds or fails, just that it doesn't crash */
        pass ("JSON conversion of mixed array doesn't crash");
        if (json)
            json_decref (json);
        toml_free (tab);
    }
}

/* Test that tomltk_parse_file() preserves filename in error struct
 * when validation fails.
 */
void test_parse_file_errors (void)
{
    struct tomltk_error error;
    toml_table_t *tab;
    char tmpfile[PATH_MAX];
    FILE *fp;

    /* Create a temporary file with invalid content */
    snprintf (tmpfile, sizeof (tmpfile), "tomltk_test_%d.toml", getpid ());
    fp = fopen (tmpfile, "w");
    if (!fp)
        BAIL_OUT ("failed to create temp file %s: %s", tmpfile, strerror (errno));

    /* Write content that will fail validation */
    fprintf (fp, "key = \"\x80invalid utf8\"");  /* Invalid UTF-8 */
    fclose (fp);

    /* Test that filename is preserved in error */
    errno = 0;
    tab = tomltk_parse_file (tmpfile, &error);
    ok (tab == NULL && errno == EINVAL,
        "tomltk_parse_file() rejects invalid UTF-8");
    ok (strstr (error.filename, "tomltk_test") != NULL,
        "error.filename contains the actual filename");
    diag ("error.filename = '%s'", error.filename);

    unlink (tmpfile);
}

/* Test that inputs which triggered buffer overflows in libtomlc99 are now
 * handled safely. These patterns caused heap buffer underflows in toml_rtoi()
 * and toml_rtod_ex() but the fixes allow them to parse without crashing.
 * The important thing is no crash, not whether the values are valid TOML.
 */
void test_number_parsing (void)
{
    toml_table_t *tab;
    struct tomltk_error error;
    json_t *json;

    /* Test patterns that triggered toml_rtoi() s[-1] buffer underflow.
     * These parse without crash (the fix works), even though some are
     * invalid TOML. The parser accepts them as raw strings.
     */
    const char *int_patterns[] = {
        "val = _123\n",      /* underscore at start */
        "val = +_123\n",     /* underscore after sign */
        "val = 123_\n",      /* trailing underscore */
        "val = 1_234\n",     /* valid underscores */
    };

    for (size_t i = 0; i < sizeof(int_patterns)/sizeof(int_patterns[0]); i++) {
        tab = tomltk_parse (int_patterns[i], strlen (int_patterns[i]), &error);
        /* Don't test validity, just that it doesn't crash */
        pass ("Integer pattern %zu parses without crash", i);
        if (tab) {
            /* Also test JSON conversion doesn't crash */
            json = tomltk_table_to_json (tab);
            if (json)
                json_decref (json);
            toml_free (tab);
        }
    }

    /* Test patterns that triggered toml_rtod_ex() s[-2] and s[-1] underflows */
    const char *float_patterns[] = {
        "val = _1.23\n",     /* underscore at start */
        "val = 1._5\n",      /* underscore after dot (triggers s[-2]) */
        "val = ._5\n",       /* dot-underscore at start */
        "val = 1.23_\n",     /* trailing underscore */
        "val = 1_234.5\n",   /* valid underscores */
    };

    for (size_t i = 0; i < sizeof(float_patterns)/sizeof(float_patterns[0]); i++) {
        tab = tomltk_parse (float_patterns[i], strlen (float_patterns[i]), &error);
        pass ("Float pattern %zu parses without crash", i);
        if (tab) {
            json = tomltk_table_to_json (tab);
            if (json)
                json_decref (json);
            toml_free (tab);
        }
    }

    /* Test timestamp parsing edge cases (heap buffer overflow in scan_string).
     * These patterns triggered reads past buffer end: p++ when *p is NUL,
     * and p[-1] without checking p > orig.
     */
    const char *ts_no_newline = "ts = 1979-05-27T07:32:00Z";
    tab = tomltk_parse (ts_no_newline, strlen (ts_no_newline), &error);
    ok (tab != NULL,
        "Timestamp without trailing newline parses without overflow");
    if (tab) {
        json = tomltk_table_to_json (tab);
        if (json)
            json_decref (json);
        toml_free (tab);
    }

    const char *ts_with_spaces = "ts = 1979-05-27T07:32:00Z  \n";
    tab = tomltk_parse (ts_with_spaces, strlen (ts_with_spaces), &error);
    ok (tab != NULL,
        "Timestamp with trailing spaces parses without overflow");
    if (tab) {
        json = tomltk_table_to_json (tab);
        if (json)
            json_decref (json);
        toml_free (tab);
    }

    const char *ts_minimal = "ts = 0\n";
    tab = tomltk_parse (ts_minimal, strlen (ts_minimal), &error);
    ok (tab != NULL,
        "Minimal timestamp parses without overflow");
    if (tab) {
        json = tomltk_table_to_json (tab);
        if (json)
            json_decref (json);
        toml_free (tab);
    }
}

/* Test multi-line string handling in validation layer.
 * This exercises the triple-quote tracking logic that was added to
 * prevent parser hangs.
 */
void test_multiline_strings (void)
{
    toml_table_t *tab;
    struct tomltk_error error;
    json_t *json;

    /* Test multi-line double-quote strings (""") */
    const char *ml_double = "text = \"\"\"\nline 1\nline 2\n\"\"\"";
    tab = tomltk_parse (ml_double, strlen (ml_double), &error);
    ok (tab != NULL,
        "Multi-line double-quote string parses successfully");
    if (tab) {
        json = tomltk_table_to_json (tab);
        if (json)
            json_decref (json);
        toml_free (tab);
    }

    /* Test multi-line single-quote strings (''') - this exercises the
     * code path that the user pointed out for coverage.
     */
    const char *ml_single = "text = '''\nline 1\nline 2\n'''";
    tab = tomltk_parse (ml_single, strlen (ml_single), &error);
    ok (tab != NULL,
        "Multi-line single-quote string parses successfully");
    if (tab) {
        json = tomltk_table_to_json (tab);
        if (json)
            json_decref (json);
        toml_free (tab);
    }

    /* Test nested quotes don't confuse parser */
    const char *nested = "text = '''\nHe said \"hello\"\n'''";
    tab = tomltk_parse (nested, strlen (nested), &error);
    ok (tab != NULL,
        "Multi-line single-quote string with nested double quotes");
    if (tab) {
        json = tomltk_table_to_json (tab);
        if (json)
            json_decref (json);
        toml_free (tab);
    }

    /* Test that we can have both types in one file */
    const char *both = "str1 = '''\nsingle\n'''\nstr2 = \"\"\"\ndouble\n\"\"\"";
    tab = tomltk_parse (both, strlen (both), &error);
    ok (tab != NULL,
        "Both multi-line string types in one file");
    if (tab) {
        json = tomltk_table_to_json (tab);
        if (json)
            json_decref (json);
        toml_free (tab);
    }

    /* Test unterminated multi-line single-quote string */
    const char *unterminated_single = "text = '''\nunclosed";
    errno = 0;
    tab = tomltk_parse (unterminated_single, strlen (unterminated_single), &error);
    ok (tab == NULL && errno == EINVAL,
        "Unterminated multi-line single-quote string rejected");
    if (tab == NULL)
        diag ("  error: %s", error.errbuf);

    /* Test unterminated multi-line double-quote string */
    const char *unterminated_double = "text = \"\"\"\nunclosed";
    errno = 0;
    tab = tomltk_parse (unterminated_double, strlen (unterminated_double), &error);
    ok (tab == NULL && errno == EINVAL,
        "Unterminated multi-line double-quote string rejected");
    if (tab == NULL)
        diag ("  error: %s", error.errbuf);
}

/* Test cases derived from AFL++ fuzzer hang findings.
 * These inputs previously caused libtomlc99 to hang indefinitely.
 * The validation layer now rejects them quickly with clear error messages.
 */
void test_afl_hangs (void)
{
    toml_table_t *tab;
    struct tomltk_error error;

    /* Test 1: Embedded NULL bytes (findings-cf id:000000, 000003, 000006)
     * NULL bytes in TOML input can cause parser to hang in string processing.
     * Example: key = "value\x00more"
     */
    const char null_bytes[] = "key = \"test\x00value\"";
    errno = 0;
    tab = tomltk_parse (null_bytes, sizeof(null_bytes)-1, &error);
    ok (tab == NULL && errno == EINVAL,
        "AFL hang: embedded NULL byte rejected");
    if (tab == NULL)
        diag ("  error: %s", error.errbuf);

    /* Test 2: Invalid UTF-8 sequences (findings-cf id:000000, 000005, 000006)
     * Invalid UTF-8 bytes (0x80-0xFF not in valid sequences) cause hangs.
     * AFL found: 0x80, 0x81, 0x92, 0xFF, 0xD1 in various contexts.
     */
    const unsigned char invalid_utf8_1[] = "key = \"test\x92value\"";  // 0x92 = invalid
    errno = 0;
    tab = tomltk_parse ((char*)invalid_utf8_1, sizeof(invalid_utf8_1)-1, &error);
    ok (tab == NULL && errno == EINVAL,
        "AFL hang: invalid UTF-8 byte 0x92 rejected");
    if (tab == NULL)
        diag ("  error: %s", error.errbuf);

    const unsigned char invalid_utf8_2[] = "allow\x81-sudo = true";  // 0x81 = invalid
    errno = 0;
    tab = tomltk_parse ((char*)invalid_utf8_2, sizeof(invalid_utf8_2)-1, &error);
    ok (tab == NULL && errno == EINVAL,
        "AFL hang: invalid UTF-8 byte 0x81 rejected");
    if (tab == NULL)
        diag ("  error: %s", error.errbuf);

    const unsigned char invalid_utf8_3[] = "ip = \"192.168.\xD1.1\"";  // 0xD1 = invalid (needs continuation)
    errno = 0;
    tab = tomltk_parse ((char*)invalid_utf8_3, sizeof(invalid_utf8_3)-1, &error);
    ok (tab == NULL && errno == EINVAL,
        "AFL hang: invalid UTF-8 byte 0xD1 (truncated sequence) rejected");
    if (tab == NULL)
        diag ("  error: %s", error.errbuf);

    /* Test 3: Control characters outside strings (findings-cf id:000003, 000006)
     * Control chars (0x01-0x1F except \t,\n,\r) between tokens cause parser hangs.
     * AFL found: 0x03, 0x04, 0xE8 embedded in unquoted context.
     */
    const unsigned char control_chars[] = "key\x04= value";  // 0x04 between key and =
    errno = 0;
    tab = tomltk_parse ((char*)control_chars, sizeof(control_chars)-1, &error);
    ok (tab == NULL && errno == EINVAL,
        "AFL hang: control character 0x04 rejected");
    if (tab == NULL)
        diag ("  error: %s", error.errbuf);

    /* Test 4: Excessive bracket nesting (findings-cf id:000006, fuzzer04 id:000004)
     * Deeply nested arrays cause stack overflow or infinite recursion in parser.
     * id:000006 had 18 brackets, id:000004 had 618 brackets!
     * MAX_NESTING = 32 should catch these.
     */
    const char deep_nest[] =
        "key = [[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[["  // 40 opening brackets
        "1"
        "]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]";        // 40 closing brackets
    errno = 0;
    tab = tomltk_parse (deep_nest, strlen(deep_nest), &error);
    ok (tab == NULL && errno == EINVAL,
        "AFL hang: excessive bracket nesting (40 levels) rejected");
    if (tab == NULL)
        diag ("  error: %s", error.errbuf);

    /* Test 5: Adjacent triple-quote sequences (fuzzer04 id:000000)
     * Patterns like '''''' or """""" (6 consecutive quotes) create ambiguous
     * zero-length multi-line strings that cause infinite loops.
     */
    const char six_single_quotes[] = "key = ''''''";
    errno = 0;
    tab = tomltk_parse (six_single_quotes, strlen(six_single_quotes), &error);
    ok (tab == NULL && errno == EINVAL,
        "AFL hang: six consecutive single quotes rejected");
    if (tab == NULL)
        diag ("  error: %s", error.errbuf);

    const char six_double_quotes[] = "key = \"\"\"\"\"\"";
    errno = 0;
    tab = tomltk_parse (six_double_quotes, strlen(six_double_quotes), &error);
    ok (tab == NULL && errno == EINVAL,
        "AFL hang: six consecutive double quotes rejected");
    if (tab == NULL)
        diag ("  error: %s", error.errbuf);

    /* Test 6: Combined patterns - NULL + invalid UTF-8 + control chars
     * Real AFL finding from id:000006: multiple issues in one input.
     */
    const unsigned char combined[] = {
        0x61, 0x4c, 0x6c, 0x6f, 0x3d, 0x20,  // aLlo=
        0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b,  // [[[[[[
        0x77, 0x2d, 0x00, 0x00, 0x04, 0x00,  // w-\x00\x00\x04\x00
        0x20, 0x3d, 0x20, 0x74, 0x72, 0x75, 0x65  // = true
    };
    errno = 0;
    tab = tomltk_parse ((char*)combined, sizeof(combined), &error);
    ok (tab == NULL && errno == EINVAL,
        "AFL hang: combined NULL+control+nesting rejected");
    if (tab == NULL)
        diag ("  error: %s", error.errbuf);

    /* Test 7: Valid UTF-8 multi-byte sequences should still work
     * Ensure our UTF-8 validator doesn't reject legitimate multi-byte chars.
     */
    const unsigned char valid_utf8[] = {
        0x6e, 0x61, 0x6d, 0x65, 0x20, 0x3d, 0x20, 0x22,  // name = "
        0xC3, 0xA9, 0x6C, 0xC3, 0xA8, 0x76, 0x65,        // élève (French: student)
        0x22  // "
    };
    errno = 0;
    tab = tomltk_parse ((char*)valid_utf8, sizeof(valid_utf8), &error);
    ok (tab != NULL,
        "Valid UTF-8 multi-byte chars (é, è) accepted");
    if (tab == NULL)
        diag ("  error: %s", error.errbuf);
    else
        toml_free (tab);

    /* Test 8: Excessive input size
     * While not technically a "hang", AFL generates huge inputs that waste time.
     * MAX_LINES=10000 should reject these quickly.
     */
    const int huge_lines = 15000;
    char *huge_input = malloc(huge_lines * 10);  // ~150KB of newlines
    if (huge_input) {
        for (int i = 0; i < huge_lines * 10; i += 10) {
            memcpy(huge_input + i, "k = 1\n", 6);
            memset(huge_input + i + 6, '\n', 4);
        }
        errno = 0;
        tab = tomltk_parse (huge_input, huge_lines * 10, &error);
        ok (tab == NULL && errno == EINVAL,
            "AFL hang: excessive input size (>10000 lines) rejected");
        if (tab == NULL)
            diag ("  error: %s", error.errbuf);
        free (huge_input);
    }

    /* Test 9: Invalid UTF-8 inside strings (fuzzer04 id:000011)
     * Invalid bytes 0xFF, 0x7F inside quoted strings.
     * String content: f\xFF\x7Fse
     */
    const unsigned char invalid_in_string[] =
        "string3 = \"\"\"\nmultabool2 = f\xff\x7fse\n\"\"\"";
    errno = 0;
    tab = tomltk_parse ((char*)invalid_in_string,
                        sizeof(invalid_in_string)-1, &error);
    ok (tab == NULL && errno == EINVAL,
        "AFL hang fuzzer04-11: invalid UTF-8 (0xFF,0x7F) in string rejected");
    if (tab == NULL)
        diag ("  error: %s", error.errbuf);

    /* Test 10: Long repetitive content with 4-quote pattern (fuzzer04 id:000012)
     * Long runs of 'J' chars (200+ bytes) followed by anomalous quote pattern.
     * This tests both string length handling and quote state tracking.
     */
    const char long_repetitive[] =
        "string3 = \"\"\"\n"
        "JJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJ"
        "JJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJ"
        "JJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJ"
        "JJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJ"
        "22\n\"\"\"";
    errno = 0;
    tab = tomltk_parse (long_repetitive, strlen(long_repetitive), &error);
    // This should either parse successfully or reject cleanly (not hang)
    if (tab != NULL) {
        pass ("AFL hang fuzzer04-12: long repetitive pattern completed");
        toml_free (tab);
    } else {
        ok (errno == EINVAL,
            "AFL hang fuzzer04-12: long repetitive pattern rejected cleanly");
        diag ("  error: %s", error.errbuf);
    }

    /* Test 11: Repetitive timestamp patterns (fuzzer04 id:000013)
     * Many malformed timestamp-like strings with commas inside.
     * Example: 1979-05-27T07:32:00+,pty_,+,1979-05-27...
     * Tests parser's timestamp validation and comma handling.
     */
    const char timestamp_spam[] =
        "bool1 = tru::bool2t5-27T07:42:00+,pty_,+,1979-05-27T07:32:79-05-27T:00+,"
        "+,1979-05-27T07:32:00+,1979-05-27T07:2:00+,pty_,+,1979-05-27T07:32:00";
    errno = 0;
    tab = tomltk_parse (timestamp_spam, strlen(timestamp_spam), &error);
    // Should reject due to malformed syntax, not hang
    ok (tab == NULL && errno == EINVAL,
        "AFL hang fuzzer04-13: repetitive timestamp patterns rejected");
    if (tab == NULL)
        diag ("  error: %s", error.errbuf);

    /* Test 12: Comment character inside array
     * Comments inside arrays can confuse the parser state machine.
     * Validates the in_array check for '#' characters.
     */
    const char comment_in_array[] = "arr = [1, # comment\n2]";
    errno = 0;
    tab = tomltk_parse (comment_in_array, strlen(comment_in_array), &error);
    ok (tab == NULL && errno == EINVAL,
        "Comment character inside array rejected");
    if (tab == NULL)
        diag ("  error: %s", error.errbuf);

    /* Test 13: Unbalanced brackets
     * Opening brackets without matching closing brackets.
     * Validates the square_count balance check.
     */
    const char unbalanced_open[] = "arr = [[1, 2]";
    errno = 0;
    tab = tomltk_parse (unbalanced_open, strlen(unbalanced_open), &error);
    ok (tab == NULL && errno == EINVAL,
        "Unbalanced brackets (missing close) rejected");
    if (tab == NULL)
        diag ("  error: %s", error.errbuf);

    /* Test 14: Extra closing bracket
     * Closing brackets without matching opening brackets.
     */
    const char unbalanced_close[] = "arr = [1, 2]]";
    errno = 0;
    tab = tomltk_parse (unbalanced_close, strlen(unbalanced_close), &error);
    ok (tab == NULL && errno == EINVAL,
        "Unbalanced brackets (extra close) rejected");
    if (tab == NULL)
        diag ("  error: %s", error.errbuf);

    /* Test 15: Truncated UTF-8 sequence (2-byte)
     * UTF-8 start byte 0xC2 indicates 2-byte sequence but input ends
     * before continuation byte.
     */
    const unsigned char truncated_2byte[] = "key = \"value\xC2";
    errno = 0;
    tab = tomltk_parse ((char*)truncated_2byte, sizeof(truncated_2byte)-1, &error);
    ok (tab == NULL && errno == EINVAL,
        "Truncated UTF-8 sequence (2-byte) rejected");
    if (tab == NULL)
        diag ("  error: %s", error.errbuf);

    /* Test 16: Truncated UTF-8 sequence (3-byte)
     * UTF-8 start byte 0xE0 indicates 3-byte sequence but only 1
     * continuation byte follows.
     */
    const unsigned char truncated_3byte[] = "key = \"test\xE0\xA0";
    errno = 0;
    tab = tomltk_parse ((char*)truncated_3byte, sizeof(truncated_3byte)-1, &error);
    ok (tab == NULL && errno == EINVAL,
        "Truncated UTF-8 sequence (3-byte) rejected");
    if (tab == NULL)
        diag ("  error: %s", error.errbuf);

    /* Test 17: Truncated UTF-8 sequence (4-byte)
     * UTF-8 start byte 0xF0 indicates 4-byte sequence but only 2
     * continuation bytes follow.
     */
    const unsigned char truncated_4byte[] = "val = \"x\xF0\x90\x80";
    errno = 0;
    tab = tomltk_parse ((char*)truncated_4byte, sizeof(truncated_4byte)-1, &error);
    ok (tab == NULL && errno == EINVAL,
        "Truncated UTF-8 sequence (4-byte) rejected");
    if (tab == NULL)
        diag ("  error: %s", error.errbuf);

    /* Test 18: Escaped quote in multi-line string followed by four quotes
     * (fuzzer04 id:000015)
     * Pattern: string3 = """ ... \"""" where backslash-4-quotes appears.
     * The backslash escapes the first quote, leaving """ as the closing
     * delimiter. This tests proper escape handling inside multi-line strings.
     * This is actually valid TOML, so we test that it completes without hanging.
     */
    const char escaped_quotes_ml[] =
        "string3 = \"\"\"\n"
        "content\n"
        "e2\\ttab\\\"\"\"\"";  // backslash + 4 quotes closes the ml string
    errno = 0;
    tab = tomltk_parse (escaped_quotes_ml, strlen(escaped_quotes_ml), &error);
    // This should either parse successfully or fail quickly (not hang)
    if (tab != NULL) {
        pass ("AFL hang fuzzer04-15: escaped quotes in ml string completed");
        toml_free (tab);
    } else {
        ok (errno == EINVAL,
            "AFL hang fuzzer04-15: escaped quotes in ml string rejected cleanly");
        diag ("  error: %s", error.errbuf);
    }

    /* Test 19: Backslash in single-quote (literal) string (fuzzer04 id:000018)
     * Pattern: 'text\'more''text' - backslash followed by quote, then two quotes
     * In TOML literal strings (single quotes), backslash is NOT an escape char.
     * The validator was incorrectly treating \ as escape, causing it to skip
     * the next quote and never close the string.
     */
    const char literal_backslash[] = "'icode: \\\'.B.D.C.''.B.D.C.allow-sudo = 937";
    errno = 0;
    tab = tomltk_parse (literal_backslash, strlen(literal_backslash), &error);
    // Should complete quickly - backslash is literal, first quote closes string
    if (tab != NULL) {
        pass ("AFL hang fuzzer04-18: backslash in literal string completed");
        toml_free (tab);
    } else {
        pass ("AFL hang fuzzer04-18: backslash in literal string rejected cleanly");
    }

    /* Test 20: Multiple single quotes with backslashes (fuzzer04 id:000019)
     * Pattern: ''.'.'= {'\\\\...\\'.B.''.'.'= [
     * Tests complex combinations of single quotes and backslashes.
     * Literal strings don't support escapes, so each ' opens/closes immediately.
     */
    const char literal_complex[] = "''.'\\t'= {'\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\'.B.''.'\\t'= [";
    errno = 0;
    tab = tomltk_parse (literal_complex, strlen(literal_complex), &error);
    // Should complete quickly regardless of parse result
    if (tab != NULL) {
        pass ("AFL hang fuzzer04-19: complex literal string pattern completed");
        toml_free (tab);
    } else {
        pass ("AFL hang fuzzer04-19: complex literal string pattern rejected cleanly");
    }
}

int main (int argc, char *argv[])
{
    plan (NO_PLAN);

    test_json_ts ();
    test_tojson_t1 ();
    test_tojson_t2 ();
    test_tojson_t3 ();
    test_parse_lineno ();
    test_corner ();
    test_json_conversion ();
    test_parse_file_errors ();
    test_number_parsing ();
    test_multiline_strings ();
    test_afl_hangs ();

    done_testing ();
}

/*
 * vi: ts=4 sw=4 expandtab
 */
