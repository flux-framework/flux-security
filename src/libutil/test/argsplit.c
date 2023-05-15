/************************************************************\
 * Copyright 2023 Lawrence Livermore National Security, LLC
 * (c.f. AUTHORS, NOTICE.LLNS, COPYING)
 *
 * This file is part of the Flux resource manager framework.
 * For details, see https://github.com/flux-framework.
 *
 * SPDX-License-Identifier: LGPL-3.0
\************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#include <errno.h>

#include "argsplit.h"
#include "src/libtap/tap.h"

int main (void)
{
    char **argv;

    plan (NO_PLAN);
    errno = 0;
    ok (argsplit (NULL) == NULL && errno == 0,
        "argsplit (NULL) returns NULL with errno not set");
    ok (argsplit ("") == NULL && errno == 0,
        "argsplit (\"\") returns NULL with errno not set");
    argv = argsplit ("one");
    ok (argv != NULL,
        "argsplit (\"one\") works");
    is (argv[0], "one",
        "first argument is correct");
    ok (argv[1] == NULL,
        "returned array is NULL terminated");
    args_free (argv);

    argv = argsplit ("one two");
    ok (argv != NULL,
        "argsplit (\"one two\") works");
    is (argv[0], "one",
        "first argument is correct");
    is (argv[1], "two",
        "second argument is correct");
    ok (argv[2] == NULL,
        "returned array is NULL terminated");
    args_free (argv);

    argv = argsplit ("one two three  ");
    ok (argv != NULL,
        "argsplit (\"one two three  \") works");
    is (argv[0], "one",
        "first argument is correct");
    is (argv[1], "two",
        "second argument is correct");
    is (argv[2], "three",
        "third argument is correct");
    ok (argv[3] == NULL,
        "returned array is NULL terminated");
    args_free (argv);

    argv = argsplit (" one\t two\t");
    ok (argv != NULL,
        "argsplit (\" one\t two\t\") works");
    is (argv[0], "one",
        "first argument is correct");
    is (argv[1], "two",
        "second argument is correct");
    ok (argv[2] == NULL,
        "returned array is NULL terminated");
    args_free (argv);

    done_testing ();
}


