#!/usr/bin/env python3
#
#  Generate a build matrix for use with github workflows
#

import json
import os
import re

docker_run_checks = "src/test/docker/docker-run-checks.sh"

default_args = (
    "--prefix=/usr"
    " --sysconfdir=/etc"
    " --with-systemdsystemunitdir=/etc/systemd/system"
    " --localstatedir=/var"
)

class BuildMatrix:
    def __init__(self):
        self.matrix = []
        self.branch = None
        self.tag = None

        #  Set self.branch or self.tag based on GITHUB_REF
        if "GITHUB_REF" in os.environ:
            self.ref = os.environ["GITHUB_REF"]
            match = re.search("^refs/heads/(.*)", self.ref)
            if match:
                self.branch = match.group(1)
            match = re.search("^refs/tags/(.*)", self.ref)
            if match:
                self.tag = match.group(1)

    def add_build(
        self,
        name=None,
        image="bookworm",
        args=default_args,
        jobs=2,
        env=None,
        coverage=False,
        platform=None,
        command_args="",
    ):
        """Add a build to the matrix.include array"""

        # Extra environment to add to this command:
        env = env or {}

        needs_buildx = False
        if platform:
            command_args += f"--platform={platform}"
            needs_buildx = True

        # The command to run:
        command = f"{docker_run_checks} -j{jobs} --image={image} {command_args}"

        if coverage:
            env["COVERAGE"] = "t"

        create_release = False
        if self.tag and "DISTCHECK" in env:
            create_release = True

        self.matrix.append(
            {
                "name": name,
                "env": env,
                "command": command,
                "image": image,
                "tag": self.tag,
                "branch": self.branch,
                "coverage": coverage,
                "needs_buildx": needs_buildx,
                "create_release": create_release,
            }
        )

    def __str__(self):
        """Return compact JSON representation of matrix"""
        return json.dumps(
            {"include": self.matrix}, skipkeys=True, separators=(",", ":")
        )


matrix = BuildMatrix()

# Ubuntu: no args
matrix.add_build(name="bookworm")

# Ubuntu: 32b
matrix.add_build(
    name="bookworm - 32 bit",
    platform="linux/386",
)

# Ubuntu: gcc-8, content-s3, distcheck
matrix.add_build(
    name="bookworm - gcc-12,distcheck",
    env=dict(
        CC="gcc-12",
        CXX="g++12",
        DISTCHECK="t",
    ),
)

# Ubuntu: clang-6.0
matrix.add_build(
    name="bookworm - clang-15,chain-lint",
    env=dict(
        CC="clang-15",
        CXX="clang++-15",
        chain_lint="t",
    ),
    command_args="--workdir=/usr/src/" + "workdir/" * 15,
)

# Ubuntu: coverage
matrix.add_build(
    name="coverage",
    coverage=True,
    jobs=2,
)

# Ubuntu 20.04: py3.8
matrix.add_build(
    name="focal",
    image="focal",
)

# RHEL8 clone
matrix.add_build(
    name="el8",
    image="el8",
)

# Fedora 34
matrix.add_build(
    name="fedora34",
    image="fedora34",
    env=dict(CFLAGS="-fanalyzer"),
)

# Fedora 38 ASan
matrix.add_build(
    name="fedora38 - asan",
    image="fedora38",
    args="--enable-sanitizers"
)
print(matrix)
