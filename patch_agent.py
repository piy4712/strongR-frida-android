#!/usr/bin/env python3
"""Patch a built frida-agent .so to hide detection strings (strongR technique).

Run on each embedded agent .so AFTER it is copied into the embed priv dir and
BEFORE the resource compiler packs it. This mirrors hluwa's anti-anti-frida.py
(0005/0006/0007): lief renames ELF symbols containing frida/FRIDA, and sed
replaces the gum-js-loop thread-name string in the binary.

Usage:
    python3 patch_agent.py <path-to-agent.so>
"""
import lief
import random
import string
import subprocess
import sys
from pathlib import Path


def rand(n, alphabet=string.ascii_uppercase):
    return "".join(random.choice(alphabet) for _ in range(n))


def main():
    if len(sys.argv) < 2:
        print("usage: patch_agent.py <agent.so>", file=sys.stderr)
        sys.exit(1)
    p = Path(sys.argv[1])
    if not p.exists():
        print(f"patch_agent: missing {p}", file=sys.stderr)
        sys.exit(1)
    if p.stat().st_size == 0:
        # empty placeholder (e.g. emulated agent for a flavor we don't build)
        print(f"patch_agent: skip empty {p}")
        return

    print(f"[*] patch_agent: {p}")
    binary = lief.parse(str(p))
    if binary is None:
        print(f"[!] lief could not parse {p} — skipping symbol patch", file=sys.stderr)
    else:
        sym_rand = rand(5)
        changed = 0
        for sym in binary.symbols:
            name = sym.name
            if "frida_agent_main" in name:
                sym.name = "main"
                changed += 1
            elif "frida" in name:
                sym.name = name.replace("frida", sym_rand.lower())
                changed += 1
            elif "FRIDA" in name:
                sym.name = name.replace("FRIDA", sym_rand)
                changed += 1
        binary.write(str(p))
        print(f"[*] lief renamed {changed} symbols (rand={sym_rand})")

    # sed binary replacements for thread-name strings (lief does not touch
    # plain .rodata C strings that aren't symbols). Same byte-length strategy
    # is unsafe, so use sed -b with equal-length random replacements where
    # possible, else rely on the symbol rename above for gum thread names.
    # gum-js-loop (11 chars) -> 11 random lowercase
    js_rand = rand(11, string.ascii_lowercase)
    # gmain (5 chars) -> 5 random lowercase (in case it appears as a thread name)
    gm_rand = rand(5, string.ascii_lowercase)
    for old, new in [("gum-js-loop", js_rand), ("gmain", gm_rand)]:
        # only replace when lengths match so we don't corrupt offsets
        if len(old) == len(new):
            subprocess.run(["sed", "-b", "-i", f"s/{old}/{new}/g", str(p)], check=False)
            print(f"[*] sed {old} -> {new}")


if __name__ == "__main__":
    main()