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
    # Symbol rename is BEST-EFFORT. The real detection-surface fix is the
    # source-level thread-name patches (frida-eternal-agent, gum-js-loop,
    # frida-agent-emulated) applied by strongr_port.py — those are what RASP
    # scans via /proc/self/task/*/comm. Symbol-table strings are a secondary
    # surface. So if lief has any trouble (API drift across versions, parse
    # edge case), warn but do NOT fail the build (the hook uses check=True,
    # and a lief failure shouldn't kill a 30-min compile).
    try:
        binary = lief.parse(str(p))
    except Exception as e:
        print(f"[!] lief.parse raised on {p}: {e} — skipping symbol patch", file=sys.stderr)
        binary = None
    if binary is None:
        print(f"[!] lief could not parse {p} — skipping symbol patch", file=sys.stderr)
    else:
        try:
            # lief API differs across versions: 1.0 uses `dynamic_symbols` (ELF),
            # 0.x uses `symbols`. Try both. frida_agent_main is an exported DYNAMIC
            # symbol, so dynamic_symbols is the right list on 1.0.
            syms = None
            for attr in ("dynamic_symbols", "symbols", "exported_symbols"):
                try:
                    lst = list(getattr(binary, attr))
                    if lst:
                        syms = lst
                        print(f"[*] lief: using binary.{attr} ({len(lst)} symbols)")
                        break
                except (AttributeError, TypeError):
                    continue
            if syms is None:
                print(f"[!] lief: no symbol list accessible on {p} — skipping rename", file=sys.stderr)
            else:
                sym_rand = rand(5)
                changed = 0
                for sym in syms:
                    name = sym.name
                    # DO NOT rename frida_agent_main: the host looks it up by
                    # that exact name to bootstrap the agent (server.symbol).
                    # Renaming -> "undefined symbol". RASP dict has "frida"
                    # (substring) but not "frida_agent_main" as a token, and the
                    # symbol lives in the agent .so's dynamic table — not in
                    # /proc/maps filenames or thread comm, which is what RASP
                    # actually scans. Leave it.
                    if name == "frida_agent_main":
                        continue
                    if "frida" in name:
                        sym.name = name.replace("frida", sym_rand.lower())
                        changed += 1
                    elif "FRIDA" in name:
                        sym.name = name.replace("FRIDA", sym_rand)
                        changed += 1
                binary.write(str(p))
                print(f"[*] lief renamed {changed} symbols (rand={sym_rand}, kept frida_agent_main)")
        except Exception as e:
            print(f"[!] lief symbol-rename failed on {p}: {e} — continuing (source patches are the real fix)", file=sys.stderr)

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