#!/usr/bin/env python3
"""Port strongR-frida patches to Frida 17.x.

The original strongR-frida (hluwa, 2021) was written for Frida 15 and uses
`git am` on .patch files. Frida 17 refactored: embed-agent.sh -> embed-agent.py,
fifo-based linjector -> memfd-based, files moved. Those patches no longer apply.

This script applies the equivalent detection-string changes directly to the
checked-out Frida 17.x source tree (no git am). It is idempotent-ish: it
asserts each target string is present before replacing, and errors loudly if a
target moved again (so a future Frida bump fails fast instead of silently
shipping a detectable binary).

Run from the frida source root (the dir containing subprojects/frida-core and
subprojects/frida-gum):
    python3 strongr_port.py
"""
import os
import re
import sys
import random
import string
from pathlib import Path


def fail(msg):
    print(f"[strongr_port] FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def patch_file(path: Path, replacements, must_exist=True):
    if not path.exists():
        if must_exist:
            fail(f"missing file: {path}")
        return
    src = path.read_text(encoding="utf-8")
    orig = src
    for old, new in replacements:
        if old not in src:
            fail(f"target not found in {path}: {old!r}")
        src = src.replace(old, new, 1)
    if src != orig:
        path.write_text(src, encoding="utf-8")
        print(f"[strongr_port] patched {path}")
    else:
        print(f"[strongr_port] no-op {path} (already patched?)")


def rand(n, alphabet=string.ascii_letters):
    return "".join(random.choice(alphabet) for _ in range(n))


def main():
    # Expect to be run from frida root, or pass root as argv[1].
    root = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path.cwd().resolve()
    core = root / "subprojects" / "frida-core"
    gum = root / "subprojects" / "frida-gum"
    if not (core / "meson.build").exists():
        fail(f"not a frida source root (no subprojects/frida-core/meson.build): {root}")

    # Random prefixes (deterministic-ish per build, but varied so each binary
    # differs). Keep ASCII alnum so they're valid in C identifiers / paths.
    rpc_b64 = "ZnJpZGE6cnBj"  # base64 of "frida:rpc" — keep literal so we can detect
    agent_prefix = rand(8, string.ascii_lowercase)
    rpc_rand = rand(8)
    print(f"[strongr_port] agent_prefix={agent_prefix} rpc_rand={rpc_rand}")

    # ---- 0001: frida:rpc -> base64-decoded at runtime ---------------------
    rpc = core / "lib" / "base" / "rpc.vala"
    patch_file(rpc, [
        ('.add_string_value ("frida:rpc")',
         f'.add_string_value ((string) GLib.Base64.decode("{rpc_b64}"))'),
        ('json.index_of ("\\"frida:rpc\\"") == -1',
         f'json.index_of ((string) GLib.Base64.decode("ImZyaWRhOnJwYyI=")) == -1'),
        ('type != "frida:rpc"',
         f'type != (string) GLib.Base64.decode("{rpc_b64}")'),
    ])

    # ---- 0002: re.frida.server default directory -> runtime UUID -----------
    srv = core / "server" / "server.vala"
    # turn the const into a mutable static + assign a UUID at startup
    patch_file(srv, [
        ('private const string DEFAULT_DIRECTORY = "re.frida.server";',
         'private static string DEFAULT_DIRECTORY = null;'),
    ])
    # inject the UUID assignment right after Environment.init () in main().
    # We insert it as the first statement after "Environment.init ();".
    s = srv.read_text(encoding="utf-8")
    needle = "Environment.init ();"
    if needle not in s:
        # may already be patched/inserted; check
        if "DEFAULT_DIRECTORY = GLib.Uuid.string_random()" not in s:
            fail(f"could not find Environment.init () anchor in {srv}")
    else:
        s = s.replace(needle, needle + '\n\t\tDEFAULT_DIRECTORY = GLib.Uuid.string_random();', 1)
        srv.write_text(s, encoding="utf-8")
        print(f"[strongr_port] injected UUID default-dir in {srv}")

    # ---- 0004: frida-agent-<arch>.so -> <rand>-<arch>.so -------------------
    # In linux-host-session.vala the AgentDescriptor PathTemplate + AgentResource
    # names are the memfd filenames RASP sees in /proc/<pid>/maps.
    lhs = core / "src" / "linux" / "linux-host-session.vala"
    patch_file(lhs, [
        ('PathTemplate ("frida-agent-<arch>.so")',
         f'PathTemplate ("{agent_prefix}-<arch>.so")'),
        ('new AgentResource ("frida-agent-arm.so",',
         f'new AgentResource ("{agent_prefix}-arm.so",'),
        ('new AgentResource ("frida-agent-arm64.so",',
         f'new AgentResource ("{agent_prefix}-arm64.so",'),
        # emulated agent lookups
        ('name = "frida-agent-arm.so";',
         f'name = "{agent_prefix}-arm.so";'),
        ('name = "frida-agent-arm64.so";',
         f'name = "{agent_prefix}-arm64.so";'),
    ])

    # ---- 0005: frida_agent_main entrypoint --------------------------------
    # NOTE: We do NOT rename the entrypoint lookup. strongR-frida original
    # renamed frida_agent_main -> main in BOTH the caller (host-session) and
    # the agent .so symbol table (via lief). But lief patching of the embedded
    # agent .so is not wired up in Frida 17's build (agent is packed into a
    # resource blob before we can intercept), so renaming only the caller side
    # would make server.symbol("main") fail with "undefined symbol: main".
    # RASP dictionary does not contain "frida_agent_main" (only "frida-agent"
    # the filename), so leaving the symbol is safe from detection.
    # The agent FILENAME (memfd name) is handled by patch 0004 above.

    # ---- 0006: gum-js-loop thread name -> random --------------------------
    sched = gum / "bindings" / "gumjs" / "gumscriptscheduler.c"
    js_loop_rand = rand(11, string.ascii_lowercase)
    patch_file(sched, [
        ('g_thread_new ("gum-js-loop",',
         f'g_thread_new ("{js_loop_rand}",'),
    ])

    # ---- 0006b: agent .so thread names (land in TARGET app's
    #      /proc/self/task/*/comm — RASP matches "frida-agent" AND bare "frida").
    #      - "frida-agent-emulated" (agent.vala:1432) — 1x
    #      - "frida-eternal-agent"  (agent.vala:366/562/670) — 3x, runs inside app
    #      Must patch at source so the built agent .so doesn't carry them. ----
    agent_vala = core / "lib" / "agent" / "agent.vala"
    emu_rand = rand(12, string.ascii_lowercase)
    eternal_rand = rand(14, string.ascii_lowercase)
    # replace_all the 3x eternal-agent first (patch_file only does 1), then
    # the single emulated via patch_file (asserts presence -> fail-fast).
    av = agent_vala.read_text(encoding="utf-8")
    n = av.count('"frida-eternal-agent"')
    if n == 0:
        fail('target not found in agent.vala: "frida-eternal-agent"')
    av = av.replace('"frida-eternal-agent"', f'"{eternal_rand}"')
    agent_vala.write_text(av, encoding="utf-8")
    print(f"[strongr_port] replaced {n}x frida-eternal-agent -> {eternal_rand} in agent.vala")
    patch_file(agent_vala, [
        ('new Thread<void> ("frida-agent-emulated",',
         f'new Thread<void> ("{emu_rand}",'),
    ])

    # ---- 0006c: frida-agent-container thread name (src/, host binary).
    #      Defensive: RASP scans the app, not the server, but the string is
    #      a literal "frida-agent" match and costs nothing to randomize. -----
    ac = core / "src" / "agent-container.vala"
    cont_rand = rand(12, string.ascii_lowercase)
    patch_file(ac, [
        ('new Thread<bool> ("frida-agent-container",',
         f'new Thread<bool> ("{cont_rand}",'),
    ])

    # ---- 0006d: host-session-service.vala error message containing
    #      "frida-agent" (host binary, defensive). --------------------------
    hss = core / "src" / "host-session-service.vala"
    if hss.exists():
        hs = hss.read_text(encoding="utf-8")
        old_msg = 'either refused to load frida-agent, '
        if old_msg in hs:
            hs = hs.replace(old_msg, 'either refused to load agent, ', 1)
            hss.write_text(hs, encoding="utf-8")
            print(f"[strongr_port] scrubbed 'frida-agent' from {hss} error msg")
        else:
            print(f"[strongr_port] {hss} msg already scrubbed / moved")

    # ---- 0006e: frida-main-loop thread name (src/frida-glue.c) — server
    #      process, but RASP matches bare "frida" so scrub defensively. ----
    glue = core / "src" / "frida-glue.c"
    if glue.exists():
        main_rand = rand(11, string.ascii_lowercase)
        patch_file(glue, [
            ('g_thread_new ("frida-main-loop",',
             f'g_thread_new ("{main_rand}",'),
        ])

    # ---- 0006f: frida-gadget thread name (lib/gadget/gadget-glue.c) — only
    #      in the gadget binary, not used by server injection. Scrub anyway
    #      in case the gadget is loaded into the app later. ----------------
    gglue = core / "lib" / "gadget" / "gadget-glue.c"
    if gglue.exists():
        gad_rand = rand(11, string.ascii_lowercase)
        patch_file(gglue, [
            ('g_thread_new ("frida-gadget",',
             f'g_thread_new ("{gad_rand}",'),
        ])

    # ---- 0008: droidy Unexpected command -> tolerate ----------------------
    droidy = core / "src" / "droidy" / "droidy-client.vala"
    if droidy.exists():
        ds = droidy.read_text(encoding="utf-8")
        old = 'throw new Error.PROTOCOL ("Unexpected command");'
        if old in ds:
            ds = ds.replace(old, 'break; //throw new Error.PROTOCOL ("Unexpected command");', 1)
            droidy.write_text(ds, encoding="utf-8")
            print(f"[strongr_port] tolerated Unexpected command in {droidy}")
        else:
            print(f"[strongr_port] Unexpected command already tolerated / moved in {droidy}")

    print("[strongr_port] source patches applied OK")


if __name__ == "__main__":
    main()