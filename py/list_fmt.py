#!/usr/bin/env python3
"""Pretty-print the temp-share list. Used by tshare --list."""
import json
import sys

d = json.load(sys.stdin)
if not d.get("shares"):
    print("no shares.")
    raise SystemExit
print(f'storage used: {d["storage"]}\n')
for s in d["shares"]:
    flags = []
    if s["password"]:
        flags.append("🔒")
    if s.get("once"):
        flags.append("1️⃣ one-time")
    if not s.get("expires_at"):
        flags.append("never expires")
    else:
        flags.append(f'exp {s["expires_at"][:10]}')
    print(f'{s["slug"]:<22}{s["size_human"]:>8}  {s["files"]:>3} files  {" ".join(flags)}')
    print(f'  {s["url"]}   · {s["hits"]} views · {s.get("unique_ips", 0)} unique IP')
    for v in s.get("visits", [])[-3:]:
        print(f'    {v["t"][:16]}  {v["ip"]:<16} {v["ua"]}')
