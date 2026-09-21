#!/usr/bin/env python3
"""Print the URL + stats of a created share. Used by tshare."""
import json
import sys

d = json.load(sys.stdin)
if not d.get("ok"):
    print(f"error: {d}", file=sys.stderr)
    raise SystemExit(1)
m = d["meta"]
bits = [f'{m["files"]} files', f'{m["size"]} bytes']
bits.append(f'expires {m["expires_at"]}' if m.get("expires_at") else "never expires")
if m.get("once"):
    bits.append("⚠️ ONE-TIME (dies after the first visit)")
if m.get("pw_hash"):
    bits.append("password protected")
print(d["url"])
print("  " + " · ".join(bits))
