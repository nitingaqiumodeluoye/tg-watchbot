"""CLI harness for the server-side CDK claimer.

Usage (on the server, inside the container):
    python cdk_claim_cli.py --link https://cdk.linux.do/receive/<uuid>
    python cdk_claim_cli.py --link ... --dry-run
    python cdk_claim_cli.py --sync-session <linux_do_cdk_session_id>
    python cdk_claim_cli.py --check          # session + clearance health only
    python cdk_claim_cli.py --list           # recent claim outcomes + codes
"""

from __future__ import annotations

import argparse
import json
import os
import sys

import cdk_claim


def cmd_check() -> int:
    session = cdk_claim.load_cdk_session(refresh=True)
    print("session file :", cdk_claim.cdk_session_file())
    print("session ok   :", session.ok, "len =", len(session.session_id))
    print("saved_at     :", session.saved_at)
    print("session ua   :", session.user_agent)
    print("provider     :", cdk_claim.cdk_captcha_provider())
    print("bypass url   :", cdk_claim.cf_bypass_url())
    print("enabled      :", cdk_claim.cdk_claim_enabled(), "dry_run:", cdk_claim.cdk_claim_dry_run())
    try:
        cookies, ua = cdk_claim.fetch_cdk_clearance()
        names = sorted(cookies)
        print("clearance    :", "OK" if "cf_clearance" in cookies else "MISSING")
        print("  cookies    :", names)
        print("  bypass ua  :", ua)
        print("  clr len    :", len(cookies.get("cf_clearance", "")))
    except Exception as exc:
        print("clearance    : FAILED", type(exc).__name__, exc)
        return 1
    if not session.ok:
        print("\n[HINT] sync a session first: --sync-session <cookie value>")
        return 1
    # The clearance check above cannot see a dead login (it counts a 401 as proof
    # Cloudflare was cleared), and `session ok: True` only means a value is
    # present. This is the check that actually answers "can we still claim?".
    state = cdk_claim.check_login_state()
    remaining = state.get("remaining_seconds")
    print("login        :", "OK" if state.get("ok") else "FAILED")
    if not state.get("ok"):
        print("  reason     :", state.get("detail") or "unknown")
    if isinstance(remaining, (int, float)):
        print(f"  expires in : {remaining / 86400:.2f} days (7-day token TTL)")
    if not state.get("ok"):
        print("\n[HINT] a dead login cannot be fixed by Cloudflare work; paste a new")
        print("       linux_do_cdk_session_id on the panel settings page, or run")
        print("       --sync-session <cookie value>")
        return 1
    return 0


def cmd_sync(value: str) -> int:
    s = cdk_claim.save_cdk_session(value.strip(), source="cli")
    print("saved session len =", len(s.session_id))
    print("path =", cdk_claim.cdk_session_file())
    return 0


def cmd_claim(link: str, dry_run: bool) -> int:
    res = cdk_claim.claim_link(link, dry_run=dry_run)
    print(json.dumps(
        {
            "ok": res.ok,
            "reason": res.reason,
            "project_id": res.project_id,
            "project_name": res.project_name,
            "error": res.error,
            "already_received": res.already_received,
            "content": res.content,
            "elapsed_ms": res.elapsed_ms,
        },
        ensure_ascii=False,
        indent=1,
    ))
    return 0 if res.ok else 2


def cmd_list(limit: int) -> int:
    """Print recently persisted claims, oldest last.

    Reads the sqlite DB directly (the same file the bot writes) so it works even
    while the bot is running, and needs no Telegram access.
    """
    import sqlite3
    from pathlib import Path

    path = Path(os.getenv("DB_PATH", "tg-watchbot.sqlite3"))
    if not path.exists():
        print(json.dumps({"error": "db not found", "path": str(path)}, ensure_ascii=False))
        return 1
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT * FROM cdk_claims ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    except sqlite3.OperationalError as e:
        print(json.dumps({"error": str(e)}, ensure_ascii=False))
        return 1
    out = []
    for r in rows:
        out.append({
            "time": r["created_at"],
            "project": (r["project_name"] or "")[:34],
            "ok": bool(r["ok"]),
            "reason": r["reason"],
            "code": (r["content"] or "")[:46],
            "attempts": r["attempts"],
            "notified": bool(r["notified"]),
            "elapsed_s": round((r["elapsed_ms"] or 0) / 1000.0, 1),
        })
    print(json.dumps(out, ensure_ascii=False, indent=1))
    total = conn.execute("SELECT COUNT(*) FROM cdk_claims").fetchone()[0]
    wins = conn.execute("SELECT COUNT(*) FROM cdk_claims WHERE ok=1").fetchone()[0]
    print("总计: %d 次, 成功: %d 次" % (total, wins), file=sys.stderr)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--link", default="")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--sync-session", default="")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--limit", type=int, default=20)
    args = ap.parse_args()

    if args.list:
        return cmd_list(args.limit)
    if args.sync_session:
        return cmd_sync(args.sync_session)
    if args.check or not args.link:
        return cmd_check()
    return cmd_claim(args.link, args.dry_run)


if __name__ == "__main__":
    sys.exit(main())
