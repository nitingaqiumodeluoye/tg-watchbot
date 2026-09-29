"""Regression tests for the three defects behind the 04:01 lost code.

Run: python test_cdk_resilience.py
"""
import sys
import types

import cdk_claim as C

PID = "bc4d44af-8419-4110-9f93-efb14ccfd62a"
LINK = f"https://cdk.linux.do/receive/{PID}"

PASS = []
FAIL = []


def check(name, cond, extra=""):
    (PASS if cond else FAIL).append(name)
    print(("  PASS  " if cond else "  FAIL  ") + name + (f"  <- {extra}" if extra and not cond else ""))


class _Sess:
    ok = True
    session_id = "sid"
    user_agent = "UA"


def _raise(exc):
    def _f(*a, **k):
        raise exc
    return _f


def _install(monkey, **over):
    """Install a harmless network layer, then apply per-test overrides."""
    C.load_cdk_session = lambda refresh=False: _Sess()
    C.cached_clearance = lambda session_id=None: ({"cf_clearance": "clr"}, "UA")
    C._new_client = lambda ua, jar: object()
    C.get_project_info = lambda pid, cl: dict(over.pop("info"))
    C.get_user_info = over.pop("user", lambda cl: {"trust_level": 5, "score": 999})
    C.solve_captcha = over.pop("captcha", lambda url: ("tok", "UA"))
    C.post_receive = over.pop("receive", lambda pid, tok, cl: {"error_msg": "", "data": {"itemContent": "MYCODE"}})
    for k, v in over.items():
        setattr(C, k, v)


CLAIMABLE = {
    "name": "test-giveaway",
    "start_time": "2020-01-01T00:00:00+00:00",
    "end_time": "2030-01-01T00:00:00+00:00",
    "minimum_trust_level": 1,
    "price": "0",
    "available_items_count": 5,
    "is_completed": False,
    "is_received": False,
}


def main():
    print("\n=== 1. 预检：user-info 不可用时不能误判为 L0 ===")
    info = {**CLAIMABLE, "minimum_trust_level": 2}
    p = C.precheck_eligibility(info, {})
    check("未知用户 -> 放行（等级门槛跳过）", p.go, p.reason)
    check("未知用户 -> trust_level 记为 None 而非 0", p.trust_level is None, repr(p.trust_level))
    p = C.precheck_eligibility(info, {"trust_level": 0, "score": 100})
    check("真实 L0 -> 仍被等级门槛拦下", (not p.go) and p.reason == "trust_level", p.reason)
    p = C.precheck_eligibility(info, {"trust_level": 3, "score": 100})
    check("真实数据齐全且达标 -> 放行", p.go, p.reason)
    priced = {**info, "price": "10"}
    p = C.precheck_eligibility(priced, {"trust_level": 3, "score": 5})
    check("price>score -> 积分不足", (not p.go) and p.reason == "insufficient_score", p.reason)
    p = C.precheck_eligibility(priced, {"trust_level": 3, "score": 10})
    check("price==score -> 放行", p.go, p.reason)
    p = C.precheck_eligibility(priced, {})
    check("积分未知 -> 跳过积分门槛而非误判为 0", p.go, p.reason)

    print("\n=== 2. 回读确认：报失败但码已到手 ===")
    res = C.ClaimResult(project_id=PID, reason="cloudflare", error="cloudflare challenged the claim request")
    _install({}, info={**CLAIMABLE, "is_received": True, "received_content": "CODE123"})
    C.confirm_received(res, _Sess())
    check("失败 -> 回读确认成功", res.ok, res.reason)
    check("回读取到码", res.content == "CODE123", res.content)
    check("reason 标记为 confirmed_after_failure", res.reason == "confirmed_after_failure", res.reason)
    check("清掉误导性的 error", res.error == "", res.error)

    res = C.ClaimResult(project_id=PID, reason="out_of_stock", error="抢光")
    _install({}, info={**CLAIMABLE, "is_received": False})
    C.confirm_received(res, _Sess())
    check("确实没领到 -> 维持失败（不谎报成功）", (not res.ok) and res.reason == "out_of_stock", res.reason)

    print("\n=== 3. user-info 被 CF 挑战时不得放弃领取（04:01 的真实故障）===")
    calls = {"n": 0}

    def challenged_user_info(cl):
        calls["n"] += 1
        raise PermissionError("cloudflare")

    _install({}, info=dict(CLAIMABLE), user=challenged_user_info)
    res = C.claim_link(LINK)
    check("user-info 两次被挑战 -> 仍领取成功", res.ok, f"reason={res.reason} error={res.error}")
    check("取回码内容", res.content == "MYCODE", res.content)
    check("user-info 重试过一次（共 2 次）", calls["n"] == 2, calls["n"])
    check("trust_level 标记为未知 -1", res.trust_level == -1, repr(res.trust_level))

    print("\n=== 4. 抢光终结（不烧打码费）+ 回读不谎报 ===")
    caps = {"n": 0}

    def counting_captcha(url):
        caps["n"] += 1
        return ("tok", "UA")

    _install(
        {},
        info=dict(CLAIMABLE),
        captcha=counting_captcha,
        receive=lambda pid, tok, cl: {"error_msg": "领取人数过多，该奖品已抢光"},
    )
    res = C.claim_link(LINK)
    check("抢光（远超宽限期）-> 终结 out_of_stock", res.reason == "out_of_stock", res.reason)
    check("只打码 1 次（不再每 1s 重打）", caps["n"] == 1, caps["n"])
    check("回读无果 -> 不谎报成功", not res.ok, res.reason)

    print("\n=== 5. 打码失败 -> 仍走回读确认 ===")
    _install(
        {},
        info={**CLAIMABLE, "is_received": True, "received_content": "RESCUED"},
        captcha=lambda url: ("", "UA"),
    )
    res = C.claim_link(LINK)
    check("打码失败但码已到手 -> 救回", res.ok and res.content == "RESCUED", f"{res.ok}/{res.content}")

    print(f"\n{'=' * 46}\n通过 {len(PASS)} / {len(PASS) + len(FAIL)}")
    if FAIL:
        print("失败项:")
        for f in FAIL:
            print("  -", f)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
