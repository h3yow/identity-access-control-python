"""签名密钥轮换测试：旧 kid 立即失效，任意时刻仅一把活动密钥。"""

from __future__ import annotations

import logging
import threading

from auth.keys import KeyManager

log = logging.getLogger("test.keys")


def test_initial_key_usable() -> None:
    km = KeyManager()
    kid, sig = km.sign("payload")
    log.info("input=payload 判定依据=当前 kid=%s 签名可验", kid[:8])
    assert km.verify(kid, "payload", sig) == (True, True)


def test_rotation_drops_old_key_immediately() -> None:
    km = KeyManager()
    old_kid, sig = km.sign("payload")
    new_kid = km.rotate()
    log.info("input=old_kid=%s new_kid=%s 判定依据=旧 kid 校验返回 (False, False)",
             old_kid[:8], new_kid[:8])
    assert new_kid != old_kid
    assert km.verify(old_kid, "payload", sig) == (False, False)


def test_concurrent_rotations_leave_single_active_key() -> None:
    km = KeyManager()
    seen: list[str] = []

    def worker() -> None:
        seen.append(km.rotate())

    threads = [threading.Thread(target=worker) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    current = km.current_kid
    log.info("input=20 线程并发轮换 判定依据=最终仅一把活动密钥 current=%s", current[:8])
    assert current == seen[-1]
    # 只有最终密钥可验签
    _, sig = km.sign("p")
    assert km.verify(current, "p", sig) == (True, True)
    # 过程中产生的旧 kid 全部不可验
    for kid in seen[:-1]:
        assert not km.verify(kid, "p", sig)[0]
