import pytest

from app.evasion_rotation import FingerprintRotator, ProtocolRotator


class Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


def test_fingerprint_rotation_never_repeats_and_respects_interval():
    clock = Clock()
    rot = FingerprintRotator(interval_seconds=100, clock=clock)
    first = rot.current()
    assert rot.current() == first  # inside the interval
    clock.t = 101
    seen = {first}
    for _ in range(50):
        prev = rot.current()
        nxt = rot.rotate()
        assert nxt != prev
        seen.add(nxt)
    assert len(seen) > 2


def test_flagged_fingerprint_is_quarantined_then_released():
    clock = Clock()
    rot = FingerprintRotator(pool=("chrome", "firefox"), flag_cooldown_seconds=60, clock=clock)
    rot.mark_flagged("chrome")
    for _ in range(20):
        assert rot.rotate() == "firefox"
    clock.t = 61
    assert "chrome" in {rot.rotate() for _ in range(40)}


def test_current_rotates_away_when_flagged():
    rot = FingerprintRotator(pool=("chrome", "firefox", "safari"))
    cur = rot.current()
    rot.mark_flagged(cur)
    assert rot.current() != cur


def test_protocol_failover_and_recovery():
    clock = Clock()
    rot = ProtocolRotator(order=("a", "b", "c"), failure_threshold=2, cooldown_seconds=100, clock=clock)
    assert rot.next_protocol() == "a"
    rot.report("a", False)
    assert rot.next_protocol() == "a"  # below threshold
    rot.report("a", False)
    assert rot.next_protocol() == "b"
    rot.report("b", False), rot.report("b", False), rot.report("c", False), rot.report("c", False)
    assert rot.next_protocol() is None
    clock.t = 101  # cooldown over: half-open retry, one more failure re-blocks
    assert rot.next_protocol() == "a"
    rot.report("a", False)
    assert rot.is_blocked("a")
    rot.report("b", True)
    assert not rot.is_blocked("b")


def test_unknown_protocol_reports_are_ignored():
    rot = ProtocolRotator(order=("a",))
    rot.report("zzz", False)
    assert rot.status()["failures"] == {}


def test_empty_pools_rejected():
    with pytest.raises(ValueError):
        FingerprintRotator(pool=())
    with pytest.raises(ValueError):
        ProtocolRotator(order=())


def test_hysteria2_port_hop_share_url_and_rules():
    from app.protocol_engine import ClientConfigGenerator, SingboxConfigGenerator

    url = ClientConfigGenerator.generate_hysteria2_share_url(
        "pw", "203.0.113.1", 8443, sni="example.com", obfs="salt", port_hop="20000-30000"
    )
    assert "mport=20000-30000" in url and "obfs=salamander" in url
    assert "mport" not in ClientConfigGenerator.generate_hysteria2_share_url("pw", "203.0.113.1", 8443)

    rules = SingboxConfigGenerator.hysteria2_port_hop_rules("20000-30000", 8443)
    assert [r[0] for r in rules] == ["iptables", "ip6tables"]
    assert all("20000:30000" in r and r[-1] == "8443" for r in rules)


@pytest.mark.parametrize("bad", ["abc", "20000", "100-200", "30000-20000", "8000-9000", "20000-99999", "1;rm-2"])
def test_port_hop_rejects_bad_ranges(bad):
    from app.protocol_engine import SingboxConfigGenerator

    with pytest.raises(ValueError):
        SingboxConfigGenerator.hysteria2_port_hop_rules(bad, 8443)


def test_plain_wireguard_is_registered():
    from app.protocol_engine import PROTOCOLS

    spec = PROTOCOLS["wireguard"]
    assert spec.backend.value == "wireguard" and spec.key == "wireguard"
