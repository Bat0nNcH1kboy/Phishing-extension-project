import socket

from dns_checker import DnsResult, resolve_domain, resolve_domain_cached


def test_dns_skips_ip_address():
    result = resolve_domain("127.0.0.1")
    assert result.checked is False
    assert result.resolvable is True


def test_dns_success_with_mock(monkeypatch):
    resolve_domain_cached.cache_clear()

    def fake_resolve(hostname):
        return ("93.184.216.34",)

    monkeypatch.setattr("dns_checker._resolve_sync", fake_resolve)
    result = resolve_domain("example.test", timeout_seconds=0.2)
    assert result.checked is True
    assert result.resolvable is True
    assert result.addresses == ("93.184.216.34",)


def test_dns_failure_with_mock(monkeypatch):
    resolve_domain_cached.cache_clear()

    def fake_resolve(hostname):
        raise socket.gaierror("not found")

    monkeypatch.setattr("dns_checker._resolve_sync", fake_resolve)
    result = resolve_domain("missing.test", timeout_seconds=0.2)
    assert result.checked is True
    assert result.resolvable is False
    assert "dns lookup failed" in (result.error or "")


def test_dns_result_hides_addresses_by_default():
    result = DnsResult("example.com", True, True, ("1.1.1.1",), 1)
    assert result.to_dict()["addresses"] == []
    assert result.to_dict(include_addresses=True)["addresses"] == ["1.1.1.1"]
