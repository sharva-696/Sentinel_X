from backend.app.utils.masking import (
    mask_secret,
    mask_wifi_credential,
    mask_private_key,
    mask_url_credentials,
    sanitize_evidence,
)


def test_mask_secret():
    assert mask_secret("short", 2, 2) == "sh*rt"
    assert mask_secret("AKIAIOSFODNN7EXAMPLE", 4, 2) == "AKIA**************LE"
    assert mask_secret("abc", 2, 2) == "***"
    assert mask_secret("") == ""


def test_mask_wifi_credential():
    raw = "wifi_password = 'super_secret_pass';"
    masked = mask_wifi_credential(raw)
    assert "super_secret_pass" not in masked
    assert "wifi_password = '*****************'" in masked


def test_mask_private_key():
    raw_pem = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Z3v9xM...PRIVATE_KEY_DATA...
-----END RSA PRIVATE KEY-----"""
    masked = mask_private_key(raw_pem)
    assert "PRIVATE_KEY_DATA" not in masked
    assert "[REDACTED PRIVATE KEY MATERIAL]" in masked
    assert "-----BEGIN RSA PRIVATE KEY-----" in masked
    assert "-----END RSA PRIVATE KEY-----" in masked


def test_mask_url_credentials():
    url = "mqtt://admin:SuperSecretMQTT123@192.168.1.100:1883"
    masked = mask_url_credentials(url)
    assert "SuperSecretMQTT123" not in masked
    assert "mqtt://admin:******@192.168.1.100:1883" == masked


def test_sanitize_evidence_aws():
    evidence = "Found AWS Key: AKIA1234567890ABCDEF in segment DROM"
    sanitized = sanitize_evidence(evidence)
    assert "AKIA1234567890ABCDEF" not in sanitized
    assert "AKIA" in sanitized
    assert "EF" in sanitized


def test_sanitize_evidence_unquoted_pw_and_softap():
    evidence = '>>> Connect to Wi-Fi "SentinelRT-Control" (pw: sentinel123) and open http://192.168.4.1/ <<<'
    sanitized = sanitize_evidence(evidence)
    assert "sentinel123" not in sanitized
    assert '(pw: ***********)' in sanitized
    assert 'SentinelRT-Control' in sanitized
    assert 'http://192.168.4.1/' in sanitized

