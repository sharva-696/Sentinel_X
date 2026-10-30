import re


def mask_secret(value: str, prefix_len: int = 4, suffix_len: int = 2) -> str:
    """
    Masks a sensitive string preserving a short prefix and suffix.
    Example: AKIAIOSFODNN7EXAMPLE (len 20, prefix 4, suffix 2) -> AKIA**************LE
    """
    if not value:
        return ""
    length = len(value)
    if length <= (prefix_len + suffix_len):
        return "*" * length
    return value[:prefix_len] + ("*" * (length - prefix_len - suffix_len)) + value[-suffix_len:]


def mask_wifi_credential(text: str) -> str:
    """
    Masks password or passphrase in Wi-Fi connection strings across all ESP-IDF and Arduino variants.
    Matches: wifi_password, wifi_pass, wpa_passphrase, psk, wifi_sta_pwd, sta_pwd, ap_pwd, wifi_key, wifi_pw, ap_pw, sta_pw, WiFi.begin.
    Example: 'wifi_sta_pwd = "super_secret_pass"' -> 'wifi_sta_pwd = "*****************"'
    """
    # Arduino / ESP-IDF WiFi.begin("SSID", "Password")
    text = re.sub(
        r'(?i)(WiFi\.begin\s*\(\s*["\'][^"\']+["\']\s*,\s*["\'])([^"\']+)(["\'])',
        lambda m: f"{m.group(1)}{'*' * len(m.group(2))}{m.group(3)}",
        text,
    )

    pattern = (
        r"(?i)([\"']?\b(?:wifi_password|wifi_pass|wpa_passphrase|psk|wifi_sta_pwd|sta_pwd|ap_pwd|wifi_key|wifi_pw|ap_pw|sta_pw)\b[\"']?"
        r"\s*[:=]\s*[\"']?)([^\s\"';,{}()]+)([\"']?)"
    )

    def repl(m):
        prefix = m.group(1)
        val = m.group(2)
        q_end = m.group(3)
        return f"{prefix}{'*' * len(val)}{q_end}"

    return re.sub(pattern, repl, text)


def mask_generic_credentials(text: str) -> str:
    """
    Masks common password, token, or secret assignments in configuration strings and JSON objects.
    Example: 'password = "secret123"' -> 'password = "*********"'
    Example: '{"password": "secret123"}' -> '{"password": "*********"}'
    Example: '(pw: sentinel123)' -> '(pw: ***********)'
    """
    pattern = (
        r"(?i)([\"']?\b(?:password|passwd|passcode|user_password|admin_password|secret_key|api_secret|client_secret|root_pwd|pw|pwd)\b[\"']?"
        r"\s*[:=]\s*[\"']?)([^\s\"';,{}()]+)([\"']?)"
    )

    def repl(m):
        prefix = m.group(1)
        val = m.group(2)
        q_end = m.group(3)
        return f"{prefix}{'*' * len(val)}{q_end}"

    return re.sub(pattern, repl, text)


def mask_private_key(text: str) -> str:
    """
    Redacts private key material when PEM boundaries are detected.
    Handles both full certificate blocks and isolated header strings.
    """
    if re.search(r"-----END [A-Z ]*PRIVATE KEY-----", text):
        return re.sub(
            r"(-----BEGIN [A-Z ]*PRIVATE KEY-----)(.*?)(-----END [A-Z ]*PRIVATE KEY-----)",
            r"\1\n[REDACTED PRIVATE KEY MATERIAL]\n\3",
            text,
            flags=re.DOTALL,
        )
    return re.sub(
        r"(-----BEGIN [A-Z ]*PRIVATE KEY-----).*",
        r"\1\n[REDACTED PRIVATE KEY MATERIAL]",
        text,
        flags=re.DOTALL,
    )


def mask_url_credentials(url: str) -> str:
    """
    Masks username:password embedded in URLs.
    Example: mqtt://admin:secret@broker.com -> mqtt://admin:******@broker.com
    """
    return re.sub(r"://([^:]+):([^@]+)@", lambda m: f"://{m.group(1)}:******@", url)


def sanitize_evidence(evidence: str) -> str:
    """
    Runs multi-pass redaction to ensure evidence snippets in findings, logs, and reports
    never expose raw sensitive material.
    """
    sanitized = mask_private_key(evidence)
    sanitized = mask_wifi_credential(sanitized)
    sanitized = mask_generic_credentials(sanitized)
    sanitized = mask_url_credentials(sanitized)

    # AWS Key ID mask
    sanitized = re.sub(r"\b(AKIA[0-9A-Z]{16})\b", lambda m: mask_secret(m.group(1), 4, 2), sanitized)

    # GitHub token mask
    sanitized = re.sub(r"\b(gh[pousr]_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{22,})\b", lambda m: mask_secret(m.group(1), 4, 2), sanitized)

    # Generic Bearer tokens
    sanitized = re.sub(
        r"(?i)(bearer\s+)([a-zA-Z0-9_\-\.]{15,})",
        lambda m: f"{m.group(1)}{mask_secret(m.group(2), 2, 2)}",
        sanitized,
    )

    return sanitized
