import re


def safe_text(value: bytes | str, limit: int = 2048) -> str:
    """Strip terminal control sequences and non-printing characters from evidence."""
    text = value.decode("utf-8", errors="replace") if isinstance(value, bytes) else value
    text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
    return "".join(c for c in text if c in "\n\t" or ord(c) >= 32 and ord(c) != 127)[:limit]
