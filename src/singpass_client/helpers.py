import random
import string
import hashlib
import base64
import datetime
from urllib.parse import urlencode as _urlencode
from typing import Any

UNICODE_ASCII_CHARACTER_SET = string.ascii_letters + string.digits


def urlsafe_b64encode(s: bytes) -> bytes:
    """Apply base64 url-safe encoding.

    Args:
        s (bytes): data to be encoded.

    Returns:
        bytes: encoded data.
    """
    return base64.urlsafe_b64encode(s).rstrip(b"=")


def generate_token(length: int = 43, chars=UNICODE_ASCII_CHARACTER_SET) -> str:
    """Generate random secret.

    Args:
        length (int, optional): size of the token. Defaults to 43.
        chars (_type_, optional): _description_. Defaults to UNICODE_ASCII_CHARACTER_SET.

    Returns:
        str: secret.
    """
    rand = random.SystemRandom()
    return "".join(rand.choice(chars) for _ in range(length))


def to_bytes(x: Any, charset: str = "utf-8", errors: str = "strict") -> bytes | None:
    """Type cast into bytes.

    Args:
        x (Any): data
        charset (str, optional): _description_. Defaults to "utf-8".
        errors (str, optional): _description_. Defaults to "strict".

    Returns:
        bytes: bytes typed data.
    """
    if x is None:
        return None
    if isinstance(x, bytes):
        return x
    if isinstance(x, str):
        return x.encode(charset, errors)
    if isinstance(x, (int, float)):
        return str(x).encode(charset, errors)
    return bytes(x)


def to_unicode(x: str | bytes, charset: str = "utf-8", errors: str = "strict") -> str:
    """Convert into unicode.

    Args:
        x (str | bytes): data
        charset (str, optional): _description_. Defaults to "utf-8".
        errors (str, optional): _description_. Defaults to "strict".

    Returns:
        str: converted data.
    """
    if x is None or isinstance(x, str):
        return x
    if isinstance(x, bytes):
        return x.decode(charset, errors)
    return str(x)


def create_s256_code_challenge(code_verifier: str) -> str:
    """Create S256 code_challenge with the given code_verifier.

    Args:
        code_verifier (str): code_verifier.

    Returns:
        str: hashed code_verifier.
    """
    data = hashlib.sha256(to_bytes(code_verifier, "ascii")).digest()
    return to_unicode(urlsafe_b64encode(data))


def url_encode(params: list[tuple]) -> str:
    """Convert list of data in url-safe query parameters string.

    Args:
        params (list[tuple]): list of data.

    Returns:
        str: query parameter string.
    """
    encoded = []
    for k, v in params:
        encoded.append((to_bytes(k), to_bytes(v)))
    return to_unicode(_urlencode(encoded))


def get_current_timestamp() -> int:
    """Give current iso time in unix timestamp.

    Returns:
        int: unix timestamp in int.
    """
    return int(datetime.datetime.now(datetime.timezone.utc).timestamp())
