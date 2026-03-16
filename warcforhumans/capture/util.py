import urllib.parse

_TYPE_SOCKET_OPTIONS = list[tuple[int, int, int | bytes]]

def normalize_netloc(orig: str, scheme: str | None = None, port: int | None = None) -> str:
    if port is not None:
        orig = orig + ":" + str(port)

    if scheme is not None:
        orig = scheme + "://" + orig

    if not "//" in orig:
        orig = "//" + orig

    parts = urllib.parse.urlsplit(orig)
    print(parts)
    if parts.netloc:
        return parts.netloc
    else:
        raise ValueError("Could not parse netloc for " + orig)