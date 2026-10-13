import re

_NON_WORD = re.compile(r"[^a-z0-9]+")


def slugify(title: str) -> str:
    """Lowercase, collapse non-alphanumerics to single dashes."""
    return _NON_WORD.sub("-", title.lower()).strip("-")
