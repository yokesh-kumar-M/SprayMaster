def load_list(path: str) -> list:
    """Return a list of non-empty, non-comment lines from ``path``."""
    with open(path, encoding="latin-1") as fh:
        lines = []
        for raw in fh:
            stripped = raw.strip()
            if stripped and not stripped.startswith("#"):
                lines.append(stripped)
        return lines


def load_combo_list(path: str) -> list:
    """Return list of (user, pass) tuples from a user:pass file."""
    pairs = []
    with open(path, encoding="latin-1") as fh:
        for raw in fh:
            stripped = raw.strip()
            if not stripped or stripped.startswith("#") or ":" not in stripped:
                continue
            user, _, password = stripped.partition(":")
            pairs.append((user, password))
    return pairs
