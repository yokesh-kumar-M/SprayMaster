def load_list(path: str) -> list:
    with open(path, "r", encoding="latin-1") as f:
        return [
            line.strip()
            for line in f
            if line.strip() and not line.strip().startswith("#")
        ]


def load_combo_list(path: str) -> list:
    """Return list of (user, pass) tuples from a user:pass file."""
    pairs = []
    with open(path, "r", encoding="latin-1") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" in line:
                user, _, password = line.partition(":")
                pairs.append((user, password))
    return pairs
