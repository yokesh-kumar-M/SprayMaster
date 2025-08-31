def load_list(path):
    with open(path, "r", encoding="latin-1") as f:
        return [line.strip() for line in f if line.strip()]

# Add utility functions here as needed.
