import sys
from pathlib import Path

# Ensure repo root is importable so `import spraymaster` works when tests are
# invoked without an editable install.
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
