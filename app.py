from pathlib import Path
import runpy
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

runpy.run_path(
    str(ROOT / "src" / "frontend" / "app.py"),
    run_name="__main__",
)
