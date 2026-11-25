"""PostToolUse hook: format and lint-fix the Python file Claude just edited."""

import json
import subprocess
import sys
from pathlib import Path

data = json.load(sys.stdin)
file = data.get("tool_input", {}).get("file_path", "")
if file.endswith(".py") and Path(file).exists():
    subprocess.run(["uv", "run", "ruff", "format", "--", file], capture_output=True, check=False)
    subprocess.run(
        ["uv", "run", "ruff", "check", "--fix", "--", file], capture_output=True, check=False
    )
