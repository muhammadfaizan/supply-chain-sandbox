"""Find which ecosystems a folder uses, from the dependency files it contains."""
import os
from pathlib import Path

ECOSYSTEMS = ("pypi", "npm", "rubygems", "go")

# Folders that hold generated or vendored code, not the project's own dependency files.
SKIP_DIRS = {".git", "node_modules", "vendor", ".venv", "venv",
             "__pycache__", "build", "dist"}


def classify(name: str):
    """Map a file name to the ecosystem it describes, or None."""
    if name.startswith("requirements") and name.endswith(".txt"):
        return "pypi"
    if name in {"setup.py", "setup.cfg", "pyproject.toml", "Pipfile.lock", "poetry.lock"}:
        return "pypi"
    if name in {"package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"}:
        return "npm"
    if name in {"Gemfile", "Gemfile.lock"} or name.endswith(".gemspec"):
        return "rubygems"
    if name in {"go.mod", "go.sum"}:
        return "go"
    return None


def iter_files(root: Path):
    """Yield regular files under root, in a stable order.

    Symbolic links are skipped. A repository could link a file to a path on the
    host (for example ~/.ssh/config), and the scanner must not read it.
    """
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            path = Path(dirpath) / name
            if not path.is_symlink():
                yield path


def detect_ecosystems(root: Path) -> dict:
    """Return {ecosystem: [relative manifest paths]} for the files found under root."""
    found = {}
    for path in iter_files(root):
        eco = classify(path.name)
        if eco:
            found.setdefault(eco, []).append(str(path.relative_to(root)))
    return found
