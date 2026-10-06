import os
import sys

IS_WINDOWS = sys.platform.startswith("win")

# Extensions treated as executable/scannable on every OS
WIN_EXT = (".exe", ".dll", ".msi", ".bat", ".cmd", ".scr", ".ps1")
NIX_EXT = (".so", ".sh", ".appimage", ".run", ".bin", ".com")


def is_executable_file(path):
    """True if the file looks like a program (by extension, exec bit, or magic bytes)."""
    if not os.path.isfile(path) or os.path.islink(path):
        return False
    lower = path.lower()
    if lower.endswith(WIN_EXT) or lower.endswith(NIX_EXT):
        return True
    if IS_WINDOWS:
        return False
    # Linux/macOS: executables usually have no extension, so check the exec bit and magic bytes
    if os.access(path, os.X_OK):
        return True
    try:
        with open(path, "rb") as f:
            head = f.read(4)
        return head == b"\x7fELF" or head[:2] == b"#!"
    except OSError:
        return False


def fileWatcher(directory, recursive=False):
    """Return executable files in `directory` (relative paths)."""
    found = []
    if recursive:
        for root, _dirs, names in os.walk(directory):
            for n in names:
                full = os.path.join(root, n)
                if is_executable_file(full):
                    found.append(os.path.relpath(full, directory))
    else:
        for n in os.listdir(directory):
            if is_executable_file(os.path.join(directory, n)):
                found.append(n)
    for f in found:
        print(f)
    return found
