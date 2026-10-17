from pathlib import Path

def read_record(name):
    root = Path('/tmp/synthetic-public').resolve()
    target = (root / name).resolve()
    if not target.is_relative_to(root):
        raise PermissionError('outside fixture boundary')
    return target.read_text()
