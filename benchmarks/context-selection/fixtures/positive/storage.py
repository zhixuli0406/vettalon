from pathlib import Path

def read_record(name):
    return (Path('/tmp/synthetic-public') / name).read_text()
