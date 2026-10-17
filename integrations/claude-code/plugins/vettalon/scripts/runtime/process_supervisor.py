#!/usr/bin/env python3
"""Fixed POSIX group leader. Target never inherits the private status descriptor."""
import json
import os
import signal
import subprocess
import sys

CONFIG_LIMIT = 65536
STATUS_LIMIT = 1024


def main():
    config_fd, status_fd = map(int, sys.argv[1:])
    os.set_inheritable(config_fd, False)
    os.set_inheritable(status_fd, False)
    status = {"schema": 1, "exit_code": None, "error": "supervisor-error"}
    try:
        packet = bytearray()
        while True:
            data = os.read(config_fd, min(4096, CONFIG_LIMIT + 1 - len(packet)))
            if not data:
                break
            packet.extend(data)
            if len(packet) > CONFIG_LIMIT:
                raise ValueError("config limit")
        os.close(config_fd)
        config_fd = None
        config = json.loads(packet.decode("utf-8"))
        if set(config) != {"argv", "cwd", "env"}:
            raise ValueError("config keys")
        if (not isinstance(config["argv"], list) or not config["argv"]
                or not all(isinstance(v, str) for v in config["argv"])
                or not isinstance(config["cwd"], str) or not isinstance(config["env"], dict)
                or not all(isinstance(k, str) and isinstance(v, str) for k, v in config["env"].items())):
            raise ValueError("config types")
        try:
            # No pass_fds: neither config nor status is exposed to target code.
            target = subprocess.Popen(config["argv"], cwd=config["cwd"], env=config["env"],
                                      stdin=subprocess.DEVNULL, close_fds=True)
        except OSError:
            status["error"] = "process-error"
        else:
            status = {"schema": 1, "exit_code": target.wait(), "error": None}
    except Exception:
        pass
    finally:
        if config_fd is not None:
            os.close(config_fd)
        frame = (json.dumps(status, separators=(",", ":")) + "\n").encode()
        if len(frame) <= STATUS_LIMIT:
            try:
                os.write(status_fd, frame)
            except OSError:
                pass
        os.close(status_fd)
    # Keep the group identifier reserved until the parent terminates the group.
    # Do not replace this with exit/exec or reap this process in the parent first.
    while True:
        signal.pause()


if __name__ == "__main__":
    main()
