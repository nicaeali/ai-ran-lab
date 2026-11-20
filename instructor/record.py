#!/usr/bin/env python3
"""Display stdin and save each output line with its observation timestamp."""

import fcntl
import json
import re
import sys
import time


def main():
    if len(sys.argv) != 2:
        raise SystemExit("Usage: record.py OUTPUT.jsonl")
    with open(sys.argv[1], "x") as output:
        fcntl.flock(output, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            for line in sys.stdin:
                # Docker can emit terminal-control sequences even in a pipe.
                line = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", line).rstrip()
                if line:
                    output.write(json.dumps({"epoch": time.time(), "line": line}) + "\n")
                    output.flush()
                    print(line, flush=True)
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
