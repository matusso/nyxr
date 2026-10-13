"""Separately registered post-panic sequential BSD VNET study."""
import argparse
import json
from pathlib import Path

import bsd_study as study

study.PROTOCOL = json.loads((Path(__file__).resolve().parent / "bsd-study-sequential-protocol.json").read_text())

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("run", "analyze"))
    parser.add_argument("--binary", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--fixtures")
    parser.add_argument("--interface")
    args = parser.parse_args()
    if args.command == "run":
        if not args.fixtures or not args.interface: parser.error("run requires explicit fixtures and interface")
        study.collect(args)
    else: print(json.dumps(study.analyze(Path(args.output), args.binary)["strata"], indent=2))
