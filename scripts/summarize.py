#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OPENSEC_ROOT = ROOT.parent / "opensec-env"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(OPENSEC_ROOT) not in sys.path:
    sys.path.insert(0, str(OPENSEC_ROOT))

_SPEC = importlib.util.spec_from_file_location("opensec_summarize", OPENSEC_ROOT / "scripts" / "summarize.py")
if _SPEC is None or _SPEC.loader is None:
    raise RuntimeError("Could not load OpenSec summarize.py")
_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)
summarize = _MODULE.summarize
summarize_stratified = _MODULE.summarize_stratified
summarize_thresholds = _MODULE.summarize_thresholds


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("files", nargs="*", help="JSONL files to summarize")
    parser.add_argument("--glob", default=None, help="Glob pattern, relative to soc_defender")
    parser.add_argument("--output", default="outputs/baseline_summary.json")
    parser.add_argument("--manifest", default=str(OPENSEC_ROOT / "data" / "seeds" / "manifest.json"))
    parser.add_argument("--stratify-by", choices=["taxonomy_family", "tier"], help="Group results by seed property")
    parser.add_argument("--thresholds", action="store_true", help="Print defensive capability threshold classification per model")
    args = parser.parse_args()

    if args.files:
        paths = [Path(f) for f in args.files]
    elif args.glob:
        paths = sorted(Path(".").glob(args.glob))
    else:
        paths = sorted(Path("outputs").glob("llm_baselines*.jsonl"))

    if args.thresholds:
        summarize_thresholds(paths)
        return 0

    if args.stratify_by:
        summarize_stratified(paths, args.stratify_by, Path(args.manifest))
        return 0

    summary = summarize(paths)
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(summary, indent=2))
    print(f"OK: wrote {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
