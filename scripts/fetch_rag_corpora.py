#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
import time
import urllib.request
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RAW_DIR = ROOT / "data" / "rag" / "raw"

SOURCES = {
    "attack_enterprise": "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
    "sigma": "https://github.com/SigmaHQ/sigma/archive/refs/heads/master.zip",
    "cwe": "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip",
}

D3FEND_CANDIDATES = (
    "https://d3fend.mitre.org/ontologies/d3fend.json",
    "https://d3fend.mitre.org/ontologies/d3fend.owl",
    "https://d3fend.mitre.org/ontologies/d3fend.ttl",
)


def log(message: str) -> None:
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {message}", flush=True)


def download(url: str, output: Path, timeout: int = 120) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    log(f"download start url={url} output={output}")
    request = urllib.request.Request(url, headers={"User-Agent": "soc-defender-rag-builder/0.1"})
    started = time.time()
    with urllib.request.urlopen(request, timeout=timeout) as response:
        with output.open("wb") as f:
            shutil.copyfileobj(response, f)
    log(f"download complete output={output} bytes={output.stat().st_size} seconds={time.time() - started:.1f}")


def fetch_attack(raw_dir: Path) -> dict[str, object]:
    log("fetch ATT&CK Enterprise")
    output = raw_dir / "attack" / "enterprise-attack.json"
    download(SOURCES["attack_enterprise"], output)
    return {"name": "attack_enterprise", "path": str(output), "bytes": output.stat().st_size}


def fetch_cwe(raw_dir: Path, work_dir: Path) -> dict[str, object]:
    log("fetch CWE")
    archive = work_dir / "cwec_latest.xml.zip"
    download(SOURCES["cwe"], archive)
    output_dir = raw_dir / "cwe"
    output_dir.mkdir(parents=True, exist_ok=True)
    extracted: list[str] = []
    with zipfile.ZipFile(archive) as zf:
        for member in zf.namelist():
            if member.lower().endswith(".xml"):
                target = output_dir / Path(member).name
                target.write_bytes(zf.read(member))
                extracted.append(str(target))
    log(f"extract CWE files={len(extracted)}")
    return {"name": "cwe", "archive": str(archive), "files": extracted}


def fetch_sigma(raw_dir: Path, work_dir: Path, max_rules: int) -> dict[str, object]:
    log(f"fetch Sigma max_rules={max_rules}")
    archive = work_dir / "sigma-master.zip"
    download(SOURCES["sigma"], archive)
    output_dir = raw_dir / "sigma"
    output_dir.mkdir(parents=True, exist_ok=True)
    extracted: list[str] = []
    with zipfile.ZipFile(archive) as zf:
        members = [
            member
            for member in zf.namelist()
            if "/rules/" in member and member.lower().endswith((".yml", ".yaml"))
        ]
        log(f"sigma rules found={len(members)} extracting={min(len(members), max_rules)}")
        for member in members[:max_rules]:
            relative = Path(*Path(member).parts[2:])
            target = output_dir / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(zf.read(member))
            extracted.append(str(target))
            if len(extracted) % 500 == 0:
                log(f"sigma extracted={len(extracted)}")
    log(f"sigma extract complete files={len(extracted)}")
    return {"name": "sigma", "archive": str(archive), "files": len(extracted), "max_rules": max_rules}


def fetch_d3fend(raw_dir: Path) -> dict[str, object]:
    log("fetch D3FEND")
    output_dir = raw_dir / "d3fend"
    output_dir.mkdir(parents=True, exist_ok=True)
    errors: list[str] = []
    for url in D3FEND_CANDIDATES:
        suffix = Path(url).suffix or ".txt"
        output = output_dir / f"d3fend{suffix}"
        try:
            download(url, output)
            log(f"D3FEND selected url={url}")
            return {"name": "d3fend", "url": url, "path": str(output), "bytes": output.stat().st_size}
        except Exception as exc:
            log(f"D3FEND candidate failed url={url} error={exc}")
            errors.append(f"{url}: {exc}")
    return {"name": "d3fend", "error": "all candidates failed", "candidates": list(D3FEND_CANDIDATES), "errors": errors}


def main() -> int:
    parser = argparse.ArgumentParser(description="Fetch public external corpora for soc_defender RAG.")
    parser.add_argument("--raw-dir", default=str(RAW_DIR))
    parser.add_argument("--work-dir", default=str(ROOT / "outputs" / "rag_downloads"))
    parser.add_argument("--max-sigma-rules", type=int, default=1500)
    parser.add_argument("--skip-sigma", action="store_true")
    args = parser.parse_args()

    raw_dir = Path(args.raw_dir)
    work_dir = Path(args.work_dir)
    raw_dir.mkdir(parents=True, exist_ok=True)
    work_dir.mkdir(parents=True, exist_ok=True)
    log(f"raw_dir={raw_dir}")
    log(f"work_dir={work_dir}")

    manifest = {
        "sources": [],
        "notes": [
            "External security corpora only.",
            "Do not add OpenSec seeds, ground truth, oracle internals, eval data, or replay caches.",
        ],
    }
    manifest["sources"].append(fetch_attack(raw_dir))
    manifest["sources"].append(fetch_cwe(raw_dir, work_dir))
    if not args.skip_sigma:
        manifest["sources"].append(fetch_sigma(raw_dir, work_dir, args.max_sigma_rules))
    manifest["sources"].append(fetch_d3fend(raw_dir))

    manifest_path = raw_dir / "corpus_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2))
    log(f"manifest written path={manifest_path}")
    print(json.dumps({"manifest": str(manifest_path), "sources": manifest["sources"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
