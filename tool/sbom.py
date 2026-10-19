#!/usr/bin/env python3
"""Generate or verify source-derived CycloneDX SBOMs for release builds.

Requires Go 1.27.2 and checksum-verified cyclonedx-gomod v1.12.0 on PATH.
No application dependencies are added by this script.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
TARGETS = (("linux", "amd64"), ("linux", "arm64"), ("linux", "arm"),
           ("windows", "amd64"), ("windows", "arm64"))
INPUT_FILES = ("go.mod", "go.sum", "build-tags.txt", ".goreleaser.yaml")


def checked(*args, cwd=ROOT, env=None):
    return subprocess.run(args, cwd=cwd, env=env, check=True,
                          text=True, capture_output=True).stdout


def source_digest(source):
    # Include tracked Go files even when they do not affect the current target.
    names = checked("git", "ls-files", "--", "*.go", *INPUT_FILES, cwd=source).splitlines()
    h = hashlib.sha256()
    for name in sorted(names):
        path = source / name
        if not path.is_file():
            raise ValueError(f"Tracked source missing: {name}")
        payload = path.read_bytes()
        h.update(name.encode() + b"\0" + str(len(payload)).encode() + b"\0" + payload)
    return h.hexdigest()


def normalize(data, digest):
    root = data["metadata"]["component"]
    old = root["version"]
    new = "v0.0.0-sbom." + digest[:16]
    old_ref = root["bom-ref"]
    new_ref = old_ref.replace("@" + old + "?", "@" + new + "?", 1)
    if old_ref == new_ref:
        raise ValueError("Missing root version in CycloneDX bom-ref")
    root["version"] = new
    root["bom-ref"] = new_ref
    root["purl"] = root["purl"].replace("@" + old + "?", "@" + new + "?", 1)
    root.setdefault("properties", []).append({
        "name": "tailcat:source-inputs:sha256", "value": digest
    })
    matches = 0
    for edge in data["dependencies"]:
        if edge["ref"] == old_ref:
            edge["ref"] = new_ref
            matches += 1
    if matches != 1:
        raise ValueError(f"Expected one root dependency edge, found {matches}")
    stdlib = [c for c in data["components"] if c.get("name") == "std"]
    if len(stdlib) != 1 or stdlib[0].get("version") != "go1.27.2":
        raise ValueError("Go standard-library component missing or unexpected version")
    if not stdlib[0].get("evidence", {}).get("licenses"):
        # Confirmed against the Go 1.27.2 toolchain LICENSE file.
        stdlib[0].setdefault("evidence", {}).setdefault("licenses", []).append({
            "license": {"id": "BSD-3-Clause"}
        })
    stdlib[0].setdefault("properties", []).append({
        "name": "tailcat:stdlib-license-source",
        "value": "https://go.googlesource.com/go/+/refs/tags/go1.27.2/LICENSE"
    })
    return data


def generate(source, destination):
    if shutil.which("cyclonedx-gomod") is None:
        raise RuntimeError("Install checksum-verified cyclonedx-gomod v1.12.0")
    version = checked("cyclonedx-gomod", "version")
    if "v1.12.0" not in version:
        raise RuntimeError("Expected cyclonedx-gomod v1.12.0, got " + version[:100])
    go_version = checked("go", "version")
    if "go1.27.2" not in go_version:
        raise RuntimeError("Expected Go 1.27.2, got " + go_version.strip())
    digest = source_digest(source)
    tags = (source / "build-tags.txt").read_text().strip()
    for goos, goarch in TARGETS:
        env = dict(os.environ, GOOS=goos, GOARCH=goarch, GOARM="7",
                   CGO_ENABLED="0", GOFLAGS="-tags=" + tags)
        output = destination / f"tailcat-{goos}-{goarch}.cdx.json"
        checked("cyclonedx-gomod", "app", "-main", "cmd/tailcat", "-std",
                "-noserial", "-notimestamp", "-json", "-licenses", "-output",
                str(output), ".", cwd=source, env=env)
        data = normalize(json.loads(output.read_text()), digest)
        if data["bomFormat"] != "CycloneDX" or data["specVersion"] != "1.6":
            raise ValueError(f"Unsupported SBOM version: {output}")
        props = data["metadata"]["component"]["properties"]
        actual = {p["value"] for p in props if p["name"] == "cdx:gomod:build:tag"}
        if actual != set(tags.split(",")):
            raise ValueError(f"Incorrect release tags for {goos}/{goarch}")
        output.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n")
        yield output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("generate", "check"))
    args = parser.parse_args()
    # A full local clone works in Git worktrees where cyclonedx-gomod cannot
    # resolve the module pseudoversion from the .git gitdir pointer.
    head = checked("git", "rev-parse", "HEAD").strip()
    with tempfile.TemporaryDirectory(prefix="tailcat-sbom-", dir=os.environ.get("TMPDIR")) as tmp:
        tmpdir = Path(tmp)
        source = tmpdir / "source"
        checked("git", "clone", "--quiet", "--no-hardlinks", str(ROOT), str(source))
        checked("git", "checkout", "--quiet", "--detach", head, cwd=source)
        outdir = tmpdir / "out"
        outdir.mkdir()
        expected = ROOT / "sbom"
        outputs = list(generate(source, outdir))
        for p in outputs:
            target = expected / p.name
            if args.action == "generate":
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(p, target)
                print("generated", target.relative_to(ROOT))
            elif not target.is_file() or json.loads(target.read_text()) != json.loads(p.read_text()):
                print("SBOM stale:", target.relative_to(ROOT), file=sys.stderr)
                return 1
            else:
                print("verified", target.relative_to(ROOT))
    return 0


if __name__ == "__main__":
    sys.exit(main())
