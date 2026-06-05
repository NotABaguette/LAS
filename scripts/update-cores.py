#!/usr/bin/env python3
import argparse
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path


GITHUB_API = "https://api.github.com/repos/{repo}/releases/latest"


CORES = {
    "xray": {
        "repo": "XTLS/Xray-core",
        "binary": "xray",
        "asset_patterns": {
            "amd64": r"Xray-linux-64\.zip$",
            "386": r"Xray-linux-32\.zip$",
            "arm64": r"Xray-linux-arm64-v8a\.zip$",
            "armv7": r"Xray-linux-arm32-v7a\.zip$",
        },
    },
    "sing-box": {
        "repo": "SagerNet/sing-box",
        "binary": "sing-box",
        "asset_patterns": {
            "amd64": r"sing-box-.*-linux-amd64\.tar\.gz$",
            "386": r"sing-box-.*-linux-386\.tar\.gz$",
            "arm64": r"sing-box-.*-linux-arm64\.tar\.gz$",
            "armv7": r"sing-box-.*-linux-armv7\.tar\.gz$",
        },
    },
}


def main() -> int:
    parser = argparse.ArgumentParser(description="Install latest Xray-core and sing-box release binaries.")
    parser.add_argument("--install-dir", default="/usr/local/bin")
    parser.add_argument("--state-dir", default="/var/lib/las/updater")
    parser.add_argument("--core", action="append", choices=sorted(CORES), help="Core to update. Defaults to all.")
    parser.add_argument("--force", action="store_true", help="Download and reinstall even if state says the tag is current.")
    parser.add_argument("--dry-run", action="store_true", help="Resolve releases without installing.")
    parser.add_argument("--no-restart", action="store_true", help="Do not try to restart xray/sing-box systemd services.")
    args = parser.parse_args()

    arch = normalize_arch(platform.machine())
    selected = args.core or sorted(CORES)
    state_dir = Path(args.state_dir)
    install_dir = Path(args.install_dir)

    if not args.dry_run:
        install_dir.mkdir(parents=True, exist_ok=True)
        state_dir.mkdir(parents=True, exist_ok=True)

    changed = []
    for name in selected:
        metadata = CORES[name]
        result = update_core(name, metadata, arch, install_dir, state_dir, args.force, args.dry_run)
        print(json.dumps(result, sort_keys=True))
        if result.get("changed"):
            changed.append(name)

    if changed and not args.no_restart and not args.dry_run:
        restart_services(changed)
    return 0


def update_core(name, metadata, arch, install_dir, state_dir, force, dry_run):
    release = fetch_json(GITHUB_API.format(repo=metadata["repo"]))
    tag = release["tag_name"]
    asset = select_asset(name, metadata, release, arch)
    state_path = state_dir / f"{name}.json"
    state = read_state(state_path)
    target = install_dir / metadata["binary"]

    result = {
        "core": name,
        "repo": metadata["repo"],
        "tag": tag,
        "asset": asset["name"],
        "url": asset["browser_download_url"],
        "target": str(target),
        "changed": False,
    }

    if not force and state.get("tag") == tag and target.exists():
        result["status"] = "current"
        return result

    if dry_run:
        result["status"] = "would-update"
        result["changed"] = True
        return result

    with tempfile.TemporaryDirectory(prefix=f"las-{name}-") as tmp:
        tmpdir = Path(tmp)
        archive = tmpdir / asset["name"]
        download(asset["browser_download_url"], archive)
        extracted = tmpdir / "extract"
        extracted.mkdir()
        extract_archive(archive, extracted)
        binary = find_binary(extracted, metadata["binary"])
        install_binary(binary, target)

    write_state(state_path, {
        "tag": tag,
        "asset": asset["name"],
        "repo": metadata["repo"],
    })
    result["status"] = "updated"
    result["changed"] = True
    return result


def normalize_arch(machine):
    value = machine.lower()
    if value in {"x86_64", "amd64"}:
        return "amd64"
    if value in {"i386", "i686", "386"}:
        return "386"
    if value in {"aarch64", "arm64"}:
        return "arm64"
    if value.startswith("armv7") or value == "armv7l":
        return "armv7"
    raise RuntimeError(f"unsupported architecture: {machine}")


def select_asset(name, metadata, release, arch):
    pattern = metadata["asset_patterns"].get(arch)
    if not pattern:
        raise RuntimeError(f"{name} does not define an asset pattern for {arch}")
    regex = re.compile(pattern)
    for asset in release.get("assets", []):
        if regex.search(asset.get("name", "")):
            return asset
    names = ", ".join(asset.get("name", "") for asset in release.get("assets", []))
    raise RuntimeError(f"no {name} asset matched {pattern}; assets: {names}")


def request(url):
    req = urllib.request.Request(url, headers={"User-Agent": "LAS-core-updater"})
    return urllib.request.urlopen(req, timeout=60)


def fetch_json(url):
    with request(url) as response:
        return json.loads(response.read().decode("utf-8"))


def download(url, target):
    with request(url) as response, target.open("wb") as out:
        shutil.copyfileobj(response, out)


def extract_archive(archive, target):
    if archive.suffix == ".zip":
        with zipfile.ZipFile(archive) as zf:
            for member in zf.infolist():
                safe_target(target, member.filename)
            zf.extractall(target)
        return
    if archive.name.endswith(".tar.gz"):
        with tarfile.open(archive, "r:gz") as tf:
            for member in tf.getmembers():
                safe_target(target, member.name)
            tf.extractall(target)
        return
    raise RuntimeError(f"unsupported archive: {archive}")


def safe_target(root, member_name):
    root = root.resolve()
    candidate = (root / member_name).resolve()
    if candidate != root and not str(candidate).startswith(str(root) + os.sep):
        raise RuntimeError(f"unsafe archive path: {member_name}")


def find_binary(root, name):
    for path in root.rglob(name):
        if path.is_file():
            return path
    raise RuntimeError(f"binary {name} not found in extracted archive")


def install_binary(source, target):
    tmp = target.with_suffix(target.suffix + ".tmp")
    shutil.copy2(source, tmp)
    mode = tmp.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
    tmp.chmod(mode)
    os.replace(tmp, target)


def read_state(path):
    try:
        return json.loads(path.read_text())
    except FileNotFoundError:
        return {}


def write_state(path, state):
    path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n")


def restart_services(cores):
    for service in cores:
        try:
            subprocess.run(["systemctl", "try-restart", service], check=False)
        except FileNotFoundError:
            return


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"las-update-cores: {exc}", file=sys.stderr)
        raise SystemExit(1)
