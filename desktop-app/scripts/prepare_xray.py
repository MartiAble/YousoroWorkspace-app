"""Stage Tauri sidecars from a checksum-verified XTLS/Xray-core release."""

import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import subprocess
from urllib.request import Request, urlopen
import zipfile


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read(url, token=""):
    headers = {"User-Agent": "Yousoro-Workspace-Release"}
    if token:
        headers["Authorization"] = "Bearer " + token
    with urlopen(Request(url, headers=headers), timeout=60) as response:
        return response.read()


def main():
    tag = os.environ.get("XRAY_RELEASE_TAG", "")
    if not re.fullmatch(r"v[0-9]+(?:\.[0-9]+){1,3}(?:-[A-Za-z0-9.-]+)?", tag):
        raise SystemExit("Set XRAY_RELEASE_TAG to a published XTLS/Xray-core version")
    system = platform.system()
    variants = {
        "Darwin": [
            ("Xray-macos-arm64-v8a.zip", "aarch64-apple-darwin", "xray"),
            ("Xray-macos-64.zip", "x86_64-apple-darwin", "xray"),
        ],
        "Windows": [("Xray-windows-64.zip", "x86_64-pc-windows-msvc", "xray.exe")],
    }.get(system)
    if not variants:
        raise SystemExit("Run the release preparer on macOS or Windows")

    tauri = Path(__file__).resolve().parents[1] / "src-tauri"
    config = json.loads((tauri / "tauri.conf.json").read_text(encoding="utf-8"))
    if "binaries/xray" not in config["bundle"]["externalBin"]:
        raise SystemExit("Expected binaries/xray in bundle.externalBin")
    binaries = tauri / "binaries"
    resources = tauri / "resources"
    binaries.mkdir(exist_ok=True)
    resources.mkdir(exist_ok=True)

    releases = "https://api.github.com/repos/XTLS/Xray-core/releases/tags/"
    release = json.loads(read(releases + tag, os.environ.get("GH_TOKEN", "")))
    assets = {asset["name"]: asset for asset in release["assets"]}
    staged = []
    for source, target, member in variants:
        asset = assets.get(source)
        if not asset:
            raise SystemExit(f"Release {tag} has no {source}")
        expected = asset.get("digest")
        if not expected or not expected.startswith("sha256:"):
            raise SystemExit(f"No published SHA-256 for {source}")
        archive = read(asset["browser_download_url"])
        if "sha256:" + sha(archive) != expected:
            raise SystemExit(f"Checksum mismatch for {source}")
        with zipfile.ZipFile(io.BytesIO(archive)) as zipped:
            binary = zipped.read(member)
        output = binaries / f"xray-{target}{Path(member).suffix}"
        output.write_bytes(binary)
        output.chmod(0o755)
        if system == "Darwin":
            subprocess.run(["/usr/bin/codesign", "--force", "--sign", "-", output], check=True)
        (resources / f"{output.name}.sha256").write_text(sha(output.read_bytes()) + "\n", encoding="ascii")
        staged.append(output)
        print(f"Verified {source} and staged {output.name}")

    if system == "Darwin":
        universal = binaries / "xray-universal-apple-darwin"
        subprocess.run(["/usr/bin/lipo", "-create", *staged, "-output", universal], check=True)
        subprocess.run(["/usr/bin/codesign", "--force", "--sign", "-", universal], check=True)
        subprocess.run(["/usr/bin/lipo", universal, "-verify_arch", "arm64", "x86_64"], check=True)


if __name__ == "__main__":
    main()
