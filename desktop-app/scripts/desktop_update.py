"""Generate the build override and static manifest for the Tauri updater."""

import argparse
import json
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urlsplit


def https_base(value):
    base = value.strip().rstrip("/")
    url = urlsplit(base)
    if (url.scheme != "https" or not url.hostname or url.username is not None
            or url.query or url.fragment or any(char.isspace() for char in base)):
        raise ValueError("The desktop update base must be an absolute HTTPS URL without credentials")
    return base


def configure(args):
    endpoints = [https_base(args.base) + "/latest.json"] if args.base.strip() else []
    args.output.write_text(json.dumps({"plugins": {"updater": {"endpoints": endpoints}}}), encoding="utf-8")


def exactly_one(directory, pattern):
    files = list(directory.rglob(pattern))
    if len(files) != 1 or not files[0].is_file():
        raise ValueError(f"Expected one {pattern} in {directory.name}")
    return files[0]


def manifest(args):
    version = json.loads(args.config.read_text(encoding="utf-8"))["version"]
    if not isinstance(version, str) or not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise ValueError("Desktop releases require a stable version in tauri.conf.json")
    tag = "desktop-v" + version
    base = https_base(args.base or f"https://github.com/{args.repo}/releases/download/{tag}")
    if urlsplit(base).hostname == "github.com" and base.endswith("/releases/latest/download"):
        base = base.removesuffix("/latest/download") + "/download/" + tag
    windows = args.artifacts / "workspace-x86_64-pc-windows-msvc"
    macos = args.artifacts / "workspace-universal-apple-darwin"
    args.output.mkdir(exist_ok=False, parents=True)

    def stage_update(path, name):
        signature = path.with_name(path.name + ".sig")
        contents = signature.read_text(encoding="ascii").strip()
        if not re.fullmatch(r"[A-Za-z0-9+/=]+", contents):
            raise ValueError(f"Invalid Tauri signature for {path.name}")
        shutil.copyfile(path, args.output / name)
        shutil.copyfile(signature, args.output / (name + ".sig"))
        return {"url": base + "/" + quote(name), "signature": contents}

    windows_update = stage_update(exactly_one(windows, "*.exe"), f"workspace-{version}-windows-x64.exe")
    macos_update = stage_update(exactly_one(macos, "*.app.tar.gz"), f"workspace-{version}-macos-universal.app.tar.gz")
    shutil.copyfile(exactly_one(macos, "*.dmg"), args.output / f"workspace-{version}-macos-universal.dmg")
    notes = args.notes.strip() or f"Yousoro Workspace {version}"
    data = {
        "version": version,
        "notes": notes,
        "pub_date": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "platforms": {
            "windows-x86_64": windows_update,
            "darwin-x86_64": macos_update,
            "darwin-aarch64": macos_update,
        },
    }
    (args.output / "latest.json").write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(tag)


def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="mode", required=True)
    config = subparsers.add_parser("configure")
    config.add_argument("--base", default="")
    config.add_argument("--output", type=Path, required=True)
    config.set_defaults(handler=configure)
    release = subparsers.add_parser("manifest")
    release.add_argument("--base", default="")
    release.add_argument("--repo", required=True)
    release.add_argument("--artifacts", type=Path, required=True)
    release.add_argument("--config", type=Path, required=True)
    release.add_argument("--output", type=Path, required=True)
    release.add_argument("--notes", default="")
    release.set_defaults(handler=manifest)
    args = parser.parse_args()
    args.handler(args)


if __name__ == "__main__":
    main()
