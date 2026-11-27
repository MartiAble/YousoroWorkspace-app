"""Stage checksum-pinned sing-box and Wintun assets for the desktop bundle."""

import io
import platform
import subprocess
import tarfile
import zipfile
from pathlib import Path

from prepare_xray import read, sha


VERSION = "1.12.22"
RELEASE = f"https://github.com/SagerNet/sing-box/releases/download/v{VERSION}"
ASSETS = {
    "windows-amd64.zip": "3c0f046e163ecb32ec2757f693daae1f4f138547535f6cc5d6a4bd9a7a086175",
    "darwin-amd64.tar.gz": "950072cf2f1e0d4aa216116e0b1f9f7542aa953c1487b55516ea9d04bd73bbc6",
    "darwin-arm64.tar.gz": "974d924c36af92a9aecab5e630555764aa665fb8210e58a48c01faec5d55de0f",
}
WINTUN_URL = "https://www.wintun.net/builds/wintun-0.14.1.zip"
WINTUN_SHA256 = "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51"


def verified_download(url, expected):
    archive = read(url)
    if sha(archive) != expected:
        raise SystemExit(f"SHA-256 mismatch for {url.rsplit('/', 1)[-1]}")
    return io.BytesIO(archive)


def sing_box_asset(asset, executable):
    name = f"sing-box-{VERSION}-{asset}"
    folder = name.removesuffix(".zip").removesuffix(".tar.gz")
    archive = verified_download(f"{RELEASE}/{name}", ASSETS[asset])
    if name.endswith(".zip"):
        with zipfile.ZipFile(archive) as zipped:
            return zipped.read(f"{folder}/{executable}"), zipped.read(f"{folder}/LICENSE")
    with tarfile.open(fileobj=archive, mode="r:gz") as tar:
        return tar.extractfile(f"{folder}/{executable}").read(), tar.extractfile(f"{folder}/LICENSE").read()


def main():
    system = platform.system()
    targets = {
        "Windows": [("windows-amd64.zip", "x86_64-pc-windows-msvc")],
        "Darwin": [
            ("darwin-arm64.tar.gz", "aarch64-apple-darwin"),
            ("darwin-amd64.tar.gz", "x86_64-apple-darwin"),
        ],
    }.get(system)
    if targets is None:
        raise SystemExit("Prepare sing-box on Windows or macOS")

    tauri = Path(__file__).resolve().parents[1] / "src-tauri"
    binaries = tauri / "binaries"
    notices = tauri / "resources" / "sing-box"
    binaries.mkdir(exist_ok=True)
    notices.mkdir(parents=True, exist_ok=True)
    staged = []
    executable = "sing-box.exe" if system == "Windows" else "sing-box"
    for asset, target in targets:
        content, license_text = sing_box_asset(asset, executable)
        output = binaries / f"sing-box-{target}{Path(executable).suffix}"
        output.write_bytes(content)
        output.chmod(0o755)
        (notices / "LICENSE-sing-box").write_bytes(license_text)
        (notices / "SOURCE-sing-box").write_text(
            f"https://github.com/SagerNet/sing-box/tree/v{VERSION}\n", encoding="ascii"
        )
        staged.append(output)

    if system == "Windows":
        with zipfile.ZipFile(verified_download(WINTUN_URL, WINTUN_SHA256)) as archive:
            (binaries / "wintun.dll").write_bytes(archive.read("wintun/bin/amd64/wintun.dll"))
            (notices / "LICENSE-wintun").write_bytes(archive.read("wintun/LICENSE.txt"))
    else:
        universal = binaries / "sing-box-universal-apple-darwin"
        subprocess.run(["/usr/bin/lipo", "-create", *staged, "-output", universal], check=True)
        subprocess.run(["/usr/bin/codesign", "--force", "--sign", "-", universal], check=True)
        subprocess.run(["/usr/bin/lipo", universal, "-verify_arch", "arm64", "x86_64"], check=True)
    print(f"Verified and staged sing-box {VERSION} for {system}")


if __name__ == "__main__":
    main()
