use super::*;
use sha2::{Digest, Sha256};

pub fn verify(binary: &Path) -> Result<(), Fallback> {
    if !binary.is_file() {
        return Err(Fallback::SidecarMissing);
    }
    let valid = Command::new("/usr/bin/codesign")
        .args(["--verify", "--strict", "--all-architectures"])
        .arg(binary)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success());
    if valid {
        Ok(())
    } else {
        Err(Fallback::SidecarInvalid)
    }
}

pub fn random(bytes: &mut [u8; 16]) -> io::Result<()> {
    fs::File::open("/dev/urandom")?.read_exact(bytes)
}

pub fn elevate(
    executable: &Path,
    control: u16,
    socks: u16,
    gate: u16,
    relay: Option<SocketAddrV4>,
    nonce: String,
) -> Result<(), Fallback> {
    let relay = relay.map_or_else(|| "none".to_owned(), |endpoint| endpoint.to_string());
    let quoted = |path: &Path| -> Result<String, Fallback> {
        Ok(format!(
            "'{}'",
            path.to_str()
                .ok_or(Fallback::ElevationFailed)?
                .replace('\'', "'\"'\"'")
        ))
    };
    let digest = |path: &Path| -> Result<String, Fallback> {
        Ok(format!(
            "{:x}",
            Sha256::digest(fs::read(path).map_err(|_| Fallback::SidecarMissing)?)
        ))
    };
    let binary = executable.with_file_name(CORE);
    let (app_source, core_source) = (quoted(executable)?, quoted(&binary)?);
    let (app_hash, core_hash) = (digest(executable)?, digest(&binary)?);
    // Copy and verify the exact bytes before executing them from a private
    // root-owned directory. The shell receives only literal paths and ports.
    let shell = format!(
        r#"
set -eu
directory=$(/usr/bin/mktemp -d /private/tmp/workspace-tun.XXXXXXXX)
/usr/bin/test -n "$directory"
cleanup() {{
    if [ -f "$directory/child" ]; then
        IFS= read -r child < "$directory/child" || child=
        # The private path also guards against signaling a reused PID.
        case "$child" in
            ''|*[!0-9]*) ;;
            *) if [ "$(/bin/ps -ww -p "$child" -o command=)" = "$directory/sing-box run -c stdin" ]; then
                /bin/kill -TERM "$child" 2>/dev/null || true
                for second in 1 2 3; do
                    [ "$(/bin/ps -ww -p "$child" -o command=)" = "$directory/sing-box run -c stdin" ] || break
                    /bin/sleep 1
                done
                if [ "$(/bin/ps -ww -p "$child" -o command=)" = "$directory/sing-box run -c stdin" ]; then
                    /bin/kill -KILL "$child" 2>/dev/null || true
                fi
            fi ;;
        esac
    fi
    /bin/rm -f "$directory/launcher" "$directory/sing-box" "$directory/child"
    /bin/rmdir "$directory"
}}
trap cleanup EXIT
/bin/cp {app_source} "$directory/launcher"
/bin/cp {core_source} "$directory/sing-box"
/usr/bin/printf '%s  %s\n%s  %s\n' '{app_hash}' "$directory/launcher" '{core_hash}' "$directory/sing-box" | /usr/bin/shasum -a 256 -c - >/dev/null
/bin/chmod 700 "$directory/launcher" "$directory/sing-box"
/usr/bin/codesign --verify --strict "$directory/launcher"
"$directory/launcher" --workspace-split-tun-helper {control} {socks} {gate} {relay} {nonce}
"#
    );
    let output = Command::new("/usr/bin/osascript")
        .args([
            "-e",
            "on run argv",
            "-e",
            "do shell script (item 1 of argv) with administrator privileges",
            "-e",
            "end run",
            "--",
        ])
        .arg(shell)
        .output()
        .map_err(|_| Fallback::ElevationFailed)?;
    if output.status.success() {
        return Ok(());
    }
    if String::from_utf8_lossy(&output.stderr).contains("(-128)") {
        return Err(Fallback::AuthorizationCancelled);
    }
    Err(Fallback::ElevationFailed)
}

pub fn prepare() -> io::Result<()> {
    Ok(())
}
pub fn track(child: &Child) -> io::Result<()> {
    let dir = std::env::current_exe()?.with_file_name("child");
    fs::write(dir, format!("{}\n", child.id()))
}
pub fn interrupt(pid: u32) {
    let _ = Command::new("/bin/kill")
        .args(["-TERM", &pid.to_string()])
        .status();
}
