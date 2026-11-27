use super::*;
use sha2::{Digest, Sha256};
use std::{
    ffi::{c_void, OsStr},
    mem::size_of,
    os::windows::{ffi::OsStrExt, fs::OpenOptionsExt},
    ptr::{null, null_mut},
};

type Handle = *mut c_void;

#[link(name = "shell32")]
extern "system" {
    fn ShellExecuteExW(request: *mut ShellExecuteInfo) -> i32;
}

#[repr(C)]
struct ShellExecuteInfo {
    size: u32,
    mask: u32,
    window: Handle,
    operation: *const u16,
    file: *const u16,
    parameters: *const u16,
    directory: *const u16,
    show: i32,
    instance: Handle,
    id_list: Handle,
    class: *const u16,
    class_key: Handle,
    hotkey: u32,
    icon: Handle,
    process: Handle,
}

#[link(name = "kernel32")]
extern "system" {
    fn AllocConsole() -> i32;
    fn FreeConsole() -> i32;
    fn GetConsoleWindow() -> Handle;
    fn GenerateConsoleCtrlEvent(event: u32, group: u32) -> i32;
    fn CloseHandle(handle: Handle) -> i32;
    fn GetSystemDirectoryW(buffer: *mut u16, capacity: u32) -> u32;
}

#[link(name = "user32")]
extern "system" {
    fn ShowWindow(window: Handle, show: i32) -> i32;
}

pub fn verify(binary: &Path) -> Result<[fs::File; 2], Fallback> {
    // Verify both assets after opening read locks, also in the elevated helper.
    let lock = |path: &Path, hash: &str| -> Result<fs::File, Fallback> {
        let mut file = fs::OpenOptions::new()
            .read(true)
            .share_mode(1)
            .open(path)
            .map_err(|error| {
                if error.kind() == io::ErrorKind::NotFound {
                    Fallback::SidecarMissing
                } else {
                    Fallback::SidecarInvalid
                }
            })?;
        let mut digest = Sha256::new();
        io::copy(&mut file, &mut digest).map_err(|_| Fallback::SidecarInvalid)?;
        if format!("{:x}", digest.finalize()) != hash {
            return Err(Fallback::SidecarInvalid);
        }
        Ok(file)
    };
    Ok([
        lock(
            binary,
            "6d35e8635c7956f69cdd63abfcdaee1ce6937f176a34458f05c7b0ae0ce6d926",
        )?,
        lock(
            &binary.with_file_name("wintun.dll"),
            "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce",
        )?,
    ])
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
    let _lock = fs::OpenOptions::new()
        .read(true)
        .share_mode(1)
        .open(executable)
        .map_err(|_| Fallback::ElevationFailed)?;
    let wide = |s: &OsStr| s.encode_wide().chain(Some(0)).collect::<Vec<_>>();
    let verb = wide(OsStr::new("runas"));
    let path = wide(executable.as_os_str());
    let args = wide(OsStr::new(&format!(
        "--workspace-split-tun-helper {control} {socks} {gate} {relay} {nonce}"
    )));
    let mut request = ShellExecuteInfo {
        size: size_of::<ShellExecuteInfo>() as u32,
        // NOCLOSEPROCESS | NOASYNC | FLAG_NO_UI (the UAC prompt is still shown).
        mask: 0x0040 | 0x0100 | 0x0400,
        window: null_mut(),
        operation: verb.as_ptr(),
        file: path.as_ptr(),
        parameters: args.as_ptr(),
        directory: null(),
        show: 0,
        instance: null_mut(),
        id_list: null_mut(),
        class: null(),
        class_key: null_mut(),
        hotkey: 0,
        icon: null_mut(),
        process: null_mut(),
    };
    if unsafe { ShellExecuteExW(&mut request) } == 0 {
        return Err(if io::Error::last_os_error().raw_os_error() == Some(1223) {
            Fallback::UacCancelled
        } else {
            Fallback::ElevationFailed
        });
    }
    if !request.process.is_null() {
        unsafe {
            CloseHandle(request.process);
        }
    }
    Ok(())
}

#[link(name = "bcrypt")]
extern "system" {
    fn BCryptGenRandom(algorithm: Handle, buffer: *mut u8, length: u32, flags: u32) -> i32;
}

pub fn random(bytes: &mut [u8; 16]) -> io::Result<()> {
    if unsafe { BCryptGenRandom(null_mut(), bytes.as_mut_ptr(), bytes.len() as u32, 2) } == 0 {
        Ok(())
    } else {
        Err(io::ErrorKind::Other.into())
    }
}

pub struct Console;

impl Drop for Console {
    fn drop(&mut self) {
        unsafe {
            FreeConsole();
        }
    }
}

pub fn prepare() -> io::Result<Console> {
    unsafe {
        FreeConsole();
        if AllocConsole() == 0 {
            return Err(io::Error::last_os_error());
        }
        ShowWindow(GetConsoleWindow(), 0);
    }
    Ok(Console)
}

pub fn track(child: &Child) -> io::Result<impl Drop> {
    crate::native_windows::process_job(child)
}

pub fn cleanup_residual() {
    if !adapter_present() {
        return;
    }
    // sing-tun v0.7.11 derives this Wintun GUID from the exact adapter name.
    // Limit recovery to that GUID and never reset another adapter or global DNS.
    const RESET: &str = r#"
$ErrorActionPreference = 'Stop'
$adapter = Get-NetAdapter -IncludeHidden | Where-Object {
    $_.Name -eq 'YousoroWorkspace' -and $_.InterfaceGuid -eq '{99516b16-e78d-a9fc-ae22-eb09c5c903d4}'
}
if ($adapter) {
    Get-NetRoute -InterfaceIndex $adapter.ifIndex -ErrorAction SilentlyContinue |
        Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
    Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ResetServerAddresses -ErrorAction SilentlyContinue
    Disable-NetAdapter -InputObject $adapter -Confirm:$false -ErrorAction SilentlyContinue
}
"#;
    use std::ffi::OsString;
    use std::os::windows::{ffi::OsStringExt, process::CommandExt};
    let mut directory = [0u16; 32768];
    let length =
        unsafe { GetSystemDirectoryW(directory.as_mut_ptr(), directory.len() as u32) } as usize;
    if length == 0 || length >= directory.len() {
        return;
    }
    let command = PathBuf::from(OsString::from_wide(&directory[..length]))
        .join(r"WindowsPowerShell\v1.0\powershell.exe");
    let Ok(mut reset) = Command::new(command)
        .args(["-NoProfile", "-NonInteractive", "-Command", RESET])
        .creation_flags(0x08000000)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    else {
        return;
    };
    let until = Instant::now() + Duration::from_secs(3);
    while matches!(reset.try_wait(), Ok(None)) {
        if Instant::now() >= until {
            let _ = reset.kill();
            let _ = reset.wait();
            break;
        }
        thread::sleep(POLL);
    }
}

pub fn interrupt(pid: u32) {
    // Ctrl+Break is scoped to the sing-box process group in our private console.
    unsafe {
        GenerateConsoleCtrlEvent(1, pid);
    }
}
