//! Windows discovery primitives. No child shells or management instrumentation.
use std::{ffi::c_void, fs, io, os::windows::ffi::OsStrExt, path::{Component, Path, PathBuf}};

type Handle = *mut c_void;
const HKCU: Handle = (0x8000_0001u32 as i32 as isize) as Handle;
const HKLM: Handle = (0x8000_0002u32 as i32 as isize) as Handle;
const KEY_READ: u32 = 0x20019;
const KEY_SET_VALUE: u32 = 2;
const ERROR_NO_MORE_ITEMS: i32 = 259;

#[link(name = "advapi32")]
extern "system" {
    fn RegOpenKeyExW(root: Handle, path: *const u16, options: u32, access: u32, key: *mut Handle) -> i32;
    fn RegCreateKeyExW(root: Handle, path: *const u16, reserved: u32, class: *const u16, options: u32,
                       access: u32, security: *const c_void, key: *mut Handle, disposition: *mut u32) -> i32;
    fn OpenProcessToken(process: Handle, access: u32, token: *mut Handle) -> i32;
    fn GetTokenInformation(token: Handle, kind: u32, buffer: *mut c_void, length: u32, used: *mut u32) -> i32;
    fn ConvertSidToStringSidW(sid: Handle, string: *mut *mut u16) -> i32;
    fn RegCloseKey(key: Handle) -> i32;
    fn RegEnumKeyExW(key: Handle, index: u32, name: *mut u16, length: *mut u32, reserved: *mut u32,
                     class: *mut u16, class_length: *mut u32, last_write: *mut c_void) -> i32;
    fn RegQueryValueExW(key: Handle, name: *const u16, reserved: *mut u32, kind: *mut u32, data: *mut u8, size: *mut u32) -> i32;
    fn RegSetValueExW(key: Handle, name: *const u16, reserved: u32, kind: u32, data: *const u8, size: u32) -> i32;
    fn RegDeleteValueW(key: Handle, name: *const u16) -> i32;
}

#[link(name = "kernel32")]
extern "system" {
    fn GetCurrentProcess() -> Handle;
    fn LocalFree(memory: Handle) -> Handle;
    fn CreateToolhelp32Snapshot(flags: u32, pid: u32) -> Handle;
    fn Process32FirstW(snapshot: Handle, entry: *mut ProcessEntry) -> i32;
    fn Process32NextW(snapshot: Handle, entry: *mut ProcessEntry) -> i32;
    fn OpenProcess(access: u32, inherit: i32, pid: u32) -> Handle;
    fn CloseHandle(handle: Handle) -> i32;
    fn QueryFullProcessImageNameW(process: Handle, flags: u32, name: *mut u16, length: *mut u32) -> i32;
    fn ProcessIdToSessionId(process: u32, session: *mut u32) -> i32;
    fn GetDynamicTimeZoneInformation(zone: *mut DynamicTimeZone) -> u32;
}

#[link(name = "ntdll")]
extern "system" {
    fn NtQuerySystemInformation(class: u32, buffer: *mut c_void, length: u32, used: *mut u32) -> i32;
    fn NtQueryInformationProcess(process: Handle, class: u32, buffer: *mut c_void, length: u32, used: *mut u32) -> i32;
}

#[link(name = "user32")]
extern "system" {
    fn EnumWindows(callback: extern "system" fn(Handle, isize) -> i32, data: isize) -> i32;
    fn GetWindowThreadProcessId(window: Handle, pid: *mut u32) -> u32;
    fn IsWindowVisible(window: Handle) -> i32;
    fn PostMessageW(window: Handle, message: u32, wparam: usize, lparam: isize) -> i32;
}

fn wide(value: impl AsRef<std::ffi::OsStr>) -> Vec<u16> {
    value.as_ref().encode_wide().chain(Some(0)).collect()
}

fn text(bytes: &[u16]) -> String {
    let end = bytes.iter().position(|&value| value == 0).unwrap_or(bytes.len());
    String::from_utf16_lossy(&bytes[..end])
}

fn status(code: i32) -> io::Result<()> {
    if code == 0 { Ok(()) } else { Err(io::Error::from_raw_os_error(code)) }
}

pub struct Key(Handle);

impl Key {
    fn open(root: Handle, path: &str, access: u32) -> io::Result<Self> {
        let mut result = std::ptr::null_mut();
        status(unsafe { RegOpenKeyExW(root, wide(path).as_ptr(), 0, access, &mut result) })?;
        Ok(Self(result))
    }

    pub fn user(path: &str, write: bool) -> io::Result<Self> {
        Self::open(HKCU, path, KEY_READ | if write { KEY_SET_VALUE } else { 0 })
    }

    pub fn user_create(path: &str) -> io::Result<Self> {
        let mut key = std::ptr::null_mut();
        status(unsafe { RegCreateKeyExW(HKCU, wide(path).as_ptr(), 0, std::ptr::null(), 0,
            KEY_READ | KEY_SET_VALUE, std::ptr::null(), &mut key, std::ptr::null_mut()) })?;
        Ok(Self(key))
    }

    fn subkey(&self, name: &str) -> io::Result<Self> {
        Self::open(self.0, name, KEY_READ)
    }

    fn names(&self) -> Vec<String> {
        let mut result = Vec::new();
        let mut name = [0; 256];
        for index in 0..8192 {
            let mut length = name.len() as u32;
            let code = unsafe { RegEnumKeyExW(self.0, index, name.as_mut_ptr(), &mut length, std::ptr::null_mut(),
                std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut()) };
            if code == ERROR_NO_MORE_ITEMS { break; }
            if code != 0 { break; }
            result.push(text(&name[..length as usize]));
        }
        result
    }

    pub fn string(&self, name: &str) -> io::Result<Option<String>> {
        let name = wide(name);
        let mut kind = 0;
        let mut size = 0;
        let code = unsafe { RegQueryValueExW(self.0, name.as_ptr(), std::ptr::null_mut(), &mut kind, std::ptr::null_mut(), &mut size) };
        if code == 2 { return Ok(None); }
        status(code)?;
        if !matches!(kind, 1 | 2) || size > 65536 || size % 2 != 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "registry string"));
        }
        let mut buffer = vec![0u16; size as usize / 2];
        status(unsafe { RegQueryValueExW(self.0, name.as_ptr(), std::ptr::null_mut(), &mut kind, buffer.as_mut_ptr().cast(), &mut size) })?;
        Ok(Some(text(&buffer[..size as usize / 2])))
    }

    pub fn dword(&self, name: &str) -> io::Result<Option<u32>> {
        let mut data = 0u32;
        let mut kind = 0;
        let mut size = 4;
        let code = unsafe { RegQueryValueExW(self.0, wide(name).as_ptr(), std::ptr::null_mut(), &mut kind,
            (&mut data as *mut u32).cast(), &mut size) };
        if code == 2 { return Ok(None); }
        status(code)?;
        if size == 4 && kind == 4 { Ok(Some(data)) } else { Err(io::Error::new(io::ErrorKind::InvalidData, "registry DWORD")) }
    }

    pub fn set_string(&self, name: &str, value: Option<&str>) -> io::Result<()> {
        match value {
            Some(value) => {
                let value = wide(value);
                status(unsafe { RegSetValueExW(self.0, wide(name).as_ptr(), 0, 1, value.as_ptr().cast(), (value.len() * 2) as u32) })
            }
            None => self.remove(name),
        }
    }

    pub fn set_dword(&self, name: &str, value: Option<u32>) -> io::Result<()> {
        match value {
            Some(value) => status(unsafe { RegSetValueExW(self.0, wide(name).as_ptr(), 0, 4, (&value as *const u32).cast(), 4) }),
            None => self.remove(name),
        }
    }

    fn remove(&self, name: &str) -> io::Result<()> {
        match unsafe { RegDeleteValueW(self.0, wide(name).as_ptr()) } { 2 => Ok(()), code => status(code) }
    }
}

impl Drop for Key { fn drop(&mut self) { unsafe { RegCloseKey(self.0); } } }

#[derive(Debug)]
pub struct Package {
    pub root: PathBuf,
    pub aumid: String,
    pub executable: Option<PathBuf>,
}

const PACKAGES: &str = r"Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages";

fn app_attribute<'a>(mut tag: &'a str, attribute: &str) -> Option<&'a str> {
    while let Some((key, rest)) = tag.split_once('=') {
        let name = key.split_whitespace().last()?;
        let rest = rest.trim_start();
        let quote = rest.chars().next().filter(|quote| matches!(quote, '"' | '\''))?;
        let (value, tail) = rest[1..].split_once(quote)?;
        if name.rsplit(':').next() == Some(attribute) { return Some(value); }
        tag = tail;
    }
    None
}

fn read_manifest(root: &Path, id: &str) -> Option<PathBuf> {
    let xml = fs::read_to_string(root.join("AppxManifest.xml")).ok()?;
    for segment in xml.split("<Application").skip(1) {
        if !segment.starts_with(char::is_whitespace) { continue; }
        let Some((tag, _)) = segment.split_once('>') else { continue };
        if app_attribute(tag, "Id") != Some(id) { continue; }
        let full_trust = app_attribute(tag, "EntryPoint") == Some("Windows.FullTrustApplication")
            || app_attribute(tag, "TrustLevel") == Some("mediumIL");
        let path = Path::new(app_attribute(tag, "Executable")?);
        if !full_trust || !path.components().all(|part| matches!(part, Component::Normal(_))) { return None; }
        let path = root.join(path);
        if path.is_file() && path.parent()?.join("resources/app.asar").is_file() { return Some(path); }
    }
    None
}

fn package_version(name: &str) -> Vec<u32> {
    name.split('_').nth(1).unwrap_or_default().split('.').filter_map(|part| part.parse().ok()).collect()
}

fn app_package(key: &Key, name: &str) -> Option<Package> {
    let (app, rest) = name.split_once('_')?;
    let publisher = rest.rsplit_once('_')?.1;
    let info = key.subkey(name).ok()?;
    let root = PathBuf::from(info.string("PackageRootFolder").ok()??);
    if !root.is_absolute() { return None; }
    let ids = info.names();
    let id = ids.iter().find(|id| id.as_str() == "App" || id.eq_ignore_ascii_case("Claude") || id.eq_ignore_ascii_case("ChatGPT"))
        .or_else(|| ids.first())?;
    Some(Package { aumid: format!("{app}_{publisher}!{id}"), executable: read_manifest(&root, id), root })
}

pub fn discover_packages() -> [Option<Package>; 2] {
    let Ok(key) = Key::user(PACKAGES, false) else { return [None, None] };
    let mut names = key.names();
    names.retain(|name| matches!(name.split('_').next().unwrap_or_default().to_ascii_lowercase().as_str(),
        "claude" | "openai.chatgpt-desktop" | "openai.codex"));
    names.sort_by_cached_key(|name| std::cmp::Reverse(package_version(name)));
    let find = |app: &str| names.iter().find_map(|name|
        (name.split('_').next()?.eq_ignore_ascii_case(app)).then(|| app_package(&key, name)).flatten());
    [find("Claude"), find("OpenAI.ChatGPT-Desktop").or_else(|| find("OpenAI.Codex"))]
}

pub fn discover_classic(claude: bool) -> Option<PathBuf> {
    let (name, exe) = if claude { ("Claude", "Claude.exe") } else { ("ChatGPT", "ChatGPT.exe") };
    if let Some(local) = std::env::var_os("LOCALAPPDATA").map(PathBuf::from) {
        let paths = if claude {
            [local.join("AnthropicClaude/claude.exe"), local.join("Programs/Claude/Claude.exe")]
        } else {
            [local.join("Programs/ChatGPT/ChatGPT.exe"), local.join("Programs/OpenAI/ChatGPT/ChatGPT.exe")]
        };
        if let Some(path) = paths.into_iter().find(|path| path.is_file()) { return Some(path); }
        if claude {
            if let Some(path) = versioned_executable(&local.join("AnthropicClaude"), exe) { return Some(path); }
        }
    }
    for folder in ["ProgramFiles", "ProgramFiles(x86)"].into_iter().filter_map(std::env::var_os).map(PathBuf::from) {
        for path in [folder.join(name).join(exe), folder.join("OpenAI").join(name).join(exe)] {
            if path.is_file() { return Some(path); }
        }
    }
    if !claude { return None; }
    let uninstall = r"Software\Microsoft\Windows\CurrentVersion\Uninstall";
    for (root, access) in [(HKCU, KEY_READ), (HKLM, KEY_READ | 0x0100), (HKLM, KEY_READ | 0x0200)] {
        let Ok(key) = Key::open(root, uninstall, access) else { continue };
        for name in key.names() {
            let Ok(entry) = key.subkey(&name) else { continue };
            if entry.string("DisplayName").ok().flatten().as_deref() != Some("Claude") { continue; }
            if let Some(icon) = entry.string("DisplayIcon").ok().flatten() {
                let icon = icon.rsplit_once(',').filter(|(_, index)| index.trim().parse::<i32>().is_ok())
                    .map_or(icon.as_str(), |(path, _)| path).trim_matches('"');
                let icon = PathBuf::from(icon);
                if icon.is_absolute() && icon.file_name().is_some_and(|name| name.eq_ignore_ascii_case(exe)) && icon.is_file() {
                    return Some(icon);
                }
            }
            if let Some(folder) = entry.string("InstallLocation").ok().flatten().map(PathBuf::from).filter(|p| p.is_absolute()) {
                if let Some(path) = versioned_executable(&folder, exe) { return Some(path); }
            }
        }
    }
    None
}

fn versioned_executable(folder: &Path, exe: &str) -> Option<PathBuf> {
    let exact = folder.join(exe);
    if exact.is_file() { return Some(exact); }
    let mut entries: Vec<_> = fs::read_dir(folder).ok()?.flatten()
        .filter(|entry| entry.file_name().to_string_lossy().starts_with("app-")).collect();
    entries.sort_by_cached_key(|entry| std::cmp::Reverse(entry.metadata().and_then(|data| data.modified()).ok()));
    entries.into_iter().map(|entry| entry.path().join(exe)).find(|path| path.is_file())
}

#[repr(C)]
struct ProcessEntry {
    size: u32, usage: u32, pid: u32, heap: usize, module: u32, threads: u32,
    parent: u32, priority: i32, flags: u32, executable: [u16; 260],
}

#[repr(C)]
struct UnicodeString { length: u16, capacity: u16, data: *const u16 }

struct OwnedHandle(Handle);
impl Drop for OwnedHandle { fn drop(&mut self) { unsafe { CloseHandle(self.0); } } }

#[derive(Clone, Debug)]
pub struct Process {
    pub id: u32,
    pub name: String,
    pub image: Option<PathBuf>,
    pub command: Option<String>,
}

pub fn machine_user_id() -> io::Result<String> {
    let guid = Key::open(HKLM, r"SOFTWARE\Microsoft\Cryptography", KEY_READ)?
        .string("MachineGuid")?.filter(|value| !value.is_empty())
        .ok_or(io::ErrorKind::NotFound)?;
    let mut handle = std::ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), 8, &mut handle) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = OwnedHandle(handle);
    let mut length = 0;
    unsafe { GetTokenInformation(token.0, 1, std::ptr::null_mut(), 0, &mut length); }
    if length < (std::mem::size_of::<usize>() * 2) as u32 || length > 65536 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "token user size"));
    }
    let mut user = vec![0usize; (length as usize).div_ceil(std::mem::size_of::<usize>())];
    if unsafe { GetTokenInformation(token.0, 1, user.as_mut_ptr().cast(), length, &mut length) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // TOKEN_USER begins with a SID pointer into the live user buffer.
    let mut sid_text = std::ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(user[0] as Handle, &mut sid_text) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut end = 0;
    while unsafe { *sid_text.add(end) } != 0 { end += 1; }
    let sid = text(unsafe { std::slice::from_raw_parts(sid_text, end) });
    unsafe { LocalFree(sid_text.cast()); }
    Ok(format!("{guid}{sid}"))
}

fn command_line(process: Handle) -> Option<String> {
    const COMMAND_LINE_INFORMATION: u32 = 60;
    let mut required = 0;
    let mut stack = [0usize; 512];
    let mut start = stack.as_mut_ptr().cast::<u8>();
    let mut capacity = std::mem::size_of_val(&stack);
    let mut code = unsafe { NtQueryInformationProcess(process, COMMAND_LINE_INFORMATION, start.cast(), capacity as u32, &mut required) };
    let mut heap;
    if code < 0 && required as usize > capacity && required <= 128 * 1024 {
        heap = vec![0usize; (required as usize).div_ceil(std::mem::size_of::<usize>())];
        start = heap.as_mut_ptr().cast();
        capacity = required as usize;
        code = unsafe { NtQueryInformationProcess(process, COMMAND_LINE_INFORMATION, start.cast(), capacity as u32, &mut required) };
    }
    if code < 0 { return None; }
    let end = start as usize + capacity;
    let value = unsafe { &*start.cast::<UnicodeString>() };
    let address = value.data as usize;
    let length = value.length as usize;
    if address < start as usize || address % 2 != 0 || length % 2 != 0 || address.checked_add(length)? > end {
        return None;
    }
    Some(text(unsafe { std::slice::from_raw_parts(value.data, length / 2) }))
}

// Available on current Windows 11 builds. Older releases use Toolhelp.
#[repr(C)]
struct SystemProcess {
    next_offset: u32,
    pid: usize,
    parent: usize,
    sequence: u64,
    image_name: UnicodeString,
}

pub fn processes(names: &[&str]) -> io::Result<Vec<Process>> {
    let mut session = 0;
    if unsafe { ProcessIdToSessionId(std::process::id(), &mut session) } == 0 { return Err(io::Error::last_os_error()); }
    let candidates = system_processes(names, session).or_else(|_| toolhelp_processes(names, session))?;
    Ok(candidates.into_iter().map(|(id, name)| process_details(id, name)).collect())
}

fn system_processes(names: &[&str], session: u32) -> io::Result<Vec<(u32, String)>> {
    const SYSTEM_BASIC_PROCESS_INFORMATION: u32 = 252;
    const LENGTH_MISMATCH: i32 = 0xc000_0004_u32 as i32;
    let mut buffer = vec![0usize; 64 * 1024 / std::mem::size_of::<usize>()];
    let mut used = 0;
    loop {
        let capacity = std::mem::size_of_val(buffer.as_slice());
        let code = unsafe { NtQuerySystemInformation(SYSTEM_BASIC_PROCESS_INFORMATION, buffer.as_mut_ptr().cast(), capacity as u32, &mut used) };
        if code >= 0 && used as usize <= capacity { break; }
        if code != LENGTH_MISMATCH || used as usize <= capacity || used > 32 * 1024 * 1024 {
            return Err(io::Error::other("Windows process snapshot"));
        }
        buffer.resize(((used as usize) + 64 * 1024).div_ceil(std::mem::size_of::<usize>()), 0);
    }
    let start = buffer.as_ptr().cast::<u8>();
    let end = start as usize + used as usize;
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "Windows process snapshot");
    let mut result = Vec::new();
    let mut offset = 0usize;
    loop {
        if offset % std::mem::align_of::<SystemProcess>() != 0 ||
            offset + std::mem::size_of::<SystemProcess>() > used as usize { return Err(invalid()); }
        let entry = unsafe { &*start.add(offset).cast::<SystemProcess>() };
        let length = entry.image_name.length as usize;
        let pointer = entry.image_name.data as usize;
        if length != 0 && length % 2 == 0 && pointer % 2 == 0 &&
            pointer >= start as usize && pointer.checked_add(length).is_some_and(|limit| limit <= end) {
            let name = text(unsafe { std::slice::from_raw_parts(entry.image_name.data, length / 2) }).to_ascii_lowercase();
            if names.contains(&name.as_str()) {
                let id = u32::try_from(entry.pid).map_err(|_| invalid())?;
                let mut found_session = 0;
                if unsafe { ProcessIdToSessionId(id, &mut found_session) } != 0 && found_session == session {
                    result.push((id, name));
                }
            }
        }
        if entry.next_offset == 0 { return Ok(result); }
        if (entry.next_offset as usize) < std::mem::size_of::<SystemProcess>() { return Err(invalid()); }
        offset = offset.checked_add(entry.next_offset as usize).ok_or_else(invalid)?;
    }
}

fn toolhelp_processes(names: &[&str], session: u32) -> io::Result<Vec<(u32, String)>> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(2, 0) };
    if snapshot as isize == -1 { return Err(io::Error::last_os_error()); }
    let snapshot = OwnedHandle(snapshot);
    let mut entry: ProcessEntry = unsafe { std::mem::zeroed() };
    entry.size = std::mem::size_of::<ProcessEntry>() as u32;
    let mut ok = unsafe { Process32FirstW(snapshot.0, &mut entry) };
    if ok == 0 { return Err(io::Error::last_os_error()); }
    let mut result = Vec::new();
    while ok != 0 {
        let name = text(&entry.executable).to_ascii_lowercase();
        let mut found_session = 0;
        if names.contains(&name.as_str()) && unsafe { ProcessIdToSessionId(entry.pid, &mut found_session) } != 0 && found_session == session {
            result.push((entry.pid, name));
        }
        ok = unsafe { Process32NextW(snapshot.0, &mut entry) };
    }
    Ok(result)
}

fn process_details(id: u32, name: String) -> Process {
    let handle = unsafe { OpenProcess(0x1000, 0, id) };
    let (image, command) = if handle.is_null() { (None, None) } else {
        let handle = OwnedHandle(handle);
        let mut path = [0u16; 1024];
        let mut length = path.len() as u32;
        let found = unsafe { QueryFullProcessImageNameW(handle.0, 0, path.as_mut_ptr(), &mut length) };
        let image = (found != 0).then(|| PathBuf::from(String::from_utf16_lossy(&path[..length as usize])));
        (image, command_line(handle.0))
    };
    Process { id, name, image, command }
}

pub fn close_windows(ids: &[u32]) {
    extern "system" fn close(window: Handle, state: isize) -> i32 {
        let ids = unsafe { &*(state as *const &[u32]) };
        let mut pid = 0;
        unsafe {
            GetWindowThreadProcessId(window, &mut pid);
            if ids.contains(&pid) && IsWindowVisible(window) != 0 { PostMessageW(window, 0x0010, 0, 0); }
        }
        1
    }
    // EnumWindows invokes the callback synchronously while the slice is live.
    unsafe { EnumWindows(close, (&ids as *const &[u32]) as isize); }
}

#[repr(C)]
struct SystemTime { fields: [u16; 8] }

#[repr(C)]
struct DynamicTimeZone {
    bias: i32, standard: [u16; 32], standard_date: SystemTime, standard_bias: i32,
    daylight: [u16; 32], daylight_date: SystemTime, daylight_bias: i32, key: [u16; 128], disabled: u8,
}

pub fn timezone() -> Option<String> {
    let mut zone: DynamicTimeZone = unsafe { std::mem::zeroed() };
    if unsafe { GetDynamicTimeZoneInformation(&mut zone) } == u32::MAX { return None; }
    let name = text(&zone.key);
    (!name.is_empty()).then_some(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_prefixed_manifest_fields_and_versions() {
        let sample = r#" Id="App" Executable='app\Codex.exe' uap10:TrustLevel="mediumIL" "#;
        assert_eq!(app_attribute(sample, "Id"), Some("App"));
        assert_eq!(app_attribute(sample, "Executable"), Some(r"app\Codex.exe"));
        assert_eq!(app_attribute(sample, "TrustLevel"), Some("mediumIL"));
        assert!(package_version("Claude_6.10.0.0_x64__id") > package_version("Claude_6.9.0.0_x64__id"));
    }

    #[test]
    fn native_process_snapshot_filters_names_and_reads_target_command_line() {
        let name = std::env::current_exe().unwrap().file_name().unwrap().to_string_lossy().to_ascii_lowercase();
        let snapshot = processes(&[&name]).unwrap();
        assert!(snapshot.iter().all(|process| process.name == name));
        let current = snapshot.iter().find(|process| process.id == std::process::id()).unwrap();
        assert!(current.command.as_deref().is_some_and(|command| command.to_ascii_lowercase().contains(&name)));
        assert!(current.image.as_ref().is_some_and(|image| image.is_file()));
    }
}
