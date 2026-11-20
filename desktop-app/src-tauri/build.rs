fn main() {
    for (name, fallback) in [
        ("DESKTOP_API_ORIGIN", include_str!("config/api-origin.txt")),
        ("DESKTOP_DIAGNOSTICS_ORIGIN", include_str!("config/diagnostics-origin.txt")),
    ] {
        println!("cargo:rerun-if-env-changed={name}");
        let configured = std::env::var(name).unwrap_or_default();
        let origin = if configured.trim().is_empty() { fallback.trim() } else { configured.trim() };
        assert!(
            origin.strip_prefix("https://").is_some_and(|host|
                !host.is_empty() && host.bytes().all(|b| b.is_ascii_alphanumeric() || b".-:".contains(&b))),
            "{name} must be an HTTPS origin without credentials or paths"
        );
        println!("cargo:rustc-env={name}={origin}");
    }
    tauri_build::build();
}
