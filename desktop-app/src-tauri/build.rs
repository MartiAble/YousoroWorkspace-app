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
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        build_notification_bridge();
    }
    tauri_build::build();
}

fn build_notification_bridge() {
    use std::{env, path::PathBuf, process::Command};
    let source = "src/subscription_notification.m";
    println!("cargo:rerun-if-changed={source}");
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo output directory"));
    let object = out.join("subscription_notification.o");
    let library = out.join("libworkspace_subscription_notification.a");
    let target = env::var("TARGET").expect("Cargo target");
    let deployment = env::var("MACOSX_DEPLOYMENT_TARGET").unwrap_or_else(|_| "10.15".into());
    println!("cargo:rerun-if-env-changed=MACOSX_DEPLOYMENT_TARGET");
    let status = Command::new("xcrun")
        .args(["--sdk", "macosx", "clang", "-target", &target, "-fobjc-arc"])
        .arg(format!("-mmacosx-version-min={deployment}")).args(["-c", source, "-o"])
        .arg(&object).status().expect("Run macOS compiler");
    assert!(status.success(), "Compile subscription notification bridge");
    let status = Command::new("xcrun").args(["--sdk", "macosx", "ar", "rcs"])
        .arg(&library).arg(&object).status().expect("Run macOS archiver");
    assert!(status.success(), "Archive subscription notification bridge");
    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=workspace_subscription_notification");
    println!("cargo:rustc-link-lib=framework=AppKit");
    println!("cargo:rustc-link-lib=framework=UserNotifications");
}
