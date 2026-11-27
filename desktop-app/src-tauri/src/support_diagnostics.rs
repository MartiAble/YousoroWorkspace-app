use crate::{apps, killswitch::Phase, split_tun::{ActiveEngine, Fallback, Recovery, RequestedEngine}};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{collections::VecDeque, sync::{Arc, Mutex}, time::SystemTime};

const LOG_LIMIT: usize = 25;
const SIGNALS: [&str; 7] = ["ipv4", "ipv6", "dns", "quic_udp_443", "browser_environment", "webrtc", "device_parity"];

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Signal { Ok, Warning, Error }

#[derive(Clone, Copy, Serialize)]
struct LogEntry {
    time_unix: u64,
    message: &'static str,
}

#[derive(Clone, Default)]
pub struct Logs(Arc<Mutex<VecDeque<LogEntry>>>);

impl Logs {
    pub fn record(&self, code: &str) {
        let Ok(mut entries) = self.0.lock() else { return; };
        if entries.len() == LOG_LIMIT { entries.pop_front(); }
        entries.push_back(LogEntry {
            time_unix: SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default().as_secs(),
            message: sanitize(code),
        });
    }
}

// Only local event codes may become report text. Never copy subprocess output,
// request errors, environment values or fragments of unknown strings.
fn sanitize(code: &str) -> &'static str {
    match code {
        "checking" => "watchdog: checking Relay",
        "active" => "watchdog: Relay confirmed",
        "blocked" => "watchdog: protected connections closed",
        "restored" => "watchdog: Relay restored",
        "unmonitored" => "watchdog: Relay monitoring disabled",
        "core_verification_failed" => "xray: sidecar verification failed",
        "core_start_failed" => "xray: failed to start or open SOCKS5",
        "tun_started" => "sing-box: TUN ready",
        "tun_fallback" => "sing-box: startup failed, using Proxy",
        "tun_relay_start_failed" => "sing-box: Relay worker failed to start",
        "tun_lost" => "sing-box: TUN lost, protected sockets closed",
        "tun_hold" => "watchdog: Dedicated Pass suspended",
        "tun_hold_released" => "watchdog: Relay check started for new pass mode",
        "tun_mode_retry" => "watchdog: Relay enrollment will retry",
        "tun_endpoint_changed" => "sing-box: reconnect required for new Relay endpoint",
        "tun_recovered" => "sing-box: previous session cleaned up",
        "tun_recovery_pending" => "sing-box: previous adapter cleanup unconfirmed",
        "stopped" => "watchdog: route stopped",
        _ => "[redacted]",
    }
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TunSession { Inactive, Running, Hold, Failed, ReconnectNeeded }

#[derive(Serialize)]
pub struct EngineState {
    pub requested_engine: RequestedEngine,
    pub active_engine: Option<ActiveEngine>,
    pub fallback_reason: Option<Fallback>,
    pub tun_session: TunSession,
    pub tun_recovery: Recovery,
}

pub fn report(
    phase: Option<Phase>, killswitch: bool, held: Option<bool>, engine: EngineState, signals: [Option<Signal>; 7],
    clients: Option<&apps::InstalledApps>, logs: &Logs,
) -> Value {
    let preflight = SIGNALS.into_iter().zip(signals).collect::<std::collections::BTreeMap<_, _>>();
    let process_guard = clients.map(|clients| {
        let summarize = |client: &Option<apps::DesktopStatus>| client.as_ref().map(|status| {
            json!({ "running": status.running, "unprotected": status.unprotected })
        });
        json!({ "claude": summarize(&clients.claude), "chatgpt": summarize(&clients.chatgpt), "cursor": summarize(&clients.cursor) })
    });
    let recent_events = logs.0.lock().map(|entries| entries.clone()).unwrap_or_default();
    let mut report = json!({
        "schema_version": 2,
        "app_version": env!("CARGO_PKG_VERSION"),
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "network_engine": engine.active_engine,
        "protection": phase,
        "killswitch_enabled": killswitch,
        "dedicated_expired_hold": held,
        "preflight": preflight,
        "process_guard": process_guard,
        "recent_events": recent_events,
    });
    report.as_object_mut().expect("diagnostics object").extend(
        serde_json::to_value(engine).expect("engine status").as_object().expect("engine object").clone()
    );
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn export_rejects_arbitrary_text_and_keeps_last_25_events() {
        let logs = Logs::default();
        logs.record("core_start_failed");
        for _ in 0..23 { logs.record("blocked"); }
        logs.record("restored");
        logs.record(r#"active Authorization: Bearer token123 vless://33333333-3333-4333-8333-333333333333@127.0.0.1:443?pbk=reality123&sid=short123 socks://user:secret@localhost jane@example.test C:\Users\jane\profile /Users/jane/profile"#);
        let signals = [Some(Signal::Ok), None, None, None, None, None, Some(Signal::Warning)];
        let engine = EngineState { requested_engine: RequestedEngine::SplitTun, active_engine: Some(ActiveEngine::ProxyFallback),
            fallback_reason: Some(Fallback::UacCancelled), tun_session: TunSession::Inactive, tun_recovery: Recovery::Recovered };
        let report = report(Some(Phase::Restored), true, Some(false), engine, signals, None, &logs);
        assert_eq!(report["requested_engine"], "split_tun");
        assert_eq!(report["active_engine"], "proxy_fallback");
        assert_eq!(report["fallback_reason"], "uac_cancelled");
        assert_eq!(report["tun_session"], "inactive");
        assert_eq!(report["tun_recovery"], "recovered");
        let events = report["recent_events"].as_array().unwrap();
        assert_eq!(events.len(), 25);
        assert_eq!(events[0]["message"], "watchdog: protected connections closed");
        assert_eq!(events[23]["message"], "watchdog: Relay restored");
        assert_eq!(events[24]["message"], "[redacted]");
        let exported = report.to_string();
        for secret in ["token123", "33333333", "reality123", "short123", "127.0.0.1", "secret", "jane", "profile"] {
            assert!(!exported.contains(secret), "{secret}");
        }
        assert_eq!(report["preflight"].as_object().unwrap().len(), 7);
        assert_eq!(report["preflight"]["ipv4"], "ok");
        assert!(report["preflight"]["ipv6"].is_null());
    }
}
