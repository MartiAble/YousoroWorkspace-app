use std::{
    collections::HashMap,
    io::{self, Read, Write},
    net::{Shutdown, TcpListener, TcpStream},
    sync::{Arc, Mutex, mpsc},
    thread::{self, JoinHandle},
    time::{Duration, Instant, SystemTime},
};

const PROCESS_INTERVAL: Duration = Duration::from_millis(500);
const HEALTH_INTERVAL: Duration = Duration::from_secs(10);
const FIRST_RETRY: Duration = Duration::from_secs(1);
const MAX_RETRY: Duration = Duration::from_secs(30);
const MAX_STREAMS: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase { Checking, Active, Blocked, Restored, Unmonitored }

struct Access {
    phase: Phase,
    target: Option<u16>,
    streams: HashMap<u64, (TcpStream, TcpStream)>,
    next_stream: u64,
    stopped: bool,
    suspended: bool,
}

impl Access {
    fn change(&mut self, phase: Phase, target: Option<u16>) {
        if self.target != target || target.is_none() {
            for (_, (client, core)) in self.streams.drain() {
                let _ = client.shutdown(Shutdown::Both);
                let _ = core.shutdown(Shutdown::Both);
            }
        }
        self.phase = phase;
        self.target = target;
    }
}

type Shared = Arc<Mutex<Access>>;

fn start_stream(client: &mut TcpStream, core: &mut TcpStream) -> io::Result<bool> {
    let timeout = Some(Duration::from_secs(5));
    client.set_read_timeout(timeout)?;
    client.set_write_timeout(timeout)?;
    core.set_read_timeout(timeout)?;
    core.set_write_timeout(timeout)?;
    let mut first = [0];
    client.read_exact(&mut first)?;
    if first == [5] {
        let mut count = [0];
        client.read_exact(&mut count)?;
        let mut methods = vec![0; count[0] as usize];
        client.read_exact(&mut methods)?;
        if !methods.contains(&0) {
            client.write_all(&[5, 255])?;
            return Ok(false);
        }
        client.write_all(&[5, 0])?;
        let mut request = [0; 3];
        client.read_exact(&mut request)?;
        if request != [5, 1, 0] {
            // The stable endpoint only forwards TCP CONNECT. sing-box can accept
            // UDP ASSOCIATE even when every UDP packet is rejected by its rules.
            client.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0])?;
            return Ok(false);
        }
        core.write_all(&[5, 1, 0])?;
        let mut method = [0; 2];
        core.read_exact(&mut method)?;
        if method != [5, 0] { return Ok(false); }
        core.write_all(&request)?;
    } else {
        core.write_all(&first)?;
    }
    client.set_read_timeout(None)?;
    client.set_write_timeout(None)?;
    core.set_read_timeout(None)?;
    core.set_write_timeout(None)?;
    Ok(true)
}

fn forward(client: TcpStream, access: &Shared) -> io::Result<()> {
    let mut state = access.lock().expect("proxy state");
    let Some(port) = state.target else { return Ok(()); };
    if state.streams.len() >= MAX_STREAMS { return Ok(()); }
    let core = TcpStream::connect_timeout(&([127, 0, 0, 1], port).into(), Duration::from_millis(100))?;
    let mut reader = client.try_clone()?;
    let mut writer = core.try_clone()?;
    let id = state.next_stream;
    state.next_stream += 1;
    state.streams.insert(id, (client.try_clone()?, core.try_clone()?));
    drop(state);
    let access = access.clone();
    // SOCKS5 and HTTP CONNECT are both byte streams. Keep the two half-closes independent.
    let cleanup = access.clone();
    if let Err(error) = thread::Builder::new().spawn(move || {
        let mut client = client;
        let mut core = core;
        if start_stream(&mut client, &mut core).unwrap_or(false) {
            thread::scope(|scope| {
                scope.spawn(move || {
                    let _ = io::copy(&mut reader, &mut writer);
                    let _ = writer.shutdown(Shutdown::Write);
                });
                let _ = io::copy(&mut core, &mut client);
                let _ = client.shutdown(Shutdown::Write);
            });
        }
        access.lock().expect("proxy state").streams.remove(&id);
    }) {
        cleanup.lock().expect("proxy state").streams.remove(&id);
        return Err(error);
    }
    Ok(())
}

pub struct Proxy {
    pub port: u16,
    access: Shared,
    listener: Option<JoinHandle<()>>,
}

impl Proxy {
    pub fn bind() -> io::Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        let port = listener.local_addr()?.port();
        listener.set_nonblocking(true)?;
        let access = Arc::new(Mutex::new(Access {
            phase: Phase::Checking, target: None, streams: HashMap::new(), next_stream: 0, stopped: false, suspended: false,
        }));
        let state = access.clone();
        let worker = thread::Builder::new().name("workspace-proxy".into()).spawn(move || loop {
            if state.lock().expect("proxy state").stopped { break; }
            match listener.accept() {
                Ok((stream, _)) => {
                    // Windows accepts sockets with the listener's nonblocking mode.
                    if stream.set_nonblocking(false).is_ok() { let _ = forward(stream, &state); }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(20)),
                Err(_) => {
                    let mut access = state.lock().expect("proxy state");
                    access.stopped = true;
                    access.change(Phase::Blocked, None);
                    break;
                }
            }
        })?;
        Ok(Self { port, access, listener: Some(worker) })
    }

    pub fn suspend(&self) {
        let mut access = self.access.lock().expect("proxy state");
        access.suspended = true;
        access.change(Phase::Blocked, None);
    }

    pub fn resume(&self) {
        let mut access = self.access.lock().expect("proxy state");
        access.suspended = false;
        access.change(Phase::Checking, None);
    }

    pub fn phase(&self) -> Phase { self.access.lock().expect("proxy state").phase }
    pub fn ready(&self) -> bool { self.access.lock().expect("proxy state").target.is_some() }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        {
            let mut access = self.access.lock().expect("proxy state");
            access.stopped = true;
            access.change(Phase::Blocked, None);
        }
        if let Some(listener) = self.listener.take() { let _ = listener.join(); }
    }
}

pub trait Core {
    fn port(&self) -> u16;
    fn running(&mut self) -> bool;
}

impl Core for Box<dyn Core + Send> {
    fn port(&self) -> u16 { (**self).port() }
    fn running(&mut self) -> bool { (**self).running() }
}

struct Watchdog<C> {
    core: Option<C>,
    enabled: bool,
    phase: Phase,
    next_check: Instant,
    retry: Duration,
}

impl<C: Core> Watchdog<C> {
    fn new(now: Instant) -> Self {
        Self { core: None, enabled: true, phase: Phase::Checking, next_check: now, retry: FIRST_RETRY }
    }

    fn tick(&mut self, clock: impl Fn() -> Instant, start: &mut impl FnMut() -> Option<C>, health: &mut impl FnMut(u16) -> bool, publish: &mut impl FnMut(Phase, Option<u16>)) {
        if self.core.as_mut().is_some_and(|core| !core.running()) {
            self.block(clock(), publish);
        }
        if clock() < self.next_check { return; }
        if self.core.is_none() { self.core = start(); }
        let Some(core) = self.core.as_mut() else {
            self.block(clock(), publish);
            return;
        };
        let port = core.port();
        if !self.enabled || (health(port) && core.running()) {
            self.phase = if !self.enabled { Phase::Unmonitored }
                else if self.phase == Phase::Blocked || self.phase == Phase::Restored { Phase::Restored }
                else { Phase::Active };
            self.next_check = clock() + HEALTH_INTERVAL;
            self.retry = FIRST_RETRY;
            publish(self.phase, Some(port));
        } else {
            self.block(clock(), publish);
        }
    }

    fn block(&mut self, now: Instant, publish: &mut impl FnMut(Phase, Option<u16>)) {
        self.phase = Phase::Blocked;
        publish(self.phase, None);
        self.core = None;
        self.next_check = now + self.retry;
        self.retry = (self.retry * 2).min(MAX_RETRY);
    }
}

pub struct Monitor {
    controls: Option<mpsc::Sender<(bool, mpsc::Sender<()>)>>,
    worker: Option<JoinHandle<()>>,
}

impl Monitor {
    pub fn start<C: Core + Send + 'static>(
        proxy: &Proxy, mut start: impl FnMut() -> Option<C> + Send + 'static,
        mut health: impl FnMut(u16) -> bool + Send + 'static,
        log_phase: impl Fn(Phase) + Send + 'static,
    ) -> io::Result<Self> {
        let (controls, changes) = mpsc::channel::<(bool, mpsc::Sender<()>)>();
        let access = proxy.access.clone();
        let worker = thread::Builder::new().name("workspace-watchdog".into()).spawn(move || {
            let mut watchdog = Watchdog::new(Instant::now());
            log_phase(Phase::Checking);
            let mut publish = |phase, target| {
                let mut access = access.lock().expect("proxy state");
                if !access.stopped && !access.suspended {
                    if phase != access.phase { log_phase(phase); }
                    access.change(phase, target);
                }
            };
            loop {
                watchdog.tick(Instant::now, &mut start, &mut health, &mut publish);
                let waited = SystemTime::now();
                match changes.recv_timeout(PROCESS_INTERVAL) {
                    Ok((enabled, ack)) => {
                        watchdog.enabled = enabled;
                        watchdog.next_check = Instant::now();
                        if enabled { publish(Phase::Checking, None); }
                        let _ = ack.send(());
                    }
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        if watchdog.enabled && waited.elapsed().is_ok_and(|gap| gap > Duration::from_secs(2)) {
                            // The OS suspended scheduling. Close streams before checking the resumed route.
                            publish(Phase::Checking, None);
                            watchdog.next_check = Instant::now();
                        }
                    }
                }
            }
        })?;
        Ok(Self { controls: Some(controls), worker: Some(worker) })
    }

    pub fn set_enabled(&self, enabled: bool) -> Result<(), String> {
        let (ack, done) = mpsc::channel();
        let stopped = "Мониторинг маршрута остановлен";
        self.controls.as_ref().ok_or(stopped)?.send((enabled, ack)).map_err(|_| stopped)?;
        done.recv().map_err(|_| stopped.into())
    }
}

impl Drop for Monitor {
    fn drop(&mut self) {
        // Release the sender before joining so shutdown also interrupts retry backoff.
        drop(self.controls.take());
        if let Some(worker) = self.worker.take() { let _ = worker.join(); }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::Cell, io::{Read, Write}, sync::atomic::{AtomicBool, Ordering}};

    struct FakeCore(u16, Arc<AtomicBool>);

    impl Core for FakeCore {
        fn port(&self) -> u16 { self.0 }
        fn running(&mut self) -> bool { self.1.load(Ordering::Relaxed) }
    }

    #[test]
    fn health_failure_retries_with_backoff_and_core_exit_blocks() {
        let now = Instant::now();
        let mut watchdog = Watchdog::new(now);
        let alive = Arc::new(AtomicBool::new(true));
        let mut start = || Some(FakeCore(42, alive.clone()));
        let healthy = Cell::new(true);
        let mut health = |_| healthy.get();
        let state = Cell::new((Phase::Checking, None));
        let mut publish = |phase, target| state.set((phase, target));

        watchdog.tick(|| now, &mut start, &mut health, &mut publish);
        assert_eq!(state.get(), (Phase::Active, Some(42)));
        healthy.set(false);
        let failure = now + HEALTH_INTERVAL;
        watchdog.tick(|| failure, &mut start, &mut health, &mut publish);
        assert_eq!(state.get(), (Phase::Blocked, None));
        assert_eq!(watchdog.next_check, failure + FIRST_RETRY);
        watchdog.tick(|| failure + FIRST_RETRY, &mut start, &mut health, &mut publish);
        assert_eq!(watchdog.next_check, failure + Duration::from_secs(3));
        healthy.set(true);
        watchdog.tick(|| failure + Duration::from_secs(2), &mut start, &mut health, &mut publish);
        assert_eq!(state.get(), (Phase::Blocked, None));
        watchdog.tick(|| failure + Duration::from_secs(3), &mut start, &mut health, &mut publish);
        assert_eq!(state.get(), (Phase::Restored, Some(42)));

        alive.store(false, Ordering::Relaxed);
        watchdog.tick(|| failure + Duration::from_millis(3500), &mut start, &mut health, &mut publish);
        assert_eq!(state.get(), (Phase::Blocked, None));
    }

    #[test]
    fn disabling_relay_checks_keeps_the_local_proxy_endpoint() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let core = listener.local_addr().unwrap().port();
        let proxy = Proxy::bind().unwrap();
        let port = proxy.port;
        let monitor = Monitor::start(&proxy,
            move || Some(FakeCore(core, Arc::new(AtomicBool::new(true)))),
            |_| false, |_| {},
        ).unwrap();
        wait_phase(&proxy, Phase::Blocked);
        monitor.set_enabled(false).unwrap();
        wait_phase(&proxy, Phase::Unmonitored);
        assert_eq!(proxy.port, port);
        monitor.set_enabled(true).unwrap();
        wait_phase(&proxy, Phase::Blocked);
        assert_closed(&mut connect(port));
    }

    fn wait_phase(proxy: &Proxy, phase: Phase) {
        let until = Instant::now() + Duration::from_secs(5);
        while proxy.phase() != phase && Instant::now() < until { thread::sleep(Duration::from_millis(10)); }
        assert_eq!(proxy.phase(), phase);
    }

    fn connect(port: u16) -> TcpStream {
        let stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        stream
    }

    fn assert_closed(stream: &mut TcpStream) {
        let result = stream.read(&mut [0]);
        assert!(matches!(result, Ok(0)) || result.is_err_and(|error| matches!(error.kind(),
            io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted)));
    }

    #[test]
    fn loopback_proxy_closes_existing_and_new_streams_and_reuses_port_after_core_restart() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let core_port = listener.local_addr().unwrap().port();
        let failed = Arc::new(AtomicBool::new(true));
        let test_core = failed.clone();
        let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let starts = attempts.clone();
        let proxy = Proxy::bind().unwrap();
        let port = proxy.port;
        assert_closed(&mut connect(port));
        let monitor = Monitor::start(&proxy, move || {
            let attempt = starts.fetch_add(1, Ordering::Relaxed);
            Some(FakeCore(core_port, if attempt == 0 { test_core.clone() } else { Arc::new(AtomicBool::new(true)) }))
        }, |_| true, |_| {}).unwrap();
        wait_phase(&proxy, Phase::Active);
        let mut browser = connect(port);
        browser.write_all(b"test").unwrap();
        let (mut relay, _) = listener.accept().unwrap();
        let mut received = [0; 4];
        relay.read_exact(&mut received).unwrap();
        assert_eq!(&received, b"test");

        failed.store(false, Ordering::Relaxed);
        wait_phase(&proxy, Phase::Blocked);
        assert_closed(&mut browser);
        assert_closed(&mut connect(port));
        wait_phase(&proxy, Phase::Restored);
        assert!(attempts.load(Ordering::Relaxed) >= 2);
        let mut browser = connect(port);
        browser.write_all(b"next").unwrap();
        let (mut relay, _) = listener.accept().unwrap();
        relay.read_exact(&mut received).unwrap();
        assert_eq!(&received, b"next");

        drop(proxy);
        drop(monitor);
        assert_closed(&mut browser);
        assert!(TcpStream::connect(("127.0.0.1", port)).is_err());
    }
}
