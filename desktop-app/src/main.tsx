import React, { useEffect, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { invoke, isTauri } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { Radar, radarModel, supportSignals, desktopLabel, usableObservation, type DesktopClient, type InstalledApps, type Observation, type BrowserProbeReport, type RadarReport, type ScanStage, type SupportSignal } from './radar';
import { DedicatedPass, type Passes, type PassAction, type RadarSummary } from './dedicated';
import { UpdateBanner, UpdateSettings, useAppUpdates } from './updates';
import './style.css';

type Profile = { applied?: string; requested?: string; city?: string; state: string };
type SubscriptionNotice = {
  days_left: number;
  expires_at: number;
  urgency: 'ok' | 'warning_3d' | 'warning_1d' | 'expires_today' | 'expired';
  renew_url: string;
};
type Account = { subscription_notice?: SubscriptionNotice | null; dedicated_passes?: Passes; dedicated_pass_price_rub?: number; email: string; access: string; has_software_license: boolean; subscription_expires_at?: number; is_suspended: boolean; suspension_reason?: string; profile: Profile; bound: { limit:number; items:{id:string;name:string;os:string}[] } };
type Protection = "checking" | "active" | "blocked" | "restored" | "unmonitored";
type RequestedEngine = "proxy" | "split_tun";
type FallbackReason = "uac_cancelled" | "authorization_cancelled" | "elevation_failed" | "elevation_timeout" | "sidecar_missing" | "sidecar_invalid" | "tun_init_failed" | "recovery_pending";
type Connection = { requested_engine?:RequestedEngine; active_engine?:"proxy"|"split_tun"|"proxy_fallback"|null; fallback_reason?:FallbackReason|null; tun_failed?:boolean; reconnect_needed?:boolean; dedicated_hold?:boolean; tun_recovery?:"none"|"recovered"|"pending"; protection?:Protection|null; killswitch_enabled?:boolean; port:number|null; region:string|null; system_proxy?:boolean; system_proxy_supported?:boolean; proxy_error?:string|null; uptime_seconds?:number|null; device_id?:string|null };
type Region = { id:string; name:string };
const tabs = ['Рабочее место','Радар подключения','CLI и Терминал','Настройки'];
const empty = {port:null,region:null};
type WorkSettings = {close_to_tray:boolean; autostart:boolean; english_browser:boolean};
type ProfileState = 'new' | 'ready' | 'open' | null;
const shellNames = ['PowerShell','CMD','Bash / Zsh'] as const;
const native = isTauri();

function formatActivationCode(value: string) {
  const upper = value.toUpperCase().replace(/\s+/g, '');
  if (upper === 'Y' || !upper) return upper;
  const body = upper.replace(/^YW-?/, '').replace(/[^A-Z2-7]/g, '').slice(0, 20);
  return body ? 'YW-' + (body.match(/.{1,5}/g) ?? []).join('-') : 'YW';
}

const dayWords: Record<string, string> = { one: 'день', few: 'дня', many: 'дней', other: 'дня' };
function remainingDays(notice: SubscriptionNotice) {
  if (notice.urgency === 'expired') return 'Канал истёк';
  if (notice.urgency === 'expires_today') return 'До конца меньше дня';
  return 'Осталось ' + notice.days_left + ' ' + dayWords[new Intl.PluralRules('ru').select(notice.days_left)];
}

function SubscriptionBanner({ notice, renew, dismiss }: {
  notice: SubscriptionNotice;
  renew: () => void;
  dismiss?: () => void;
}) {
  const heading = notice.urgency === 'expired' ? 'Срок подписки на канал закончился' :
    notice.urgency === 'expires_today' ? 'Канал заканчивается сегодня' : remainingDays(notice);
  return <section className="panel subscription-banner" data-urgency={notice.urgency} aria-label="Срок подписки">
    <div><h2>{heading}</h2><p>{notice.urgency === 'expired' ? 'Продление восстановит подключение.' :
      'Продление добавит 30 дней к текущему сроку.'}</p></div>
    <div className="actions">
      <button className="primary" onClick={renew}>Продлить в браузере</button>
      {dismiss && <button className="quiet" onClick={dismiss}>Скрыть до перезапуска</button>}
    </div>
  </section>;
}

const activationErrors: Record<string, string> = {
  INVALID_ACTIVATION_CODE: 'Этот код недействителен. Скопируйте актуальный код в разделе «Компьютер».',
  DEVICE_LIMIT_REACHED: 'К аккаунту уже привязаны два ПК. Отвяжите один из них и повторите активацию.',
  DEVICE_REVOKED: 'Этот ПК отвязан от аккаунта. Получите код в кабинете и активируйте компьютер снова.',
};

function App() {
  const [code,setCode] = useState('');
  const [account,setAccount] = useState<Account|null>(null);
  const [hiddenSubscription,setHiddenSubscription] = useState('');
  const subscription = account?.has_software_license && !account.is_suspended ? account.subscription_notice : null;
  const subscriptionKey = subscription ? subscription.expires_at + ':' + subscription.urgency : '';
  const urgency = subscription?.urgency;
  useEffect(() => {
    if (native && (urgency === 'warning_3d' || urgency === 'warning_1d' || urgency === 'expires_today')) {
      void invoke('notify_subscription', {urgency}).catch(() => {});
    }
  }, [subscriptionKey, urgency]);
  const [regions,setRegions] = useState<Region[]>([]);
  const [connection,setConnection] = useState<Connection>(empty);
  const [passState,setPassState] = useState<Passes|null>(null);
  const [summary,setSummary] = useState<RadarSummary|null>(null);
  const [launchWarning,setLaunchWarning] = useState<{destination:string; timezone:string}|null>(null);
  const passRevision = useRef(0);
  const radarRequest = useRef<Promise<RadarSummary>|null>(null);
  const [lastScan, setLastScan] = useState<Date|null>(null);
  const [observed,setObserved] = useState<RadarReport|null>(null);
  const [browserReport,setBrowserReport] = useState<BrowserProbeReport|null>(null);
  const [browserToast,setBrowserToast] = useState(0);
  const [useStun,setUseStun] = useState(true);
  const [useBrowserDns,setUseBrowserDns] = useState(true);
  const [outbound,setOutbound] = useState<Observation|null>(null);
  const networkRevision = useRef(0);
  const [radarStage,setRadarStage] = useState<ScanStage|null>(null);
  const [tab,setTab] = useState(0);
  const [error,setError] = useState('');
  const [working,setBusy] = useState(false);
  const workLock = useRef(false);
  const [profileState,setProfileState] = useState<ProfileState>(null);
  const [settings,setSettings] = useState<WorkSettings|null>(null);
  const [contrast,setContrast] = useState(() => localStorage.getItem('workspace.contrast') === 'on');
  const [shellIndex,setShellIndex] = useState(0);
  const [copied,setCopied] = useState('');
  const [activation,setActivation] = useState<"checking"|"required"|"offline"|"restored">(native ? "checking" : "required");
  const updates = useAppUpdates(native);
  const busy = working || updates.phase === 'downloading' || updates.phase === 'installing';
  const [message,setMessage] = useState('');
  const [installed,setInstalled] = useState<InstalledApps|null>(null);
  const [launching,setLaunching] = useState<Partial<Record<DesktopClient,boolean>>>({});
  const launchLocks = useRef(new Set<DesktopClient>());
  const clientCheck = useRef<Promise<void>|null>(null);
  const [refreshingClients,setRefreshingClients] = useState(false);
  const connecting = useRef<Promise<Connection>|null>(null);

  function refreshClients() {
    if (!clientCheck.current) {
      clientCheck.current = invoke<InstalledApps>('check_running_clients')
        .then(result => setInstalled(previous => ({
          claude: result.claude ?? previous?.claude ?? null,
          chatgpt: result.chatgpt ?? previous?.chatgpt ?? null,
          cursor: result.cursor ?? previous?.cursor ?? null,
        })))
        .finally(() => { clientCheck.current = null; });
    }
    return clientCheck.current;
  }

  async function rediscoverClients() {
    setRefreshingClients(true);
    try {
      await invoke('discover_installed_clients');
      await clientCheck.current?.catch(() => {});
      await refreshClients();
    } catch(e) { setError(String(e)); }
    finally { setRefreshingClients(false); }
  }
  const [resetRegion,setResetRegion] = useState<string|null>(null);
  const profileRegion = connection.region || account?.profile.applied;
  useEffect(() => {
    if (!native) return;
    const openRadar = () => { void invoke<boolean>('take_radar_link').then(requested => { if (requested) setTab(1); }).catch(() => {}); };
    const radarLink = listen('open-radar', openRadar);
    void radarLink.then(openRadar).catch(() => {});
    const progress = listen<'network'|'services'|'profile'>('radar-progress', event => setRadarStage(event.payload));
    return () => { void radarLink.then(unlisten => unlisten()).catch(() => {}); void progress.then(unlisten => unlisten()).catch(() => {}); };
  }, []);
  useEffect(() => { setResetRegion(null); setCopied(''); }, [profileRegion, tab]);
  useEffect(() => { setProfileState(null); }, [profileRegion]);
  useEffect(() => {
    if (!native || tab !== 0 || !profileRegion) return;
    let active = true;
    const update = () => { void invoke<ProfileState>('browser_profile_state',{region:profileRegion}).then(value => { if (active) setProfileState(value); }).catch(() => {}); };
    update();
    const interval = window.setInterval(update, 8000);
    window.addEventListener('focus', update);
    return () => { active = false; window.clearInterval(interval); window.removeEventListener('focus', update); };
  }, [tab,profileRegion]);
  useEffect(() => {
    if (!native || !account) return;
    void invoke<WorkSettings>('work_settings').then(setSettings).catch(() => setError('Не удалось загрузить параметры работы'));
  }, [account?.email]);
  useEffect(() => {
    if (!native) return;
    let active = true;
    const refresh = () => { if (active) void refreshClients().catch(() => {}); };
    const onChanged = listen('desktop-clients-changed', () => {
      void Promise.resolve(clientCheck.current).catch(() => {}).then(refresh);
    });
    refresh();
    const retry = window.setTimeout(refresh, 150);
    const poll = window.setInterval(refresh, 8000);
    window.addEventListener('focus', refresh);
    return () => {
      active = false;
      window.clearTimeout(retry);
      window.clearInterval(poll);
      window.removeEventListener('focus', refresh);
      void onChanged.then(unlisten => unlisten()).catch(() => {});
    };
  }, []);
  useEffect(() => { if (native) void refreshClients().catch(() => {}); }, [connection.port,connection.system_proxy]);
  const refreshLock = useRef(false);
  const sessionRevision = useRef(0);
  async function refreshAccount(showError = false) {
    if (refreshLock.current) return;
    refreshLock.current = true;
    const revision = sessionRevision.current;
    try {
      const updated = await invoke<Account>('account');
      if (revision !== sessionRevision.current) return;
      setAccount(updated);
      setActivation("restored");
      if (showError || activation === "offline") setError('');
    } catch (error) {
      if (revision !== sessionRevision.current) return;
      const message = String(error);
      if (message === 'DEVICE_REVOKED') {
        setAccount(null);
        setConnection(empty);
        setActivation("required");
        setError(message);
      } else if (message === "ACTIVATION_REQUIRED") {
        setAccount(null);
        setConnection(empty);
        setActivation("required");
      } else {
        setActivation("offline");
        if (showError) setError(message);
      }
    } finally { refreshLock.current = false; }
  }
  useEffect(() => {
    if (!native) return;
    void refreshAccount(true);
    invoke<Region[]>('regions').then(setRegions).catch(() => {});
  }, []);
  useEffect(() => {
    if (!native || (!account && activation !== "offline")) return;
    const check = () => { if (!workLock.current && !connecting.current) void refreshAccount(); };
    const id = window.setInterval(check, account?.profile.state === 'pending' ? 3000 : 15000);
    window.addEventListener('focus', check);
    return () => { window.clearInterval(id); window.removeEventListener('focus', check); };
  }, [activation, account?.email, account?.profile.state]);
  useEffect(() => {
    if (!native || !account) return;
    let active = true;
    let checking = false;
    const refresh = async () => {
      if (checking || workLock.current || connecting.current) return;
      checking = true;
      try {
        const route = await invoke<Connection>('tunnel_status');
        if (active && !workLock.current && !connecting.current) setConnection(route);
      } catch { /* A later poll retries transient errors. */ }
      finally { checking = false; }
    };
    void refresh();
    const event = listen('tunnel-changed', () => void refresh());
    const id = window.setInterval(refresh, 1500);
    return () => {
      active = false;
      window.clearInterval(id);
      void event.then(unlisten => unlisten()).catch(() => {});
    };
  }, [!!account]);
  const held = connection.dedicated_hold || passState?.mode === 'DEDICATED_EXPIRED_HOLD';
  const blocked = held || connection.tun_failed || connection.reconnect_needed ||
    connection.protection === 'blocked' || connection.protection === 'checking';
  const online = !!connection.port && !blocked;
  const healthySplitTun = online && connection.active_engine === 'split_tun' &&
    (connection.protection === 'active' || connection.protection === 'restored');
  const engineText = connection.active_engine === 'split_tun' ? 'Split-TUN'
    : connection.active_engine ? 'Proxy' : 'Выключен';
  const proxyFallback = connection.active_engine === 'proxy_fallback';
  const [routeAction, setRouteAction] = useState<'starting'|'stopping'|null>(null);
  function changeRoute(retry = false) {
    return perform(async () => {
      const start = retry || !connection.port;
      setRouteAction(start ? 'starting' : 'stopping');
      try {
        if (connection.port) setConnection(await invoke<Connection>('disconnect'));
        if (start) setConnection(await invoke<Connection>('connect_tunnel'));
      } finally { setRouteAction(null); }
    });
  }
  const routeStatus = routeAction === 'starting' ? 'Подключение…' : routeAction === 'stopping' ? 'Останавливаем…'
    : held ? 'Пауза · HOLD'
    : connection.tun_failed || connection.reconnect_needed || connection.protection === 'blocked' ? 'Ошибка маршрута'
    : connection.protection === 'checking' ? 'Подключение…'
    : online ? connection.protection === 'unmonitored' ? 'Подключён' : 'Защищён' : 'Выключен';
  const statusTone = held || routeAction || connection.protection === 'checking' ? 'warning'
    : blocked ? 'error' : online && connection.protection !== 'unmonitored' ? 'ok' : 'idle';
  const fallbackText = connection.fallback_reason && ({
    uac_cancelled: 'Права администратора не выданы.',
    authorization_cancelled: 'Права администратора не выданы.',
    elevation_failed: 'Система не выдала права администратора.',
    elevation_timeout: 'Истекло время ожидания прав администратора.',
    sidecar_missing: 'В установке отсутствуют файлы системного режима.',
    sidecar_invalid: 'Не удалось проверить файлы системного режима.',
    tun_init_failed: 'Не удалось запустить сетевой адаптер.',
    recovery_pending: 'Система ещё не освободила сетевой адаптер.',
  } satisfies Record<FallbackReason, string>)[connection.fallback_reason];
  const needsPermission = connection.fallback_reason?.endsWith('cancelled') || connection.fallback_reason?.startsWith('elevation_');
  const protectionText = connection.tun_failed ? 'Сетевой адаптер остановился. Переподключите контур.'
    : connection.reconnect_needed ? 'Переподключите контур, чтобы применить канал.'
    : held ? 'Рабочие соединения на паузе.'
    : connection.protection === 'blocked' ? 'Связь прервана. Восстанавливаем рабочие соединения.'
    : connection.protection === 'checking' ? 'Проверяем связь с рабочим шлюзом.'
    : connection.protection === 'unmonitored' ? 'Автоблокировка при сбое выключена.'
    : online ? 'Автоблокировка при сбое включена.' : 'Выберите, какие приложения должны использовать рабочий канал.';
  useEffect(() => {
    setOutbound(null);
    setObserved(null);
    setLastScan(null);
    setBrowserReport(null);
    if (!native || !online) return;
    let active = true;
    const refresh = () => {
      const revision = networkRevision.current;
      return invoke<Observation>('observe_tunnel')
        .then(result => { if (active && revision === networkRevision.current) setOutbound(usableObservation(result)); })
        .catch(() => { if (active && revision === networkRevision.current) setOutbound(null); });
    };
    void refresh();
    const id = window.setInterval(refresh, 45000);
    return () => { active = false; window.clearInterval(id); };
  }, [online, connection.port, connection.region, connection.active_engine]);
  function refreshSummary() {
    if (radarRequest.current) return radarRequest.current;
    const revision = passRevision.current;
    const pending = invoke<RadarSummary>('radar_summary').then(data => {
      if (revision === passRevision.current) setSummary(data);
      return data;
    }).finally(() => { if (radarRequest.current === pending) radarRequest.current = null; });
    radarRequest.current = pending;
    return pending;
  }
  useEffect(() => {
    passRevision.current++;
    setPassState(account?.dedicated_passes ?? null);
    setSummary(null);
    radarRequest.current = null;
  }, [account?.email, account?.profile.applied]);
  useEffect(() => {
    if (!native || account?.access !== 'active') return;
    let active = true;
    let pending = false;
    const poll = async () => {
      if (pending || workLock.current || document.hidden) return;
      pending = true;
      const revision = passRevision.current;
      try {
        const data = await invoke<Passes>('dedicated_status');
        if (!active || revision !== passRevision.current || workLock.current) return;
        setPassState(data);
        if (tab === 1) await refreshSummary();
      } catch { /* The next poll retries a transient outage. */ }
      finally { pending = false; }
    };
    void poll();
    const timer = window.setInterval(poll, tab === 1 ? 15000 : 5000);
    window.addEventListener('focus', poll);
    return () => { active = false; window.clearInterval(timer); window.removeEventListener('focus', poll); };
  }, [account?.email, account?.access, account?.profile.applied, tab]);
  async function perform(action: () => Promise<unknown>) {
    if (busy || workLock.current) return;
    workLock.current = true;
    setBusy(true); setError(''); setMessage('');
    try { await action(); } catch(e) { setError(String(e)); } finally { workLock.current = false; setBusy(false); }
  }
  async function ensureRoute() {
    if (!routeReady) throw new Error('Лицензия, подписка и регион должны быть активны.');
    if (connection.port) return;
    if (!connecting.current) {
      connecting.current = invoke<Connection>('connect_tunnel').finally(() => { connecting.current = null; });
    }
    setConnection(await connecting.current);
  }
  const open = (destination:string, notice?: string) => perform(async () => {
    await ensureRoute();
    const localTimezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
    const timezone = await invoke<string|null>('launch_browser',{destination, localTimezone});
    if (timezone) setLaunchWarning({destination, timezone});
    else { setLaunchWarning(null); setProfileState('open'); if (notice) setMessage(notice); }
  });
  useEffect(() => {
    if (!native || !account) return;
    const event = listen('open-work-browser', () => { setTab(0); void open('workspace'); });
    return () => { void event.then(remove => remove()).catch(() => {}); };
  }, [tab, account, connection.port, busy]);
  const changePass = (action:PassAction, passId?:number, tabsClosed = false) => perform(async () => {
    passRevision.current++;
    const data = await invoke<Passes>('dedicated_action', {action, passId, tabsClosed});
    setPassState(data);
    setSummary(null);
    radarRequest.current = null;
    networkRevision.current++;
    setOutbound(null);
    setObserved(null);
    setLastScan(null);
    setBrowserReport(null);
    if (tab === 1) await refreshSummary();
  });
  const official = (page:string) => perform(() => invoke('open_official',{page}));
  async function launchClient(client:DesktopClient, restart:boolean, explicit = false) {
    if (launchLocks.current.has(client)) return;
    launchLocks.current.add(client);
    setLaunching(previous => ({...previous, [client]:true}));
    setError('');
    setMessage('');
    try {
      await ensureRoute();
      setConnection(await invoke<Connection>('launch_desktop_app',{client,restart,explicit}));
      setMessage("Клиент запущен с настройками прокси.");
    } catch(e) { setError(String(e)); }
    finally {
      launchLocks.current.delete(client);
      setLaunching(previous => ({...previous, [client]:false}));
      void Promise.resolve(clientCheck.current).catch(() => {}).then(refreshClients).catch(() => {});
    }
  }
  async function copy(text:string, key = '') {
    try { await navigator.clipboard.writeText(text); setCopied(key); if (!key || key === 'support') setMessage('Скопировано ✓'); }
    catch { setError('Буфер обмена недоступен. Выделите текст вручную.'); }
  }
  const changeSetting = (setting:'autostart'|'tray'|'browser-language',enabled:boolean) => perform(async () => {
    await invoke('set_work_setting',{setting,enabled});
    setSettings(await invoke<WorkSettings>('work_settings'));
  });
  async function readRadar() {
    networkRevision.current += 1;
    setRadarStage('start');
    try {
      const result = await invoke<RadarReport>('run_system_radar',{checkDns:true});
      networkRevision.current += 1;
      setObserved(result);
      setLastScan(new Date());
      setOutbound(usableObservation(result.network));
      setRadarStage('complete');
      await radarRequest.current?.catch(() => {});
      await refreshSummary().catch(() => {});
      return result;
    } catch (error) { setRadarStage(null); throw error; }
  }
  useEffect(() => {
    if (radarStage !== 'complete') return;
    const timer = window.setTimeout(() => setRadarStage(null), 1400);
    return () => window.clearTimeout(timer);
  }, [radarStage]);
  const scan = () => perform(readRadar);
  const copySupport = (signals: SupportSignal[]) => perform(async () => {
    const mode = passState?.mode ?? summary?.mode;
    const held = mode == null ? null : mode === "DEDICATED_EXPIRED_HOLD";
    await copy(await invoke<string>("support_report", {signals, held}), "support");
  });
  useEffect(() => {
    if (!native) return;
    const ping = listen('radar-device-ping-failed', () => setError('Не удалось записать IP компьютера для сверки с телефоном. Повторите проверку.'));
    const event = listen<BrowserProbeReport>('browser-probe-update', ({payload}) => {
      setBrowserReport(payload);
      setLastScan(new Date());
      setBrowserToast(current => current + 1);
    });
    return () => { void event.then(unlisten => unlisten()).catch(() => {}); void ping.then(unlisten => unlisten()).catch(() => {}); };
  }, []);
  useEffect(() => {
    if (!browserToast) return;
    const timer = window.setTimeout(() => setBrowserToast(0), 4500);
    return () => window.clearTimeout(timer);
  }, [browserToast]);
  const scanBrowser = (ignoreTimezone = false) => perform(async () => {
    setBrowserReport(null);
    const snapshot = observed ?? await readRadar();
    const localTimezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
    const report = await invoke<BrowserProbeReport | {timezone_warning:string}>('run_browser_probe', {
      stun: useStun, checkDns: useBrowserDns, exitIp: snapshot.network?.ip ?? null, exitCountry: summary?.location.country_code ?? null,
      localTimezone, ignoreTimezone,
    });
    if ('timezone_warning' in report) {
      setLaunchWarning({destination:'probe', timezone:report.timezone_warning});
      return;
    }
    setLaunchWarning(null);
    setBrowserReport(report);
    setLastScan(new Date());
    setBrowserToast(current => current + 1);
  });
  const connectRadar = () => changeRoute(true);
  const repairRadar = () => perform(async () => {
    if (!profileRegion) return;
    await invoke('repair_browser_profile',{region:profileRegion});
    await readRadar();
    setMessage('Настройки рабочего профиля обновлены');
  });
  const routeRadarClient = (client:DesktopClient, usePac = false) => perform(async () => {
    if (usePac) setConnection(await invoke<Connection>('set_system_proxy',{enabled:true}));
    setConnection(await invoke<Connection>('launch_desktop_app',{client,restart:true}));
    await readRadar();
  });
  const endpoint = connection.port ? '127.0.0.1:' + connection.port : '';
  const proxy = 'http://' + endpoint;
  const socks = 'socks5h://' + endpoint;
  const variables = [["HTTP_PROXY", proxy], ["HTTPS_PROXY", proxy], ["ALL_PROXY", socks]];
  const commands = [
    ["Remove-Item Env:NO_PROXY -ErrorAction SilentlyContinue", ...variables.map(([key,value]) => "$env:" + key + " = '" + value + "'")].join("\n"),
    ['set "NO_PROXY="', ...variables.map(([key,value]) => 'set "' + key + '=' + value + '"')].join("\n"),
    ["unset NO_PROXY no_proxy", ...variables.flatMap(([key,value]) => [key, key.toLowerCase()].map(name => "export " + name + "='" + value + "'"))].join("\n"),
  ];
  const regionName = regions.find(region=>region.id===profileRegion)?.name || profileRegion?.toUpperCase() || 'Регион не выбран';
  const routeReady = account?.has_software_license && !account.is_suspended &&
    account.access === 'active' && account.profile.state === 'applied' && !!account.profile.applied;
  const changeTab = (index:number) => { setTab(index); setError(''); setMessage(''); };
  const expiryBanner = subscription && urgency !== "ok" && (urgency === "expired" || hiddenSubscription !== subscriptionKey)
    ? <SubscriptionBanner notice={subscription} renew={()=>void official("renewal")}
        dismiss={urgency === "expired" ? undefined : ()=>setHiddenSubscription(subscriptionKey)}/> : null;
  const signOut = () => perform(async () => {
    sessionRevision.current++;
    await invoke('sign_out'); setLaunchWarning(null); setConnection(empty); setAccount(null); setActivation('required'); setCode(''); setHiddenSubscription('');
  });
  const dedicatedCard = account && passState && (held ? passState.held_pass : passState.active_pass) &&
    <DedicatedPass passes={passState} price={account.dedicated_pass_price_rub}
      location={[account.profile.city, regionName].filter(Boolean).join(', ')} busy={busy}
      action={(action, id, tabsClosed)=>void changePass(action, id, tabsClosed)} buy={()=>void official('dedicated-checkout')}/>;
  const radarProps = {
    engine: engineText, lastScan, protectedByTun: healthySplitTun, openPhone: ()=>void official('mobile'),
    summary, english: settings?.english_browser ?? true, scanPaused: !!held,
    refreshPass: passState?.active_pass && passState.active_pass.refresh_count < passState.active_pass.max_refreshes
      ? ()=>void changePass('refresh-channel') : undefined,
    report: online ? observed : null, browserReport: online ? browserReport : null, stun: useStun, setStun: setUseStun,
    checkDns: useBrowserDns, setCheckDns: setUseBrowserDns, scanBrowser: ()=>void scanBrowser(),
    network: outbound, connected: online, busy, stage: radarStage, region: regionName,
    scan: ()=>void scan(), connect: ()=>void connectRadar(), repair: ()=>void repairRadar(),
    time: ()=>void perform(()=>invoke('open_time_settings')),
    client: (client: DesktopClient, usePac?: boolean)=>void routeRadarClient(client,usePac),
    copy: (text: string)=>void copy(text),
  };
  const radar = radarModel(radarProps);
  const regionalSetup = account?.has_software_license && !account.is_suspended && account.access === 'active';
  const gate = account?.is_suspended ? ['Доступ на паузе', 'Статус доступа можно уточнить в кабинете.']
    : !account?.has_software_license ? ['Лицензия ещё не подключена', 'Начальный доступ включает лицензию для двух компьютеров и подписку на рабочий канал.']
    : account?.access === 'expired' ? ['Подписка на канал истекла', 'Продлите подписку, чтобы восстановить рабочий канал.']
    : !regionalSetup ? ['Подключите рабочий канал', 'После оплаты рабочий канал станет доступен на этом компьютере.']
    : account?.profile.state === 'pending' ? ['Закрепляем регион', 'Лаунчер откроет рабочее место, как только регион будет готов.']
    : ['Выберите регион', 'Закрепите регион рабочего канала в кабинете.'];
  return !account ? <main className="sign-screen"><section className="sign-card panel">
    <Brand/><h1>{activation === "required" ? "Активируйте компьютер" : activation === "offline" ? "Не удалось проверить аккаунт" : "Проверяем аккаунт"}</h1>
    {!native && <p role="status">Веб-предпросмотр. Для входа откройте приложение Tauri.</p>}
    <UpdateBanner updates={updates} busy={busy}/>
    {activation === "checking" ? <p role="status">Проверяем активацию компьютера…</p> : activation === "offline" ? <>
      <p role="status">Проверка повторится автоматически. Сохранённый ключ можно использовать при восстановлении связи.</p>
      {error && <p className="error" role="alert">{error}</p>}
      <div className="gate-actions"><button className="primary" disabled={busy} onClick={()=>void perform(()=>refreshAccount(true))}>Проверить снова</button>
      <button className="quiet" disabled={busy} onClick={()=>void signOut()}>Выйти</button></div>
    </> : <form onSubmit={e=>{e.preventDefault();void perform(async()=>{
      setAccount(await invoke<Account>('activate',{code})); setCode('');
    });}}>
      <label>Код активации<input name="code" value={code} onChange={e=>{setCode(formatActivationCode(e.target.value)); if (error) setError('');}}
        autoComplete="off" autoCapitalize="characters" spellCheck={false} placeholder="YW-XXXXX-XXXXX-XXXXX-XXXXX" required/></label>
      {error && <p className="error" role="alert">{activationErrors[error] ?? error}</p>}
      <button className="primary" disabled={busy || !native || code.length !== 26}>{busy?'Активируем…':'Активировать ПК'}</button>
      <button type="button" className="quiet" disabled={busy || !native} onClick={()=>void official('desktop')}>
        {error === 'DEVICE_LIMIT_REACHED' ? 'Управление устройствами' : 'Открыть кабинет в браузере'} <Icon name="arrow"/>
      </button>
    </form>}
  </section></main> : !routeReady ? <main className="sign-screen"><section className="sign-card panel gate-card">
    <Brand/>
    <span className="pill gate-label" data-tone="warning"><i/>{account.email}</span>
    <h1>{gate[0]}</h1><p>{gate[1]}</p>
    {account.is_suspended && account.suspension_reason && <p>{account.suspension_reason}</p>}
    <div className="gate-actions">
      <button className="primary" disabled={busy} onClick={()=>void official(account.is_suspended ? 'cabinet' : regionalSetup ? 'setup' : account.access === 'expired' ? 'renewal' : 'billing')}>
        {account.is_suspended ? 'Открыть кабинет в браузере' : regionalSetup ? 'Открыть настройку региона' : 'Открыть оплату в браузере'}
      </button>
      <button disabled={busy} onClick={()=>void perform(()=>refreshAccount(true))}>
        {busy ? 'Проверяем…' : regionalSetup || account.is_suspended ? 'Проверить статус' : 'Я оплатил — проверить сейчас'}
      </button>
    </div>
    <div className="gate-footer"><small>Автопроверка каждые {account.profile.state === 'pending' ? '3 секунды' : '15 секунд'}</small><button className="quiet" disabled={busy} onClick={()=>void signOut()}>Выйти</button></div>
    <UpdateBanner updates={updates} busy={busy}/>
    {error && <p className="error" role="alert">{activationErrors[error] ?? error}</p>}
  </section></main> : <div className="shell" data-contrast={contrast}>
    <aside><Brand/><nav aria-label="Разделы">{tabs.map((label,i)=><button key={label} aria-current={i===tab?'page':undefined} onClick={()=>changeTab(i)}>
      <Icon name={['grid','radar','terminal','settings'][i]}/><span>{label}</span>
      {i===3 && updates.available && <i className="nav-update" role="img" aria-label="Доступно обновление"/>}
    </button>)}</nav>
      <div className="account"><span className="avatar" aria-hidden="true">{account.email.slice(0,1).toUpperCase()}</span>
        <div className="account-text"><strong title={account.email}>{account.email}</strong><small>Аккаунт Workspace</small></div>
        <button className="icon-button" title="Выйти" aria-label="Выйти" onClick={()=>void signOut()} disabled={busy}><Icon name="logout"/></button>
      </div>
    </aside>
    <div className="body">
      <header className="status">
        <span className="pill route-status" data-tone={statusTone} role="status"><i/>{routeStatus}</span>
        <span className="region-label" title="Закреплённый регион"><Icon name="pin"/>{regionName}</span>
        <span className="pill engine-badge">Движок · {engineText}</span>
        {subscription && <span className="pill subscription-badge" data-urgency={urgency}>{remainingDays(subscription)}</span>}
      </header>
      <UpdateBanner updates={updates} busy={busy}/>
      <main>
        <h1>{tabs[tab]}</h1>
        {expiryBanner}
        {(error || connection.proxy_error) && <p className="error" role="alert">{activationErrors[error] || error || 'Не удалось настроить рабочий маршрут. Отключите контур и попробуйте снова.'}</p>}
        {message && <p className="feedback" role="status">{message}</p>}
        {([["claude","Claude"],["chatgpt","ChatGPT"],["cursor","Cursor"]] as const).map(([client,name])=>installed?.[client]?.running && installed[client]?.unprotected && !healthySplitTun &&
          <section key={client} className="panel process-notice" aria-label={name}>
            <p role="status"><strong>{name}</strong> открыт вне рабочего контура.</p>
            <button disabled={busy || !!launching[client] || !routeReady || blocked}
              onClick={()=>void launchClient(client, true, true)}>Перезапустить через контур</button>
          </section>
        )}
        {!!browserToast && <p key={browserToast} className="radar-toast" role="status">Отчёт из рабочего браузера получен</p>}
        {launchWarning && <section className="panel profile-confirm" aria-label="Часовой пояс рабочего канала">
          <h2>Рабочий браузер не применил часовой пояс канала</h2>
          <p>В настройках даты и времени ОС выберите {launchWarning.timezone === 'Europe/Istanbul' ? '(UTC+03:00) Стамбул' : launchWarning.timezone} и повторите проверку.</p>
          <div className="actions">
            <button className="primary" disabled={busy} onClick={()=>void perform(()=>invoke('open_time_settings'))}>Открыть настройки времени</button>
            <button disabled={busy} onClick={()=>void (launchWarning.destination === "probe" ? scanBrowser() : open(launchWarning.destination))}>Перепроверить</button>
            {launchWarning.destination === "probe" && <button disabled={busy} onClick={()=>void scanBrowser(true)}>Проверить диагностику</button>}
            <button className="quiet" onClick={()=>setLaunchWarning(null)}>Отмена</button>
          </div>
        </section>}
        {tab===0 && <>
          {proxyFallback && fallbackText && <section className="panel fallback-notice" data-tone="warning" aria-label="Резервный режим">
            <div><h2>Активен режим браузера (Proxy)</h2><p>{fallbackText} {needsPermission
              ? 'Чтобы защитить поддерживаемые сервисы во всём ПК, повторите подключение и подтвердите запрос системы.'
              : 'Повторите подключение Split-TUN, когда причина устранена.'}</p></div>
            <button disabled={busy || held} onClick={()=>void changeRoute(true)}>Повторить Split-TUN</button>
          </section>}
          {connection.tun_recovery === 'pending' && !fallbackText && <p className="process-notice" role="status">Система ещё не освободила сетевой адаптер после прошлого подключения.</p>}
          {held && !passState?.held_pass && <section className="panel dedicated-panel"><h2>Выделенный канал 1:1 · HOLD</h2>
            <p>Рабочие вкладки защищены паузой. Закройте их перед возвратом в базовый режим.</p>
          </section>}
          {held && dedicatedCard}
          <section className="connection panel" data-tone={statusTone}>
            <div className="route-heading">
              <div className="route-summary"><div className="route-mark"><Icon name="radar"/></div><div>
                <h2>Контур защиты</h2>
                <p>{protectionText}</p>
              </div></div>
              <button disabled={busy} onClick={()=>void changeRoute()}>
                {routeAction === 'starting' ? 'Подключение…' : routeAction === 'stopping' ? 'Останавливаем…' : connection.port ? 'Остановить' : 'Запустить контур'}
              </button>
            </div>
            <div className="quick-launch">
              <button className="primary" disabled={busy || blocked} onClick={()=>void open('workspace')}><Icon name="browser"/>Открыть рабочий браузер</button>
              {([['claude', 'Claude'], ['chatgpt', 'ChatGPT']] as const).map(([client, name]) => {
                const app = installed?.[client];
                return <button key={client} disabled={busy || blocked || launching[client]} aria-busy={!!launching[client]} onClick={()=>{
                  if (app?.installed && app.can_launch) void launchClient(client, app.running);
                  else if (app?.installed) void open(client, name + ' установлен, но способ запуска не найден. Открыта веб-версия в рабочем браузере.');
                  else void open(client, app ? name + ' не установлен на ПК. Открыта веб-версия в рабочем браузере.' : undefined);
                }}><Icon name={client}/>{name}</button>;
              })}
              <small>Изолированный профиль · часовой пояс канала применяется при запуске</small>
            </div>
            <fieldset className="engine-picker" disabled={busy || !!connection.port}>
              <legend>Режим защиты</legend>
              <div className="engine-options">
                {([
                  ['split_tun', 'Весь ПК (Split-TUN)', 'Рабочий браузер и поддерживаемые AI-приложения на ПК.'],
                  ['proxy', 'Только браузер (Proxy)', 'Рабочий браузер и клиенты, запущенные через контур.'],
                ] as const).map(([engine, label, hint]) => {
                  const fallbackState = proxyFallback ? engine === 'proxy' ? 'active' : 'unavailable' : undefined;
                  return <label key={engine} data-fallback-state={fallbackState}>
                    <input type="radio" name="engine" value={engine} checked={(connection.requested_engine ?? 'proxy') === engine}
                      onChange={()=>void perform(async()=>setConnection(await invoke<Connection>('set_requested_engine',{engine})))}/>
                    <span className="engine-description"><strong>{label}</strong>
                      {fallbackState && <small className="engine-badge">{fallbackState === 'active' ? 'Активен сейчас' : 'Не запущен'}</small>}
                      <small>{hint}</small>
                    </span>
                  </label>;
                })}
              </div>
            </fieldset>
          </section>
          {!held && dedicatedCard}
          <details className="panel workspace-tools"><summary>Дополнительные настройки и канал 1:1</summary>
          {passState && !passState.active_pass && !passState.held_pass && <DedicatedPass passes={passState}
            price={account.dedicated_pass_price_rub} location={regionName} busy={busy}
            action={(action, id, tabsClosed)=>void changePass(action, id, tabsClosed)} buy={()=>void official('dedicated-checkout')}/>}
          <div className="cards">
            <Card title="Изолированный браузер" icon="browser" description={profileState==='open'?'Рабочий профиль открыт':profileState==='ready'?'Рабочий профиль готов':profileState==='new'?'Создадим профиль при запуске':'Отдельное рабочее окно'}>
              <label className="toggle-row"><span>Английский язык, если узел не задаёт локаль</span><input type="checkbox" role="switch" checked={settings?.english_browser ?? true} disabled={busy || !settings} onChange={e=>void changeSetting('browser-language',e.target.checked)}/></label>
              <button className="quiet reset-profile" disabled={!profileRegion || busy} onClick={()=>setResetRegion(profileRegion || null)}>Очистить профиль</button>
            </Card>
            {([['claude','Claude'],['chatgpt','ChatGPT']] as const).map(([client,name])=>{
              const app = installed?.[client];
              const label = app ? [app.variant, healthySplitTun && app.running ? 'Запущен · системный маршрут активен' : desktopLabel(app)].filter(Boolean).join(' · ') : installed ? 'Статус недоступен' : 'Проверяем установку…';
              return <Card key={client} title={name + ' Desktop'} icon={client} description={label}>
                {app && !app.installed && <button className="launch-button" disabled={busy} onClick={()=>void official(client)}>Скачать клиент</button>}
              </Card>;
            })}
          </div>
          {connection.system_proxy_supported && <label className="toggle-row"><span>Точечный маршрут для Store-приложений</span><input type="checkbox" role="switch" checked={!!connection.system_proxy} disabled={busy} onChange={e=>{
            const enabled=e.target.checked; void perform(async()=>{ if (enabled) await ensureRoute(); setConnection(await invoke<Connection>('set_system_proxy',{enabled})); });
          }}/></label>}
          <button className="quiet refresh-clients" disabled={refreshingClients} onClick={()=>void rediscoverClients()}>Обновить список приложений</button>
          {resetRegion && resetRegion === profileRegion && <section className="panel profile-confirm" aria-label="Подтвердить очистку профиля">
            <p>Удалить данные рабочего профиля для {resetRegion.toUpperCase()}? Сначала закройте его окно.</p>
            <div className="actions"><button disabled={busy} onClick={()=>void perform(async()=>{
              await invoke('clear_browser_profile',{region:resetRegion});setResetRegion(null);setProfileState('new');setMessage('Рабочий профиль очищен');
            })}>Подтвердить очистку</button><button disabled={busy} onClick={()=>setResetRegion(null)}>Отмена</button></div>
          </section>}
          <button className="cli-link" onClick={()=>changeTab(2)}><Icon name="terminal"/><span>Терминал, Cursor или Codex CLI</span><strong>Настроить окружение</strong><Icon name="arrow"/></button>
          </details>
        </>}
        {tab===1 && <Radar {...radarProps} model={radar}/>}
        {tab===2 && <>
          <section className="panel cli-panel">
            <div className="section-heading"><h2>Подключение команд</h2><span className="chip">{online ? "Маршрут активен" : blocked ? "Трафик заблокирован" : "Отключено"}</span></div>
            <div className="command-tabs" role="group" aria-label="Оболочка">{shellNames.map((name,index)=><button key={name} aria-pressed={index===shellIndex} onClick={()=>{setShellIndex(index);setCopied('');}}>{name}</button>)}</div>
            {connection.port ? <>
              <dl className="proxy-addresses"><div><dt>HTTP</dt><dd>{proxy}</dd></div><div><dt>SOCKS5</dt><dd>{socks}</dd></div></dl>
              <pre className="command-text">{commands[shellIndex]}</pre>
              <div className="actions"><button onClick={()=>void copy(commands[shellIndex],'cli')}>{copied==='cli'?'Скопировано ✓':'Копировать'}</button>
                <button disabled={busy || blocked} onClick={()=>void perform(()=>invoke('launch_terminal'))}>Открыть терминал</button></div>
            </> : <><p>Подключите рабочий маршрут, чтобы получить команды.</p><button className="standalone" disabled={busy || !routeReady} onClick={()=>void perform(ensureRoute)}>Подключить</button></>}
          </section>
          <section className="panel"><div className="section-heading"><h2>Cursor / VS Code</h2><Icon name="terminal"/></div>
            <p>Откройте настройки IDE и укажите адрес в поле HTTP Proxy.</p>
            {connection.port && <div className="ide-address"><code>{proxy}</code><button onClick={()=>void copy(proxy,'ide')}>{copied==='ide'?'Скопировано ✓':'Копировать'}</button></div>}
          </section>
        </>}
        {tab===3 && <div className="settings-grid">
          <section className="panel devices-panel">
            <div className="section-heading"><h2>Аккаунт и устройства</h2><span className="chip">{account.bound.items.length} из {account.bound.limit}</span></div>
            <p>{account.access==='active'?'Подписка активна':'Подписка неактивна'} · {regionName}</p>
            <ul className="device-slots">{account.bound.items.map(item=><li key={item.id}><Icon name={['ios','android'].includes(item.os)?'phone':'browser'}/><span>{item.name}<small>{['ios','android'].includes(item.os)?'Телефон':'ПК'}</small></span>
              {connection.device_id===item.id && <strong>Это устройство</strong>}</li>)}</ul>
            <button className="standalone" disabled={busy} onClick={()=>void official('workspace')}>Открыть веб-кабинет</button>
          </section>
          <UpdateSettings updates={updates} busy={busy}/>
          <section className="panel preferences-panel">
            <h2>Параметры работы</h2>
            <label className="toggle-row"><span>Автозапуск при входе в ОС</span><input type="checkbox" role="switch" checked={!!settings?.autostart} disabled={busy || !settings} onChange={e=>void changeSetting('autostart',e.target.checked)}/></label>
            <label className="toggle-row"><span>Сворачивать в трей при закрытии</span><input type="checkbox" role="switch" checked={!!settings?.close_to_tray} disabled={busy || !settings} onChange={e=>void changeSetting('tray',e.target.checked)}/></label>
            <label className="toggle-row"><span>Killswitch рабочего маршрута</span><input type="checkbox" role="switch" checked={connection.killswitch_enabled ?? true} disabled={busy || !connection.port || connection.active_engine === "split_tun" || connection.tun_failed || connection.dedicated_hold} onChange={e=>{
              const enabled=e.target.checked; void perform(async()=>setConnection(await invoke<Connection>("set_killswitch",{enabled})));
            }}/></label>
            <p>При сбое Relay блокирует рабочие соединения. В Split-TUN проверка шлюза включена постоянно.</p>
            <label className="toggle-row"><span>Повышенный контраст</span><input type="checkbox" role="switch" checked={contrast} onChange={e=>{setContrast(e.target.checked);localStorage.setItem('workspace.contrast',e.target.checked?'on':'off');}}/></label>
            <div className="actions"><button onClick={()=>void copy(['Workspace ' + updates.version, 'Регион: ' + regionName, 'Маршрут: ' + (online ? "активен" : blocked ? "заблокирован" : "отключён"), 'Задержка: ' + (outbound ? outbound.latency_ms + ' мс' : 'недоступна'), 'Точечный маршрут Store: ' + (connection.system_proxy?'включён':'выключен'),...updates.diagnostics].join('\n'),'log')}>{copied==='log'?'Скопировано ✓':'Скопировать лог'}</button></div>
          </section>
        </div>}
      </main>
      <footer className="service-footer">
        <span>{updates.version ? 'v' + updates.version : 'Yousoro Workspace'}</span>
        <button className="quiet" disabled={busy} onClick={()=>void official('cabinet')}>Кабинет <Icon name="arrow"/></button>
        <button className="quiet" disabled={busy} onClick={()=>void copySupport(supportSignals(radar.readiness))}>{copied === 'support' ? 'Скопировано ✓' : 'Скопировать диагностику'}</button>
        <button className="quiet" disabled={busy || updates.phase !== 'idle'} onClick={()=>{changeTab(3);void updates.refresh();}}>Проверить обновления</button>
      </footer>
    </div>
  </div>;
}
function Brand(){return <div className="brand"><img src="/favicon.svg" width="25" height="25" alt=""/><strong>Yousoro</strong> Workspace</div>;}
function Icon({name}:{name:string}) {
  const paths: Record<string,string> = {
    grid:'M3 3h7v7H3z M14 3h7v7h-7z M3 14h7v7H3z M14 14h7v7h-7z',
    radar:'M20 12a8 8 0 1 1-8-8 M16 12a4 4 0 1 1-4-4 M12 12l8-8 M12 12h.01',
    terminal:'M4 5h16v14H4z M7 9l3 3-3 3 M12 15h4',
    settings:'M4 7h16 M4 17h16 M8 4v6 M15 14v6',
    logout:'M10 4H4v16h6 M9 12h12m-4-4 4 4-4 4',
    pin:'M19 10c0 5-7 10-7 10S5 15 5 10a7 7 0 0 1 14 0z M12 10h.01',
    browser:'M3 5h18v14H3z M3 9h18 M6 7h.01 M9 7h.01',
    arrow:'M4 12h15m-5-5 5 5-5 5',
    claude:'M12 2v20m10-10H2m17-7L5 19m0-14 14 14',
    chatgpt:'M12 3l7.8 4.5v9L12 21l-7.8-4.5v-9L12 3z M12 7l4.3 2.5v5L12 17l-4.3-2.5v-5L12 7z',
    phone:'M7 3h10v18H7z M10 18h4'
  };
  return <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.65" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d={paths[name]}/></svg>;
}
function Card({title,icon,description,children}:{title:string;icon:string;description:string;children:React.ReactNode}) {
  return <article className="panel quick-card"><div className="app-mark" data-app={icon}><Icon name={icon}/></div><h2>{title}</h2><p>{description}</p><div className="quick-actions">{children}</div></article>;
}
createRoot(document.getElementById('root')!).render(<App/>);
