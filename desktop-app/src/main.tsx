import React, { useEffect, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { invoke, isTauri } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { Radar, desktopLabel, usableObservation, type DesktopClient, type InstalledApps, type Observation, type BrowserProbeReport, type RadarReport, type ScanStage } from './radar';
import { UpdateBanner, UpdateSettings, useAppUpdates } from './updates';
import './style.css';

type Profile = { applied?: string; requested?: string; state: string };
type Account = { email: string; access: string; profile: Profile; bound: { limit:number; items:{id:string;name:string;os:string}[] } };
type Connection = { port:number|null; region:string|null; system_proxy?:boolean; system_proxy_supported?:boolean; proxy_error?:string|null; uptime_seconds?:number|null; device_id?:string|null };
type Region = { id:string; name:string };
const tabs = ['Рабочее место','Радар подключения','CLI и Терминал','Устройства и настройки'];
const empty = {port:null,region:null};
type WorkSettings = {close_to_tray:boolean; autostart:boolean};
type ProfileState = 'new' | 'ready' | 'open' | null;
const shellNames = ['PowerShell','CMD','Bash / Zsh'] as const;
const native = isTauri();

function App() {
  const [account,setAccount] = useState<Account|null>(null);
  const [regions,setRegions] = useState<Region[]>([]);
  const [connection,setConnection] = useState<Connection>(empty);
  const [observed,setObserved] = useState<RadarReport|null>(null);
  const [browserReport,setBrowserReport] = useState<BrowserProbeReport|null>(null);
  const [useStun,setUseStun] = useState(false);
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
  const updates = useAppUpdates(native);
  const busy = working || updates.phase === 'downloading' || updates.phase === 'installing';
  const [loading,setLoading] = useState(native);
  const [message,setMessage] = useState('');
  const [installed,setInstalled] = useState<InstalledApps|null>(null);
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
  useEffect(() => {
    if (!native || tab !== 0 || !profileRegion) return;
    let active = true;
    const update = () => { void invoke<ProfileState>('browser_profile_state',{region:profileRegion}).then(value => { if (active) setProfileState(value); }).catch(() => {}); };
    setProfileState(null);
    update();
    const interval = window.setInterval(update, 8000);
    window.addEventListener('focus', update);
    return () => { active = false; window.clearInterval(interval); window.removeEventListener('focus', update); };
  }, [tab,profileRegion]);
  useEffect(() => {
    if (!native || tab !== 3) return;
    void invoke<WorkSettings>('work_settings').then(setSettings).catch(() => setError('Не удалось загрузить параметры работы'));
  }, [tab]);
  useEffect(() => {
    if (!native || tab !== 0) return;
    let active = true;
    let checking = false;
    const refresh = () => {
      if (checking) return;
      checking = true;
      void invoke<InstalledApps>('installed_desktop_apps')
      .then(result => { if (active) setInstalled(result); })
        .catch(e => { if (active) setError(String(e)); }).finally(() => { checking = false; });
    };
    refresh();
    const id = window.setInterval(refresh, 8000);
    window.addEventListener('focus', refresh);
    return () => { active = false; window.clearInterval(id); window.removeEventListener('focus', refresh); };
  }, [tab,connection.port,connection.system_proxy]);
  useEffect(() => {
    if (!native) return;
    invoke<Account>('account').then(setAccount).catch(() => {}).finally(() => setLoading(false));
    invoke<Region[]>('regions').then(setRegions).catch(() => {});
  }, []);
  useEffect(() => {
    if (!native || !account) return;
    const id = window.setInterval(() => {
      invoke<Connection>('tunnel_status').then(setConnection).catch(() => {});
      if (account.profile.state === 'pending') invoke<Account>('account').then(setAccount).catch(() => {});
    }, 2200);
    return () => window.clearInterval(id);
  }, [account]);
  useEffect(() => {
    setOutbound(null);
    setObserved(null);
    setBrowserReport(null);
    if (!native || !connection.port) return;
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
  }, [connection.port, connection.region]);
  async function perform(action: () => Promise<unknown>) {
    if (busy || workLock.current) return;
    workLock.current = true;
    setBusy(true); setError(''); setMessage('');
    try { await action(); } catch(e) { setError(String(e)); } finally { workLock.current = false; setBusy(false); }
  }
  async function ensureRoute() {
    if (!connection.port) setConnection(await invoke<Connection>('connect_tunnel'));
  }
  const open = (destination:string) => perform(async () => {
    await ensureRoute();
    await invoke('launch_browser',{destination});
    setProfileState('open');
  });
  const official = (page:string) => perform(() => invoke('open_official',{page}));
  const launchClient = (client:DesktopClient, restart:boolean) => perform(async () => {
    await ensureRoute();
    setConnection(await invoke<Connection>('launch_desktop_app',{client,restart}));
    setInstalled(await invoke<InstalledApps>('installed_desktop_apps'));
    setMessage('Клиент запущен через рабочий маршрут');
  });
  async function copy(text:string, key = '') {
    try { await navigator.clipboard.writeText(text); setCopied(key); if (!key) setMessage('Скопировано ✓'); }
    catch { setError('Буфер обмена недоступен. Выделите текст вручную.'); }
  }
  const changeSetting = (setting:'autostart'|'tray',enabled:boolean) => perform(async () => {
    await invoke('set_work_setting',{setting,enabled});
    setSettings(await invoke<WorkSettings>('work_settings'));
  });
  async function readRadar() {
    networkRevision.current += 1;
    setRadarStage('start');
    try {
      const result = await invoke<RadarReport>('run_system_radar',{lookupGeo:true,checkDns:true});
      networkRevision.current += 1;
      setObserved(result);
      setOutbound(usableObservation(result.network));
      setRadarStage('complete');
    } catch (error) { setRadarStage(null); throw error; }
  }
  useEffect(() => {
    if (radarStage !== 'complete') return;
    const timer = window.setTimeout(() => setRadarStage(null), 1400);
    return () => window.clearTimeout(timer);
  }, [radarStage]);
  const scan = () => perform(readRadar);
  const scanBrowser = () => perform(async () => {
    setBrowserReport(null);
    if (!observed) await readRadar();
    const report = await invoke<BrowserProbeReport>('run_browser_probe', { stun: useStun });
    setBrowserReport(report);
  });
  const connectRadar = () => perform(async () => {
    if (connection.port) setConnection(await invoke<Connection>('disconnect'));
    setConnection(await invoke<Connection>('connect_tunnel'));
  });
  const repairRadar = () => perform(async () => {
    if (!profileRegion) return;
    await invoke('repair_browser_profile',{region:profileRegion});
    await readRadar();
    setMessage('Настройки рабочего профиля обновлены');
  });
  const routeRadarClient = (client:DesktopClient) => perform(async () => {
    setConnection(await invoke<Connection>('launch_desktop_app',{client,restart:true}));
    await readRadar();
  });
  const endpoint = connection.port ? '127.0.0.1:' + connection.port : '';
  const proxy = 'http://' + endpoint;
  const socks = 'socks5h://' + endpoint;
  const variables = [['HTTP_PROXY', proxy], ['HTTPS_PROXY', proxy], ['ALL_PROXY', socks]];
  const commands = [
    variables.map(([key,value]) => "$env:" + key + " = '" + value + "'").join('\n'),
    variables.map(([key,value]) => 'set "' + key + '=' + value + '"').join('\n'),
    variables.map(([key,value]) => "export " + key + "='" + value + "'").join('\n'),
  ];
  const regionName = regions.find(region=>region.id===profileRegion)?.name || profileRegion?.toUpperCase() || 'Регион не выбран';
  const routeReady = account?.access === 'active' && account.profile.state === 'applied';
  const activeTime = connection.uptime_seconds ?? 0;
  const duration = Math.floor(activeTime / 60) + ' мин ' + (activeTime % 60) + ' с';
  const changeTab = (index:number) => { setTab(index); setError(''); setMessage(''); };
  return !account ? <main className="sign-screen"><section className="sign-card panel">
    <Brand/><h1>Вход в Workspace</h1><p>Подключите это устройство к своему рабочему пространству.</p>
    {!native && <p role="status">Веб-предпросмотр. Для входа откройте приложение Tauri.</p>}
    {loading ? <p role="status">Проверяем сохранённую сессию…</p> : <form onSubmit={e=>{e.preventDefault();const data=new FormData(e.currentTarget);void perform(async()=>{
      setAccount(await invoke<Account>('sign_in',{email:data.get('email'),password:data.get('password')}));
    });}}>
      <label>Email<input name="email" type="email" autoComplete="username" required/></label>
      <label>Пароль<input name="password" type="password" autoComplete="current-password" required/></label>
      <button className="primary" disabled={busy || !native}>{busy?'Входим…':'Войти'}</button>
    </form>}
    {error && <p className="error" role="alert">{error}</p>}
  </section></main> : <div className="shell" data-contrast={contrast}>
    <aside><Brand/><nav aria-label="Разделы">{tabs.map((label,i)=><button key={label} aria-current={i===tab?'page':undefined} onClick={()=>changeTab(i)}>
      <Icon name={['grid','radar','terminal','settings'][i]}/><span>{label}</span>
      {i===3 && updates.available && <i className="nav-update" role="img" aria-label="Доступно обновление"/>}
    </button>)}</nav>
      <div className="account"><span className="avatar" aria-hidden="true">{account.email.slice(0,1).toUpperCase()}</span>
        <div className="account-text"><strong title={account.email}>{account.email}</strong><small>{updates.version ? 'v'+updates.version : 'Workspace Desktop'}</small></div>
        <button className="icon-button" title="Выйти" aria-label="Выйти" onClick={()=>void perform(async()=>{await invoke('sign_out');setConnection(empty);setAccount(null);})} disabled={busy}><Icon name="logout"/></button>
      </div>
    </aside>
    <div className="body">
      <header className="status"><span className="pill" data-online={!!connection.port}><i/>{connection.port?'Маршрут активен':'Отключено'}</span>
        <label className="region-label"><Icon name="pin"/><select aria-label="Регион" disabled={busy || account.access!=='active'} value={account.profile.requested || account.profile.applied || ''} onChange={e=>{
          const region=e.target.value; void perform(async()=>{const result=await invoke<Account>('select_region',{region});setConnection(empty);setAccount(result);setObserved(null);});
        }}><option value="" disabled>Выберите регион</option>{regions.map(r=><option key={r.id} value={r.id}>{r.name}</option>)}</select></label>
        {connection.port && <button className="pill ip-status" title="Открыть Радар подключения" onClick={()=>changeTab(1)}>{outbound ? outbound.ip + ' · ' + outbound.latency_ms + ' мс' : 'Внешний IP проверяется'}<Icon name="arrow"/></button>}
      </header>
      <UpdateBanner updates={updates} busy={busy}/>
      <main>
        <h1>{tabs[tab]}</h1>
        {(error || connection.proxy_error) && <p className="error" role="alert">{error || connection.proxy_error}</p>}
        {message && <p className="feedback" role="status">{message}</p>}
        {account.profile.state==='pending' && <p role="status">Применяем регион. После смены региона заново откройте рабочий браузер.</p>}
        {tab===0 && <>
          <section className="connection panel">
            <div className="route-summary"><div className="route-mark" data-online={!!connection.port}><Icon name="radar"/></div><div>
              <h2>{connection.port ? 'Рабочий маршрут активен · ' + regionName : 'Рабочий маршрут отключён'}</h2>
              <p>{connection.port ? 'Сессия ' + duration + (outbound ? ' · ' + outbound.latency_ms + ' мс' : '') : 'Подключите рабочий маршрут перед запуском приложений.'}</p>
            </div></div>
            <button className="primary" disabled={busy || (!connection.port && !routeReady)} onClick={()=>void perform(async()=>{setConnection(await invoke<Connection>(connection.port?'disconnect':'connect_tunnel'));})}>{busy?'Выполняется…':connection.port?'Отключить':'Подключить'}</button>
          </section>
          <div className="cards">
            <Card title="Изолированный браузер" icon="browser" description={profileState==='open'?'Рабочий профиль открыт':profileState==='ready'?'Рабочий профиль готов':profileState==='new'?'Создадим профиль при запуске':'Отдельное рабочее окно'}>
              <button className="launch-button" disabled={busy || !routeReady} onClick={()=>void open('workspace')}>Открыть браузер</button>
              <div className="quick-links">
                <button disabled={busy || !routeReady} onClick={()=>void open('claude')}>Открыть Claude</button>
                <button disabled={busy || !routeReady} onClick={()=>void open('chatgpt')}>Открыть ChatGPT</button>
              </div>
              <button className="quiet reset-profile" disabled={!profileRegion || busy} onClick={()=>setResetRegion(profileRegion || null)}>Очистить профиль</button>
            </Card>
            {([['claude','Claude'],['chatgpt','ChatGPT']] as const).map(([client,name])=>{
              const app = installed?.[client];
              const label = app ? [app.variant,desktopLabel(app)].filter(Boolean).join(' · ') : installed ? 'Статус недоступен' : 'Проверяем установку…';
              return <Card key={client} title={name + ' Desktop'} icon={client} description={label}>
                {app && !app.installed && <button className="launch-button" disabled={busy} onClick={()=>void official(client)}>Скачать клиент</button>}
                {app?.installed && <button className="launch-button" disabled={busy} onClick={()=>{
                  if (app.can_launch) void launchClient(client,app.running);
                  else setError('Клиент найден, но Windows или macOS не вернула ярлык запуска. Откройте приложение из системного меню и повторите проверку.');
                }}>{app.running?'Перезапустить через маршрут':'Запустить через маршрут'}</button>}
              </Card>;
            })}
          </div>
          {resetRegion && resetRegion === profileRegion && <section className="panel profile-confirm" aria-label="Подтвердить очистку профиля">
            <p>Удалить данные рабочего профиля для {resetRegion.toUpperCase()}? Сначала закройте его окно.</p>
            <div className="actions"><button disabled={busy} onClick={()=>void perform(async()=>{
              await invoke('clear_browser_profile',{region:resetRegion});setResetRegion(null);setProfileState('new');setMessage('Рабочий профиль очищен');
            })}>Подтвердить очистку</button><button disabled={busy} onClick={()=>setResetRegion(null)}>Отмена</button></div>
          </section>}
          <button className="cli-link" onClick={()=>changeTab(2)}><Icon name="terminal"/><span>Терминал, Cursor или Codex CLI</span><strong>Настроить окружение</strong><Icon name="arrow"/></button>
        </>}
        {tab===1 && <Radar
          report={observed} browserReport={browserReport} stun={useStun} setStun={setUseStun} scanBrowser={()=>void scanBrowser()} network={outbound} connected={!!connection.port} busy={busy} stage={radarStage}
          region={regions.find(region=>region.id===profileRegion)?.name || ''}
          scan={()=>void scan()} connect={()=>void connectRadar()} repair={()=>void repairRadar()}
          time={()=>void perform(()=>invoke('open_time_settings'))}
          client={client=>void routeRadarClient(client)} copy={text=>void copy(text)}
        />}
        {tab===2 && <>
          <section className="panel cli-panel">
            <div className="section-heading"><h2>Подключение команд</h2><span className="chip">{connection.port?'Маршрут активен':'Отключено'}</span></div>
            <div className="command-tabs" role="group" aria-label="Оболочка">{shellNames.map((name,index)=><button key={name} aria-pressed={index===shellIndex} onClick={()=>{setShellIndex(index);setCopied('');}}>{name}</button>)}</div>
            {connection.port ? <>
              <dl className="proxy-addresses"><div><dt>HTTP</dt><dd>{proxy}</dd></div><div><dt>SOCKS5</dt><dd>{socks}</dd></div></dl>
              <pre className="command-text">{commands[shellIndex]}</pre>
              <div className="actions"><button onClick={()=>void copy(commands[shellIndex],'cli')}>{copied==='cli'?'Скопировано ✓':'Копировать'}</button>
                <button disabled={busy} onClick={()=>void perform(()=>invoke('launch_terminal'))}>Открыть терминал</button></div>
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
            {connection.system_proxy_supported && <label className="toggle-row"><span>Точечный маршрут для Store-приложений</span><input type="checkbox" role="switch" checked={!!connection.system_proxy} disabled={busy} onChange={e=>{
              const enabled=e.target.checked; void perform(async()=>{ if (enabled) await ensureRoute(); setConnection(await invoke<Connection>('set_system_proxy',{enabled})); });
            }}/></label>}
            <label className="toggle-row"><span>Повышенный контраст</span><input type="checkbox" role="switch" checked={contrast} onChange={e=>{setContrast(e.target.checked);localStorage.setItem('workspace.contrast',e.target.checked?'on':'off');}}/></label>
            <div className="actions"><button onClick={()=>void copy(['Workspace ' + updates.version, 'Регион: ' + regionName, 'Маршрут: ' + (connection.port?'активен':'отключён'), 'Задержка: ' + (outbound ? outbound.latency_ms + ' мс' : 'недоступна'), 'Точечный маршрут Store: ' + (connection.system_proxy?'включён':'выключен')].join('\n'),'log')}>{copied==='log'?'Скопировано ✓':'Скопировать лог'}</button></div>
          </section>
        </div>}
      </main>
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
