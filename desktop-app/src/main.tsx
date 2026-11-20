import React, { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { invoke, isTauri } from '@tauri-apps/api/core';
import { UpdateSettings, useAppUpdates } from './updates';
import './style.css';

type Profile = { applied?: string; requested?: string; state: string };
type Account = { email: string; access: string; profile: Profile; bound: { limit:number; items:{id:string;name:string;os:string}[] } };
type Connection = { port: number | null; region: string | null; system_proxy?:boolean; system_proxy_supported?:boolean; proxy_error?:string|null };
type Region = {id:string; name:string};
type DesktopClient = 'claude' | 'chatgpt';
type DesktopStatus = {installed:boolean; running:boolean; store:boolean; proxy:'arguments'|'system'|'unknown'};
type InstalledApps = Record<DesktopClient, DesktopStatus|null>;
type Observation = {ip:string; latency_ms:number};
type RadarReport = {
  network:Observation|null; network_error:string|null; matched:boolean|null;
  geo:{country:string|null; city:string|null; connection:{isp:string|null; asn:number|null}|null}|null;
  browser:{running:boolean|null; expected_timezone:string; expected_language:string;
    actual:{timezone:string;language:string}|null; launch_language:string|null;
    geolocation_blocked:boolean|null; webrtc_protected:boolean|null};
  dns:{status:'distinct'|'overlap'|'unavailable'; tunnel_resolvers:number; system_resolvers:number}|null;
  devices:{used:number;limit:number;desktop:number;mobile:number;current_pc:boolean|null}|null;
  timezone:string|null; system_proxy:boolean|null; apps:InstalledApps;
  ready:number; total:number; hints:string[];
};
const tabs = ['Рабочее место','Радар подключения','CLI и Терминал','Устройства и настройки'];
const empty = {port:null,region:null};
const native = isTauri();

function App() {
  const [account,setAccount] = useState<Account|null>(null);
  const [regions,setRegions] = useState<Region[]>([]);
  const [connection,setConnection] = useState<Connection>(empty);
  const [observed,setObserved] = useState<RadarReport|null>(null);
  const [outbound,setOutbound] = useState<Observation|null>(null);
  const [lookupGeo,setLookupGeo] = useState(false);
  const [checkDns,setCheckDns] = useState(false);
  const [tab,setTab] = useState(0);
  const [error,setError] = useState('');
  const [working,setBusy] = useState(false);
  const updates = useAppUpdates(native);
  const busy = working || updates.phase === 'downloading' || updates.phase === 'installing';
  const [loading,setLoading] = useState(native);
  const [message,setMessage] = useState('');
  const [installed,setInstalled] = useState<InstalledApps|null>(null);
  const [resetRegion,setResetRegion] = useState<string|null>(null);
  const profileRegion = connection.region || account?.profile.applied;
  useEffect(() => { setResetRegion(null); }, [profileRegion, tab]);
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
    if (!native || !connection.port) return;
    let active = true;
    const refresh = () => invoke<Observation>('observe_tunnel')
      .then(result => { if (active) setOutbound(result); })
      .catch(() => { if (active) setOutbound(null); });
    void refresh();
    const id = window.setInterval(refresh, 45000);
    return () => { active = false; window.clearInterval(id); };
  }, [connection.port, connection.region]);
  async function perform(action: () => Promise<unknown>) {
    if (busy) return;
    setBusy(true); setError(''); setMessage('');
    try { await action(); } catch(e) { setError(String(e)); } finally { setBusy(false); }
  }
  const open = (destination:string) => perform(() => invoke('launch_browser',{destination}));
  const official = (page:string) => perform(() => invoke('open_official',{page}));
  const launchClient = (client:DesktopClient, restart:boolean) => perform(async () => {
    await invoke('launch_desktop_app',{client,restart});
    setInstalled(await invoke<InstalledApps>('installed_desktop_apps'));
  });
  async function copy(text:string) {
    try { await navigator.clipboard.writeText(text); setMessage('Скопировано'); }
    catch { setError('Буфер обмена недоступен. Выделите текст вручную.'); }
  }
  const scan = () => perform(async () => {
    const result = await invoke<RadarReport>('run_system_radar',{lookupGeo,checkDns});
    setObserved(result);
    setOutbound(result.network);
  });
  const proxy = connection.port ? 'http://127.0.0.1:'+connection.port : '';
  const terminal = proxy ? ['export HTTPS_PROXY='+proxy+' HTTP_PROXY='+proxy, "$env:HTTPS_PROXY='"+proxy+"'; $env:HTTP_PROXY='"+proxy+"'"] : [];
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
  </section></main> : <div className="shell">
    <aside><Brand/><nav aria-label="Разделы">{tabs.map((label,i)=><button key={label} aria-current={i===tab?'page':undefined} onClick={()=>{setTab(i);setError('');setMessage('');}}>{label}</button>)}</nav>
      <div className="account"><strong>{account.email}</strong><button onClick={()=>void perform(async()=>{await invoke('sign_out');setConnection(empty);setAccount(null);})} disabled={busy}>Выйти</button></div>
    </aside>
    <div className="body">
      <header className="status"><span className="pill" data-online={!!connection.port}><i/>{connection.port?'Туннель подключён':'Туннель отключён'}</span>
        <label className="region-label">Регион<select aria-label="Регион" disabled={busy || account.access!=='active'} value={account.profile.requested || account.profile.applied || ''} onChange={e=>{
          const region=e.target.value; void perform(async()=>{const result=await invoke<Account>('select_region',{region});setConnection(empty);setAccount(result);setObserved(null);});
        }}><option value="" disabled>Выберите регион</option>{regions.map(r=><option key={r.id} value={r.id}>{r.name}</option>)}</select></label>
        {connection.port && (outbound ? <button className="pill" title="Задержка HTTPS через туннель" onClick={()=>void copy(outbound.ip)}>{outbound.ip} · {outbound.latency_ms} мс</button> : <span className="pill">Внешний IP недоступен</span>)}
      </header>
      {updates.available && tab!==3 && <div className="update-banner" role="status">
        <span>Доступно обновление v{updates.available.version}</span>
        <button onClick={()=>setTab(3)}>Подробнее</button>
      </div>}
      <main>
        <h1>{tabs[tab]}</h1>
        {(error || connection.proxy_error) && <p className="error" role="alert">{error || connection.proxy_error}</p>}
        {message && <p className="feedback" role="status">{message}</p>}
        {account.profile.state==='pending' && <p role="status">Применяем регион. После смены региона заново откройте рабочий браузер.</p>}
        {tab===0 && <><div className="connection panel"><div><h2>Рабочий маршрут</h2><p>{connection.port ? 'Локальный SOCKS5 на 127.0.0.1:'+connection.port : 'Подключите туннель, чтобы открыть рабочие инструменты.'}</p></div>
          <button className="primary" disabled={busy || (!connection.port && (account.access!=='active' || account.profile.state!=='applied'))} onClick={()=>void perform(async()=>{setConnection(await invoke<Connection>(connection.port?'disconnect':'connect_tunnel'));})}>{busy?'Выполняется…':connection.port?'Отключить':'Подключить'}</button></div>
          {connection.system_proxy_supported && <section className="panel proxy-control">
            <label><input type="checkbox" checked={!!connection.system_proxy} disabled={busy || (!connection.port && !connection.system_proxy)} onChange={e=>{
              const enabled=e.target.checked; void perform(async()=>{setConnection(await invoke<Connection>('set_system_proxy',{enabled}));});
            }}/> Системный прокси Windows</label>
            <p>Меняет маршрут приложений, которые используют системные настройки, пока подключён туннель. Нужен для запуска клиентов из Microsoft Store.</p>
          </section>}
          <div className="cards">
            <Card title="Изолированный браузер" description="Отдельное рабочее окно Chrome, Brave или Edge.">
              <button disabled={!connection.port || busy} onClick={()=>void open('workspace')}>Открыть браузер</button>
              <button disabled={!connection.port || busy} onClick={()=>void open('claude')}>Claude</button>
              <button disabled={!connection.port || busy} onClick={()=>void open('chatgpt')}>ChatGPT</button>
              <button disabled={!profileRegion || busy} onClick={()=>setResetRegion(profileRegion || null)}>Очистить профиль</button>
              {resetRegion && resetRegion === profileRegion && <div>
                <p>Удалить данные браузера для {resetRegion.toUpperCase()}? Сначала закройте рабочий браузер этого региона.</p>
                <button disabled={busy} onClick={()=>void perform(async()=>{
                  await invoke('clear_browser_profile',{region:resetRegion});
                  setResetRegion(null);
                  setMessage('Рабочий профиль очищен');
                })}>Подтвердить очистку</button>
                <button disabled={busy} onClick={()=>setResetRegion(null)}>Отмена</button>
              </div>}
            </Card>
            {([['claude', 'Claude'], ['chatgpt', 'ChatGPT']] as const).map(([client, name]) => {
              const status = installed?.[client];
              const description = status ? desktopLabel(status)
                : installed ? 'Статус недоступен' : 'Проверяем установку…';
              return <Card key={client} title={name + ' Desktop'} description={description}>
                {status?.installed && <>
                  <button disabled={busy || !connection.port || (status.store && !connection.system_proxy)}
                    onClick={()=>void launchClient(client,status.running)}>
                    {status.running?'Перезапустить через туннель':'Запустить через туннель'}
                  </button>
                  {status.store && !connection.system_proxy && <p>Для запуска версии Microsoft Store включите системный прокси Windows.</p>}
                </>}
                {status && !status.installed && <button disabled={busy} onClick={()=>void official(client)}>Скачать</button>}
              </Card>;
            })}
            <Card title="CLI и Терминал" description="Подключение рабочих команд к локальному прокси."><button onClick={()=>setTab(2)}>Команды прокси</button></Card>
          </div></>}
        {tab===1 && <section className="panel diagnostics"><p>Проверяем внешний IPv4 через туннель и параметры рабочего профиля.</p>
          <label className="geo-option"><input type="checkbox" checked={lookupGeo} onChange={e=>setLookupGeo(e.target.checked)}/> Запросить страну, город и ASN у ipwho.is</label>
          {lookupGeo && <p>Запрос к ipwho.is идёт напрямую и передаёт внешний IPv4 туннеля.</p>}
          <label className="geo-option"><input type="checkbox" checked={checkDns} onChange={e=>setCheckDns(e.target.checked)}/> Сравнить DNS-резолверы через bash.ws</label>
          {checkDns && <p>Сравниваем тестовые DNS-имена системного маршрута и SOCKS5. Сервис увидит сетевые адреса этих запросов.</p>}
          <button className="primary" onClick={()=>void scan()} disabled={busy || !connection.port}>Запустить диагностику</button>
          {observed && <RadarSummary report={observed}/>}
        </section>}
        {tab===2 && <section className="panel diagnostics">{terminal.length ? terminal.map((command,index)=><div className="command" key={command}><span>{index ? 'PowerShell':'macOS / Bash'}</span><code>{command}</code><button onClick={()=>void copy(command)}>Скопировать</button></div>) : <p>Сначала подключите туннель, чтобы получить команды.</p>}<div className="actions"><button disabled={!connection.port || busy} onClick={()=>void perform(()=>invoke('launch_terminal'))}>Открыть терминал</button><button disabled={!connection.port || busy} onClick={()=>{setTab(1);void scan();}}>Проверить HTTPS через прокси</button></div></section>}
        {tab===3 && <><UpdateSettings updates={updates} busy={busy}/><section className="panel diagnostics"><h2>Привязанные устройства</h2><p>Использовано {account.bound.items.length} из {account.bound.limit}. Новый нативный клиент использует отдельную привязку.</p><ul>{account.bound.items.map(item=><li key={item.id}>{item.name} · {item.os}</li>)}</ul><button disabled={busy} onClick={()=>void official('workspace')}>Открыть веб-кабинет</button></section></>}
      </main>
      <footer>Yousoro Workspace{updates.version && ' · v'+updates.version}</footer>
    </div>
  </div>;
}
function desktopLabel(status:DesktopStatus) {
  if (!status.installed) return 'Не установлен';
  if (!status.running) return 'Установлен';
  if (status.proxy==='arguments') return 'Запущен · с параметрами туннеля';
  if (status.proxy==='system') return 'Запущен · системный прокси направлен на туннель';
  return 'Запущен · маршрут не подтверждён';
}

function RadarSummary({report}:{report:RadarReport}) {
  const {network,geo,browser,apps} = report;
  const unavailable = 'Нет данных';
  const check = (value:boolean|null, yes:string, no:string) => value===null?unavailable:value?yes:no;
  return <>
    <p><strong>Готовность контура {report.total ? Math.round(100*report.ready/report.total) : 0}%</strong> · {report.ready} из {report.total} проверок</p>
    <div className="radar-grid">
      <section>
        <h2>Сеть и выходной шлюз</h2>
        <dl>
          <dt>Внешний IPv4</dt><dd>{network?.ip ?? report.network_error ?? unavailable}</dd>
          <dt>Задержка HTTPS</dt><dd>{network ? network.latency_ms+' мс' : unavailable}</dd>
          <dt>Страна / город</dt><dd>{[geo?.country,geo?.city].filter(Boolean).join(', ') || unavailable}</dd>
          <dt>Провайдер / ASN</dt><dd>{[geo?.connection?.isp,geo?.connection?.asn && 'AS'+geo.connection.asn].filter(Boolean).join(' · ') || unavailable}</dd>
          <dt>Сверка с узлом</dt><dd>{check(report.matched,'Подтверждена','IP отличается')}</dd>
          <dt>Сравнение DNS</dt><dd>{report.dns?.status==='distinct' ? 'В пробе резолверы различаются' : report.dns?.status==='overlap' ? 'Есть общие резолверы' : report.dns ? 'Проверка недоступна' : 'Проверка не запускалась'}
            {report.dns && <><br/>Через SOCKS5: {report.dns.tunnel_resolvers}, системных: {report.dns.system_resolvers}</>}
          </dd>

        </dl>
      </section>
      <section>
        <h2>Изолированный браузер</h2>
        <dl>
          <dt>Рабочий профиль</dt><dd>{check(browser.running,'Открыт','Закрыт')}</dd>
          <dt>Часовой пояс</dt><dd>Ожидаемый {browser.expected_timezone}<br/>Фактический {browser.actual?.timezone ?? unavailable}</dd>
          <dt>Язык</dt><dd>Ожидаемый {browser.expected_language}<br/>Флаг запуска {browser.launch_language ?? unavailable}<br/>В браузере {browser.actual?.language ?? unavailable}</dd>
          <dt>Геолокация</dt><dd>{check(browser.geolocation_blocked,'Блокируется в профиле','Блокировка отключена')}</dd>
          <dt>WebRTC</dt><dd>{check(browser.webrtc_protected,'Ограничение включено','Ограничение отключено')}</dd>
        </dl>
      </section>
      <section>
        <h2>Система и приложения</h2>
        <dl>
          <dt>Часовой пояс ОС</dt><dd>{report.timezone ?? unavailable}</dd>
          <dt>Системный прокси</dt><dd>{check(report.system_proxy,'Указывает на туннель','Туннель не задан')}</dd>
          <dt>Claude Desktop</dt><dd>{apps.claude ? desktopLabel(apps.claude) : unavailable}</dd>
          <dt>ChatGPT Desktop</dt><dd>{apps.chatgpt ? desktopLabel(apps.chatgpt) : unavailable}</dd>
          <dt>Активные слоты аккаунта</dt><dd>{report.devices ? report.devices.used+' из '+report.devices.limit : unavailable}</dd>
          <dt>ПК / телефоны</dt><dd>{report.devices ? report.devices.desktop+' / '+report.devices.mobile : unavailable}</dd>
          <dt>Текущий ПК</dt><dd>{check(report.devices?.current_pc ?? null,'Привязка активна','Привязка отсутствует в списке')}</dd>

        </dl>
      </section>
    </div>
    {!!report.hints.length && <ul>{report.hints.map(hint=><li key={hint}>{hint}</li>)}</ul>}
  </>;
}

function Brand(){return <div className="brand"><img src="/favicon.svg" width="25" height="25" alt=""/><strong>Yousoro</strong> Workspace</div>;}
function Card({title,description,children}:{title:string;description:string;children:React.ReactNode}){return <article className="panel"><h2>{title}</h2><p>{description}</p><div className="actions">{children}</div></article>;}
createRoot(document.getElementById('root')!).render(<App/>);
