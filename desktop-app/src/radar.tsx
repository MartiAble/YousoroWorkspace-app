export type DesktopClient = 'claude' | 'chatgpt';
export type DesktopStatus = { installed: boolean; can_launch: boolean; variant?: string|null; running: boolean; store: boolean; proxy: 'arguments' | 'pac' | 'unknown' };
export type InstalledApps = Record<DesktopClient, DesktopStatus | null>;
export type Observation = { ip: string; latency_ms: number };
export type BrowserProbeReport = {
  observed_ip: string | null; timezone: string; offsets: number[]; timezone_matches: boolean | null;
  language: string; languages: string[]; accept_language: string; webdriver: boolean | null;
  geolocation: 'denied' | 'granted' | 'prompt' | 'unknown';
  ice: 'match' | 'mismatch' | 'local' | 'unknown'; stun: boolean;
  local_ip?: 'clear' | 'exposed' | 'unknown'; media?: 'working' | 'denied' | 'not_tested';
};

type ServiceProbe = { state: 'available' | 'restricted' | 'unavailable'; status: number | null };
export type RadarReport = {
  network: Observation | null; network_error: string | null; matched: boolean | null;
  geo: { country: string | null; country_code?: string | null; city: string | null; connection: { isp: string | null; asn: number | null } | null } | null;
  browser: {
    running: boolean | null; expected_timezone: string | null; expected_language: string | null;
    actual: { timezone: string; language: string; timezone_matches: boolean | null } | null; launch_language: string | null;
    geolocation_blocked: boolean | null; webrtc_protected: boolean | null;
  };
  dns: { status: 'distinct' | 'overlap' | 'unavailable'; tunnel_resolvers: number; system_resolvers: number } | null;
  devices: { used: number; limit: number; desktop: number; mobile: number; current_pc: boolean | null } | null;
  timezone: string | null; timezone_matches: boolean | null;
  system_proxy: boolean | null; apps: InstalledApps;
  https: Record<DesktopClient, ServiceProbe> | null;
  ready: number; total: number;
};

export function desktopLabel(status: DesktopStatus) {
  if (!status.installed) return 'Не установлен';
  if (!status.running) return 'Установлен';
  if (status.proxy === 'arguments') return 'Запущен · маршрут задан приложению';
  if (status.proxy === 'pac') return 'Запущен · точечный маршрут включён';
  return 'Запущен · маршрут не подтверждён';
}

export function usableObservation(value: Observation | null): Observation | null {
  if (!value || !/^[0-9]{1,3}([.][0-9]{1,3}){3}$/.test(value.ip) || !Number.isFinite(value.latency_ms) || value.latency_ms < 0) return null;
  const octets = value.ip.split('.').map(Number);
  const [a, b, c] = octets;
  if (octets.some(part => part > 255) || a === 0 || a === 10 || a === 127 || a >= 224 ||
      (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) ||
      (a === 100 && b >= 64 && b <= 127) || (a === 198 && (b === 18 || b === 19)) ||
      (a === 192 && b === 0 && (c === 0 || c === 2)) || (a === 198 && b === 51 && c === 100) ||
      (a === 203 && b === 0 && c === 113)) return null;
  return value;
}

export type ScanStage = 'start' | 'network' | 'services' | 'profile' | 'complete';
type Tone = 'idle' | 'ok' | 'warning' | 'error';
type Action = { label: string; run: () => void };
type Row = { title: string; text: string; tone: Tone; action?: Action };
type Props = {
  report: RadarReport | null; network: Observation | null; region: string; stage: ScanStage | null;
  connected: boolean; busy: boolean;
  browserReport: BrowserProbeReport | null; scanBrowser: () => void; stun: boolean; setStun: (enabled: boolean) => void;
  scan: () => void; connect: () => void; repair: () => void; time: () => void;
  client: (client: DesktopClient, usePac?: boolean) => void; copy: (text: string) => void;
};
const clientNames = { claude: 'Claude', chatgpt: 'ChatGPT' };
const clients = ['claude','chatgpt'] as const;
const stages: Record<ScanStage, [number, string]> = {
  start: [0, 'Начинаем проверку'],
  network: [20, 'Проверяем подключение и выходной IP…'],
  services: [50, 'Проверяем доступность сервисов…'],
  profile: [80, 'Проверяем настройки браузера и приложений…'],
  complete: [100, 'Проверка завершена'],
};
const symbols: Record<Tone, string> = { idle: '·', ok: '✓', warning: '!', error: '×' };
const headings = {
  idle: 'Проверка подключения', ok: 'Всё готово к работе',
  warning: 'Можно работать, есть советы', error: 'Нужно исправить подключение',
};
const regions = new Intl.DisplayNames(['ru'], {type:'region', fallback:'none'});
const cities: Record<string, string> = {
  Berlin: 'Берлин', Frankfurt: 'Франкфурт', 'Frankfurt am Main': 'Франкфурт-на-Майне',
  Amsterdam: 'Амстердам', London: 'Лондон', Istanbul: 'Стамбул', 'New York': 'Нью-Йорк',
  Almaty: 'Алматы', Helsinki: 'Хельсинки', Stockholm: 'Стокгольм', Paris: 'Париж',
};

function locationLabel(geo: RadarReport['geo'] | undefined, region: string) {
  const code = geo?.country_code;
  const country = code && /^[A-Z]{2}$/.test(code) ? regions.of(code) : '';
  const city = geo?.city && (cities[geo.city] ?? geo.city);
  return [country || region || geo?.country, city].filter(Boolean).join(', ');
}

export function Radar(props: Props) {
  const { report, busy, connected, stage, browserReport: measured } = props;
  const network = connected ? usableObservation(report ? report.network : props.network) : null;
  const location = locationLabel(report?.geo, props.region);
  const browser = report?.browser;
  const service = report?.https;
  const mismatch = report?.timezone_matches === false;
  const browserMismatch = (measured?.timezone_matches ?? browser?.actual?.timezone_matches) === false;
  const language = measured?.language || browser?.actual?.language;
  const localeMismatch = !!browser?.expected_language && !!language && language.toLowerCase() !== browser.expected_language.toLowerCase();
  const addressMismatch = !!measured?.observed_ip && !!network && measured.observed_ip !== network.ip;
  const differentWebRtcAddress = measured?.ice === 'mismatch';
  const localExposed = measured?.local_ip === 'exposed';
  const localProtected = browser?.webrtc_protected === true && measured?.local_ip === 'clear';
  const locationAllowed = measured?.geolocation === 'granted';
  const browserIpConfirmed = !!measured?.observed_ip && measured.observed_ip === network?.ip;
  const privacyConfigured = browser?.geolocation_blocked === true && browser?.webrtc_protected === true;
  const missingProtection = browser?.geolocation_blocked === false || browser?.webrtc_protected === false;
  const inspected = clients.find(key => report?.apps[key]?.running && report.apps[key]?.proxy === 'unknown');
  const offerPac = inspected === 'chatgpt' && report?.apps.chatgpt?.store && !report.system_proxy;
  const reconnect = { label: connected ? 'Переподключить' : 'Подключить маршрут', run:props.connect };
  const timeAction = { label:'Открыть настройки времени', run:props.time };
  const limited = service ? clients.filter(key => service[key].state === 'restricted').map(key => clientNames[key]) : [];
  const unreachable = service ? clients.filter(key => service[key].state === 'unavailable').map(key => clientNames[key]) : [];
  const serviceMiss = unreachable.length > 0;
  const critical = !connected || !!report && (!network || serviceMiss || addressMismatch || differentWebRtcAddress);
  const advisory = !!report && (report.matched !== true || !service || missingProtection || localExposed || mismatch || browserMismatch || localeMismatch || locationAllowed || measured?.webdriver === true || limited.length > 0 || !!inspected);
  const verdict: Tone = critical ? 'error' : !report ? 'idle' : advisory ? 'warning' : 'ok';
  const rows: Row[] = [
    {
      title:'Подключение и IP',
      tone: !connected || addressMismatch || report && !network ? 'error' : report && report.matched !== true ? 'warning' : network ? 'ok' : 'idle',
      text: !connected ? 'Рабочий маршрут отключён' : addressMismatch ? 'Адрес рабочего браузера отличается от адреса проверки лаунчера' : !network ? report ? 'Не удалось получить внешний IP' : 'Проверка внешнего IP ещё не завершена' :
        report?.matched === false ? 'Внешний IP отличается от адреса выбранного узла' : report?.matched === null ?
          'Внешний IP получен. Сверка с выбранным узлом недоступна' :
          (browserIpConfirmed ? 'Адрес рабочего браузера подтверждён' : report?.matched ? 'Адрес узла подтверждён для проверки' : 'Получен внешний адрес') + ' (' + network.ip + '). Остальные программы используют свои настройки сети.',
      action: !connected || report && (!network || report.matched === false) ? reconnect : undefined,
    },
    {
      title:'Доступность сервисов',
      tone: serviceMiss ? 'error' : limited.length ? 'warning' : service ? 'ok' : 'idle',
      text: !service ? 'Доступность ещё не проверена' : [
        unreachable.length ? 'Не удалось подключиться: ' + unreachable.join(', ') : '',
        limited.length ? limited.join(', ') + ' ограничил запрос с этого узла. Попробуйте сменить регион' : '',
      ].filter(Boolean).join('. ') || 'Claude и ChatGPT отвечают на проверку',
      action: serviceMiss ? reconnect : undefined,
    },
    {
      title:'Защита сетевого адреса',
      tone: differentWebRtcAddress ? 'error' : missingProtection || localExposed ? 'warning' : localProtected ? 'ok' : 'idle',
      text: differentWebRtcAddress ? 'Браузер сообщил другой публичный адрес. Повторите проверку рабочего маршрута.' :
        localExposed ? 'Браузер сообщил локальный IP. Проверьте настройки рабочего профиля.' :
        localProtected ? 'Утечек локального IP не обнаружено' :
        measured ? 'Проверка локальных адресов не подтвердила защиту.' :
        privacyConfigured ? 'Настроено в профиле • можно проверить в браузере' : 'Проверьте настройки открытого рабочего браузера.',
      action: missingProtection && !browser?.running ? {label:'Восстановить защиту',run:props.repair} : undefined,
    },
    {
      title:'Геолокация и язык',
      tone: locationAllowed || localeMismatch ? 'warning' : measured?.geolocation === 'denied' && !!browser?.expected_language && !localeMismatch ? 'ok' : 'idle',
      text: [
        measured?.geolocation === 'denied' ? 'Запрос координат заблокирован' : locationAllowed ? 'Странице разрешён запрос координат' :
          browser?.geolocation_blocked ? 'Запрет координат настроен в профиле' : 'Доступ к координатам ещё не проверен',
        localeMismatch ? 'язык браузера отличается от настройки узла' : measured && browser?.expected_language ? 'язык совпадает с настройкой узла' : 'язык можно проверить в браузере',
      ].join(', ') + '.',
    },
    {
      title:'Время на компьютере',
      tone: mismatch || browserMismatch ? 'warning' : report?.timezone_matches ? 'ok' : 'idle',
      text: mismatch ? (report?.timezone === 'Turkey Standard Time' ? 'Время Windows (Турция) отличается от выбранного региона' : 'Время компьютера отличается от выбранного региона') :
        browserMismatch ? 'Перезапустите рабочий браузер после смены часового пояса' : report?.timezone_matches ? 'Совпадает с выбранным регионом' : 'Сверка времени ещё не выполнена',
      action: mismatch || browserMismatch ? timeAction : undefined,
    },
    {
      title:'Приложения и изоляция',
      tone: inspected ? 'warning' : report ? 'ok' : 'idle',
      text: offerPac ? 'Для Store-версии ChatGPT можно включить точечный маршрут. Обычные сайты продолжат открываться напрямую.' : inspected ? clientNames[inspected] + ' открыт. Рабочий маршрут не подтверждён' :
        report ? clients.some(key => report.apps[key]?.running) ? 'Рабочий маршрут настроен для запущенных клиентов' : 'Лаунчер направляет только рабочий браузер и выбранные приложения' : 'Состояние приложений ещё не проверено',
      action: inspected && report?.apps[inspected]?.can_launch ? {label:offerPac ? 'Включить и перезапустить' : 'Перезапустить через маршрут',run:()=>props.client(inspected, !!offerPac)} : undefined,
    },
    ...(measured?.media === 'working' || measured?.media === 'denied' ? [{
      title:'Камера и микрофон', tone: (measured.media === 'working' ? 'ok' : 'warning') as Tone,
      text: measured.media === 'working' ? 'Проверены и работают' : 'Браузер или система не разрешили доступ',
    }] : []),
  ];
  const details: Array<[string,string]> = report ? [
    ['IPv4', report.matched === true ? 'Маршрут подтверждён для этой пробы' : report.network ? 'Адрес получен, маршрут не подтверждён' : 'Не проверено'],
    ['IPv6', measured?.observed_ip?.includes(':') ? 'Браузер сообщил IPv6: ' + measured.observed_ip : 'Не проверено отдельным адресом'],
    ['Маршрут Store', report.system_proxy === true ? 'Точечный PAC включён' : 'PAC выключен'],
    ['Accept-Language', measured?.accept_language || 'Не проверено'],
    ['Языки браузера', measured?.languages.join(', ') || 'Не проверено'],
    ['Смещения браузера, мин. (сейчас / январь / июль)', measured?.offsets.join(' / ') || 'Не проверено'],
    ['Автоматизация', measured?.webdriver === false ? 'Браузер не сообщает об автоматизации' : measured?.webdriver === true ? 'Браузер сообщает об автоматизации' : 'Не проверено'],
    ['HTTPS', service ? clients.map(key => clientNames[key] + ' · ' + (service[key].status ?? 'нет HTTP-ответа')).join(' / ') : 'Не проверено'],
    ['Провайдер / ASN', [report.geo?.connection?.isp, report.geo?.connection?.asn && 'AS' + report.geo.connection.asn].filter(Boolean).join(' · ') || 'Нет данных'],
    ['DNS-проба', report.dns ? (report.dns.status === 'distinct' ? 'Разные резолверы в этой пробе' : report.dns.status === 'overlap' ? 'Есть совпадения' : 'Не проверено: нет ответа от сервиса сравнения') +
      ' · SOCKS5 ' + report.dns.tunnel_resolvers + ' / ОС ' + report.dns.system_resolvers : 'Не запрашивалась'],
    ['WebRTC', measured ? measured.ice + (measured.stun ? ' · внешняя проба' : ' · внешний STUN не запускался') : browser?.webrtc_protected === true ? 'disable_non_proxied_udp' : browser?.webrtc_protected === false ? 'Ограничение выключено' : 'Нет данных'],
    ['Язык браузера', [measured?.language || browser?.actual?.language || browser?.expected_language, browser?.launch_language && '--lang=' + browser.launch_language].filter(Boolean).join(' · ') || 'Нет данных'],
    ['Часовые пояса', [browser?.expected_timezone, report.timezone, measured?.timezone || browser?.actual?.timezone].filter(Boolean).join(' / ') || 'Нет данных'],
    ['Слоты устройств', report.devices ? report.devices.used + ' из ' + report.devices.limit + ' · ПК ' + report.devices.desktop + ' · телефон ' + report.devices.mobile : 'Нет данных'],
  ] : [];
  function copyReport() {
    props.copy(['Yousoro Workspace · Радар подключения', headings[verdict], ...rows.map(({title,text}) => title + ': ' + text),
      ...details.map(([name,value]) => name + ': ' + value)].join('\n'));
  }
  const phase = stage ? stages[stage] : null;
  return <div className="radar-dashboard">
    <section className="panel radar-verdict" data-tone={verdict} data-confirmed={!!measured} aria-busy={!!stage && stage !== 'complete'}>
      <div className="radar-intro">
        <span className="radar-symbol" data-tone={verdict} aria-hidden="true">{symbols[verdict]}</span>
        <div><h2>{headings[verdict]}</h2>
          <div className="radar-location">
            {location && <span>{location}</span>}
            {measured && <span className="chip">Подтверждено в браузере</span>}
            {network && <button className="radar-copy-ip" aria-label={'Скопировать IP ' + network.ip} onClick={()=>props.copy(network.ip)}>{network.ip} <span aria-hidden="true">⧉</span></button>}
            {network && <span className="chip">Отклик {network.latency_ms} мс</span>}
          </div>
        </div>
      </div>
      <div className="radar-controls">
        <button className="primary" disabled={busy} onClick={connected ? props.scan : props.connect}>{stage && stage !== 'complete' ? 'Проверяем…' : connected ? report ? 'Проверить снова' : 'Проверить всё' : 'Подключить маршрут'}</button>
        <button disabled={!connected || busy} onClick={props.scanBrowser}>Проверить в браузере</button>
        <button className="radar-support" disabled={!report || busy} onClick={copyReport}>Отчёт для поддержки</button>
      </div>
      {phase && <div className="radar-progress" role="status">
        <div className="radar-track" data-percent={phase[0]} role="progressbar" aria-label="Ход проверки подключения" aria-valuemin={0} aria-valuemax={100} aria-valuenow={phase[0]}><span/></div>
        <p>{phase[0]}% — {phase[1]}</p>
      </div>}
    </section>
    <ul className="panel radar-checks" aria-label="Результаты проверки">
      {rows.map(row=><li key={row.title}>
        <span className="radar-symbol" data-tone={row.tone} aria-label={{idle:'Ожидание',ok:'Готово',warning:'Совет',error:'Ошибка'}[row.tone]} role="img">{symbols[row.tone]}</span>
        <div><h3>{row.title}</h3><p>{row.text}</p></div>
        {row.action && <button disabled={busy} onClick={row.action.run}>{row.action.label}</button>}
      </li>)}
    </ul>
    {(report || connected) && <details className="panel radar-details"><summary>Технические подробности</summary>
      <label className="radar-stun"><input type="checkbox" checked={props.stun} disabled={busy} onChange={event=>props.setStun(event.target.checked)} /> Проверить внешний адрес для видеосвязи (STUN Cloudflare увидит ваш сетевой адрес)</label><dl>
      {details.map(([name,value])=><div key={name}><dt>{name}</dt><dd>{value}</dd></div>)}
    </dl></details>}
  </div>;
}
