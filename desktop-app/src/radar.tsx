export type DesktopClient = 'claude' | 'chatgpt';
export type DesktopStatus = { installed: boolean; can_launch: boolean; variant?: string|null; running: boolean; store: boolean; proxy: 'arguments' | 'system' | 'unknown' };
export type InstalledApps = Record<DesktopClient, DesktopStatus | null>;
export type Observation = { ip: string; latency_ms: number };
export type RadarReport = {
  network: Observation | null; network_error: string | null; matched: boolean | null;
  geo: { country: string | null; country_code?: string | null; city: string | null; connection: { isp: string | null; asn: number | null } | null } | null;
  browser: {
    running: boolean | null; expected_timezone: string; expected_language: string;
    actual: { timezone: string; language: string } | null; launch_language: string | null;
    geolocation_blocked: boolean | null; webrtc_protected: boolean | null;
  };
  dns: { status: 'distinct' | 'overlap' | 'unavailable'; tunnel_resolvers: number; system_resolvers: number } | null;
  devices: { used: number; limit: number; desktop: number; mobile: number; current_pc: boolean | null } | null;
  timezone: string | null; timezone_matches: boolean | null;
  system_proxy: boolean | null; apps: InstalledApps;
  https: { claude: boolean; chatgpt: boolean } | null;
  ready: number; total: number;
};

export function desktopLabel(status: DesktopStatus) {
  if (!status.installed) return 'Не установлен';
  if (!status.running) return 'Установлен';
  if (status.proxy === 'arguments') return 'Запущен через маршрут';
  if (status.proxy === 'system') return 'Запущен · системный прокси включён';
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
  scan: () => void; connect: () => void; repair: () => void; time: () => void;
  client: (client: DesktopClient) => void; copy: (text: string) => void;
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
  const { report, busy, connected, stage } = props;
  const network = connected ? usableObservation(report ? report.network : props.network) : null;
  const location = locationLabel(report?.geo, props.region);
  const browser = report?.browser;
  const service = report?.https;
  const mismatch = report?.timezone_matches === false;
  const browserMismatch = !!browser?.actual && browser.actual.timezone !== browser.expected_timezone;
  const missingProtection = browser?.geolocation_blocked === false || browser?.webrtc_protected === false;
  const inspected = clients.find(key => report?.apps[key]?.running && report.apps[key]?.proxy === 'unknown');
  const reconnect = { label: connected ? 'Переподключить' : 'Подключить маршрут', run:props.connect };
  const timeAction = { label:'Открыть настройки времени', run:props.time };
  const serviceMiss = !!service && (!service.claude || !service.chatgpt);
  const critical = !connected || !!report && (!network || serviceMiss);
  const advisory = !!report && (report.matched !== true || !service || missingProtection || mismatch || browserMismatch || !!inspected);
  const verdict: Tone = critical ? 'error' : !report ? 'idle' : advisory ? 'warning' : 'ok';
  const rows: Row[] = [
    {
      title:'Подключение и IP',
      tone: !connected || report && !network ? 'error' : report && report.matched !== true ? 'warning' : network ? 'ok' : 'idle',
      text: !connected ? 'Рабочий маршрут отключён' : !network ? report ? 'Не удалось получить внешний IP' : 'Проверка внешнего IP ещё не завершена' :
        report?.matched === false ? 'Внешний IP отличается от адреса выбранного узла' : report?.matched === null ?
          'Внешний IP получен. Сверка с выбранным узлом недоступна' :
          'Маршрут активен' + (location ? ' · ' + location : '') + ' (' + network.ip + ')',
      action: !connected || report && (!network || report.matched === false) ? reconnect : undefined,
    },
    {
      title:'Доступность сервисов',
      tone: serviceMiss ? 'error' : service ? 'ok' : 'idle',
      text: !service ? 'Доступность ещё не проверена' : !service.claude && !service.chatgpt ? 'Нет ответа от Claude и ChatGPT' :
        !service.claude ? 'Нет ответа от Claude. ChatGPT отвечает' : !service.chatgpt ? 'Нет ответа от ChatGPT. Claude отвечает' : 'Claude и ChatGPT отвечают',
      action: serviceMiss ? reconnect : undefined,
    },
    {
      title:'Защита браузера',
      tone: missingProtection ? 'warning' : browser ? 'ok' : 'idle',
      text: missingProtection ? 'Параметры защиты рабочего профиля требуют настройки' :
        browser?.running === false ? 'Рабочий браузер готов к запуску' :
        browser?.geolocation_blocked && browser.webrtc_protected ? 'Доступ к геолокации и локальному адресу ограничен' : 'Защита проверяется в рабочем браузере',
      action: missingProtection && !browser?.running ? {label:'Восстановить защиту',run:props.repair} : undefined,
    },
    {
      title:'Время на компьютере',
      tone: mismatch || browserMismatch ? 'warning' : report?.timezone_matches ? 'ok' : 'idle',
      text: mismatch ? (report?.timezone === 'Turkey Standard Time' ? 'Время Windows (Турция) отличается от выбранного региона' : 'Время компьютера отличается от выбранного региона') :
        browserMismatch ? 'Перезапустите рабочий браузер после смены часового пояса' : report?.timezone_matches ? 'Совпадает с выбранным регионом' : 'Сверка времени ещё не выполнена',
      action: mismatch || browserMismatch ? timeAction : undefined,
    },
    {
      title:'Приложения на ПК',
      tone: inspected ? 'warning' : report ? 'ok' : 'idle',
      text: inspected ? clientNames[inspected] + ' открыт. Рабочий маршрут не подтверждён' :
        report ? clients.some(key => report.apps[key]?.running) ? 'Запущенные клиенты используют рабочий маршрут' : 'Лаунчер готов открыть рабочие приложения' : 'Состояние приложений ещё не проверено',
      action: inspected && report?.apps[inspected]?.can_launch ? {label:'Перезапустить через маршрут',run:()=>props.client(inspected)} : undefined,
    },
  ];
  const details: Array<[string,string]> = report ? [
    ['Провайдер / ASN', [report.geo?.connection?.isp, report.geo?.connection?.asn && 'AS' + report.geo.connection.asn].filter(Boolean).join(' · ') || 'Нет данных'],
    ['DNS-проба', report.dns ? (report.dns.status === 'distinct' ? 'Разные резолверы' : report.dns.status === 'overlap' ? 'Есть совпадения' : 'Нет ответа от сервиса проверки') +
      ' · SOCKS5 ' + report.dns.tunnel_resolvers + ' / ОС ' + report.dns.system_resolvers : 'Не запрашивалась'],
    ['WebRTC', browser?.webrtc_protected === true ? 'disable_non_proxied_udp' : browser?.webrtc_protected === false ? 'Ограничение выключено' : 'Нет данных'],
    ['Язык браузера', [browser?.actual?.language || browser?.expected_language, browser?.launch_language && '--lang=' + browser.launch_language].filter(Boolean).join(' · ') || 'Нет данных'],
    ['Часовые пояса', [browser?.expected_timezone, report.timezone, browser?.actual?.timezone].filter(Boolean).join(' / ') || 'Нет данных'],
    ['Слоты устройств', report.devices ? report.devices.used + ' из ' + report.devices.limit + ' · ПК ' + report.devices.desktop + ' · телефон ' + report.devices.mobile : 'Нет данных'],
  ] : [];
  function copyReport() {
    props.copy(['Yousoro Workspace · Радар подключения', headings[verdict], ...rows.map(({title,text}) => title + ': ' + text),
      ...details.map(([name,value]) => name + ': ' + value)].join('\n'));
  }
  const phase = stage ? stages[stage] : null;
  return <div className="radar-dashboard">
    <section className="panel radar-verdict" data-tone={verdict} aria-busy={!!stage && stage !== 'complete'}>
      <div className="radar-intro">
        <span className="radar-symbol" data-tone={verdict} aria-hidden="true">{symbols[verdict]}</span>
        <div><h2>{headings[verdict]}</h2>
          <div className="radar-location">
            {location && <span>{location}</span>}
            {network && <button className="radar-copy-ip" aria-label={'Скопировать IP ' + network.ip} onClick={()=>props.copy(network.ip)}>{network.ip} <span aria-hidden="true">⧉</span></button>}
            {network && <span className="chip">Отклик {network.latency_ms} мс</span>}
          </div>
        </div>
      </div>
      <div className="radar-controls">
        <button className="primary" disabled={busy} onClick={connected ? props.scan : props.connect}>{stage && stage !== 'complete' ? 'Проверяем…' : connected ? report ? 'Проверить снова' : 'Проверить всё' : 'Подключить маршрут'}</button>
        <button disabled={!report || busy} onClick={copyReport}>Отчёт для поддержки</button>
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
    {report && <details className="panel radar-details"><summary>Технические подробности</summary><dl>
      {details.map(([name,value])=><div key={name}><dt>{name}</dt><dd>{value}</dd></div>)}
    </dl></details>}
  </div>;
}
