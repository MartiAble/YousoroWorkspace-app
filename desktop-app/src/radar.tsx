import React from 'react';

export type DesktopClient = 'claude' | 'chatgpt';
export type DesktopStatus = { installed: boolean; can_launch: boolean; variant?: string|null; running: boolean; store: boolean; proxy: 'arguments' | 'system' | 'unknown' };
export type InstalledApps = Record<DesktopClient, DesktopStatus | null>;
export type Observation = { ip: string; latency_ms: number };
export type RadarReport = {
  network: Observation | null; network_error: string | null; matched: boolean | null;
  geo: { country: string | null; city: string | null; connection: { isp: string | null; asn: number | null } | null } | null;
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

type Tone = 'ok' | 'warning' | 'error';
type Action = { label: string; run: () => void };
type RadarCard = { title: string; tone: Tone; rows: Array<[string, string]>; action?: Action };
type ScanStage = 'network' | 'profile' | 'devices';
type Props = {
  report: RadarReport | null; network: Observation | null; region: string; stage: ScanStage | null;
  connected: boolean; busy: boolean; windows: boolean;
  scan: () => void; connect: () => void; repair: () => void; time: () => void; phone: () => void;
  browser: () => void; proxy: () => void; client: (client: DesktopClient) => void;
  copy: (text: string) => void;
};
const unavailable = 'Нет данных';
const status = (value: boolean | null | undefined, ok: string, fail: string) => value == null ? unavailable : value ? ok : fail;
const names = { claude: 'Claude Desktop', chatgpt: 'ChatGPT Desktop' };
const clients = Object.keys(names) as DesktopClient[];
const labels = { ok: 'OK', warning: 'Внимание', error: 'Ошибка' };
const phases: Array<[ScanStage, string]> = [['network', 'Маршрут и HTTPS'], ['profile', 'Браузер и DNS'], ['devices', 'Приложения и устройства']];

function RadarTile({ card, busy }: { card: RadarCard; busy: boolean }) {
  return <section className="panel radar-tile">
    <div className="radar-tile-head"><h2>{card.title}</h2><span className="radar-badge" data-tone={card.tone}>{labels[card.tone]}</span></div>
    <dl>{card.rows.map(([label, value]) => <React.Fragment key={label}><dt>{label}</dt><dd>{value}</dd></React.Fragment>)}</dl>
    {card.action && <button className="radar-action" disabled={busy} onClick={card.action.run}>{card.action.label}</button>}
  </section>;
}

export function Radar(props: Props) {
  const { report, busy, connected, stage } = props;
  const network = usableObservation(report ? report.network : props.network);
  const passed = report ? Math.max(0, Math.min(report.ready, network ? report.total : report.total - 2)) : 0;
  const score = report?.total ? Math.round(100 * passed / report.total) : 0;
  const scoreTone = !report ? 'idle' : score === 100 ? 'ok' : score >= 70 ? 'warning' : 'error';
  const headline = !report ? 'Проверка среды' : score === 100 ? 'Контур чист, можно работать' : score >= 70 ? 'Есть рекомендации' : 'Требуется действие';
  const latencyTone = !network ? 'warning' : network.latency_ms < 250 ? 'ok' : network.latency_ms <= 600 ? 'warning' : 'error';
  const location = [report?.geo?.country, report?.geo?.city].filter(Boolean).join(', ') || props.region;
  const browser = report?.browser;
  const reconnect = { label: connected ? 'Переподключить туннель' : 'Подключить туннель', run: props.connect };
  const repair = { label: 'Починить настройки профиля', run: props.repair };
  const openBrowser = { label: 'Открыть рабочий браузер', run: props.browser };
  const time = { label: 'Открыть настройки времени ОС', run: props.time };
  const phone = { label: 'Открыть проверку смартфона', run: props.phone };
  const retry = { label: 'Повторить проверку', run: props.scan };
  const enableProxy = { label: 'Включить системный прокси', run: props.proxy };
  const matched = network ? report?.matched : null;
  const routeIssue = !!report && (!network || matched !== true);
  const profileIssue = !!report && (browser?.geolocation_blocked !== true || browser?.webrtc_protected !== true);
  const inspectedClient = clients.find(key => {
    const app = report?.apps[key];
    return app?.running && app.proxy === 'unknown';
  });
  const clientAction = inspectedClient ? (report?.apps[inspectedClient]?.store && !report?.system_proxy
    ? enableProxy : { label: 'Перезапустить через маршрут', run: () => props.client(inspectedClient) }) : undefined;
  const systemMismatch = props.windows && report?.timezone_matches === false;
  const browserTimezoneMismatch = !!browser?.actual && browser.actual.timezone !== browser.expected_timezone;
  const browserMismatch = !!browser?.actual && (browserTimezoneMismatch ||
    browser.actual.language.toLowerCase() !== browser.expected_language.toLowerCase());
  const https = report?.https;
  const httpsIssue = !!https && (!https.claude || !https.chatgpt);
  const dns = report?.dns;
  const dnsText = dns?.status === 'distinct' ? 'Резолверы различаются' : dns?.status === 'overlap' ? 'Есть общие резолверы' : dns ? 'Проба недоступна' : 'Ожидает проверки';
  const cards: RadarCard[] = [
    {
      title: 'Маршрут и выходной узел',
      tone: report && (!network || matched === false) ? 'error' : matched === true ? 'ok' : 'warning',
      rows: [
        ['Внешний IPv4', network?.ip || (report?.network_error ? 'Публичный IPv4 недоступен' : unavailable)],
        ['Страна и город', location || unavailable],
        ['Провайдер / ASN', [report?.geo?.connection?.isp, report?.geo?.connection?.asn && 'AS' + report.geo.connection.asn].filter(Boolean).join(' · ') || unavailable],
        ['Сверка с узлом', status(matched, 'Подтверждено', 'Адрес отличается от узла')],
      ],
      action: routeIssue || !connected ? reconnect : undefined,
    },
    {
      title: 'Чистота сети',
      tone: httpsIssue ? 'error' : report && !profileIssue && dns?.status === 'distinct' && https ? 'ok' : 'warning',
      rows: [
        ['DNS', dnsText + (dns ? ' · SOCKS5 ' + dns.tunnel_resolvers + ' / ОС ' + dns.system_resolvers : '')],
        ['WebRTC', status(browser?.webrtc_protected, 'Ограничен · disable_non_proxied_udp', 'Ограничение выключено')],
        ['Геолокация', status(browser?.geolocation_blocked, 'Заблокирована в профиле', 'Блокировка выключена')],
        ['HTTPS через туннель', https ? 'Claude ' + (https.claude ? '✓' : '—') + ' · ChatGPT ' + (https.chatgpt ? '✓' : '—') : unavailable],
      ],
      action: profileIssue ? repair : httpsIssue ? reconnect : undefined,
    },
    {
      title: 'Среда и локализация',
      tone: systemMismatch || browserMismatch || !browser?.actual ? 'warning' : 'ok',
      rows: [
        ['Часовой пояс узла', browser?.expected_timezone || unavailable],
        ['Часовой пояс ОС', report?.timezone || unavailable],
        ['Рабочий браузер', browser?.actual?.timezone || unavailable],
        ['Язык / флаг запуска', [browser?.actual?.language || browser?.expected_language, browser?.launch_language && '--lang=' + browser.launch_language].filter(Boolean).join(' · ') || unavailable],
        ['Системный прокси', props.windows ? status(report?.system_proxy, 'Указывает на туннель', 'Выключен') : 'Не применяется'],
      ],
      action: systemMismatch ? time : undefined,
    },
    {
      title: 'Приложения и устройства',
      tone: report?.devices?.current_pc === false ? 'error' : report?.devices?.current_pc && report.devices.mobile && browser?.running && !clientAction ? 'ok' : 'warning',
      rows: [
        ['Рабочий браузер', status(browser?.running, 'Открыт', 'Закрыт')],
        ...clients.map((key): [string, string] => {
          const app = report?.apps[key];
          return [names[key], app ? desktopLabel(app) : unavailable];
        }),
        ['Слоты аккаунта', report?.devices ? report.devices.used + ' из ' + report.devices.limit + ' · ПК ' + report.devices.desktop + ' · телефон ' + report.devices.mobile : unavailable],
        ['Текущий ПК', status(report?.devices?.current_pc, 'Привязка активна', 'Привязка отсутствует')],
      ],
      action: clientAction,
    },
  ];
  const recommendations: Array<[string, Action]> = [];
  if (routeIssue || httpsIssue) recommendations.push(['Проверьте рабочий маршрут через выделенный узел.', reconnect]);
  if (profileIssue) recommendations.push([browser?.running ? 'Закройте рабочий браузер перед исправлением профиля.' : 'Восстановите блокировку геолокации и настройки WebRTC.', repair]);
  if (systemMismatch) recommendations.push(['Сверьте часовой пояс Windows с выбранным узлом.', time]);
  if (clientAction) recommendations.push(['Подключите запущенный клиент к рабочему маршруту.', clientAction]);
  if (browser?.running === false) recommendations.push(['Откройте рабочий браузер для проверки языка и часового пояса.', openBrowser]);
  if (browser?.running === true && browserTimezoneMismatch) recommendations.push(['Перезапустите рабочий браузер после смены часового пояса ОС.', time]);
  if (report && !report.devices?.mobile) recommendations.push(['Проверьте профиль на смартфоне.', phone]);
  if (report && dns?.status !== 'distinct') recommendations.push(['Повторите сравнение системных и туннельных DNS-резолверов.', retry]);
  if (report?.devices?.current_pc !== true) recommendations.push(['Повторите сверку текущего ПК с активными слотами.', retry]);

  const reportText = () => {
    const lines = cards.flatMap(card => ['', card.title, ...card.rows.map(([key, value]) => key + ': ' + value)]);
    return ['Yousoro Workspace · Радар подключения', 'Готовность: ' + score + '%',
      'Задержка HTTPS: ' + (network ? network.latency_ms + ' мс' : unavailable), ...lines].join('\n');
  };
  const phase = phases.findIndex(([key]) => key === stage);
  return <div className="radar-dashboard">
    <section className="panel radar-hero" data-tone={scoreTone} aria-busy={!!stage}>
      <div className="radar-health">
        <div className="radar-gauge" aria-label={report ? 'Готовность ' + score + '%' : 'Проверка не запускалась'}>
          <svg viewBox="0 0 80 80" aria-hidden="true"><circle cx="40" cy="40" r="34" pathLength="100"/><circle className="radar-gauge-fill" cx="40" cy="40" r="34" pathLength="100" strokeDasharray={score + ' 100'}/></svg>
          <strong>{report ? score + '%' : '—'}</strong>
        </div>
        <div><small>Готовность контура</small><h2>{headline}</h2>{report && <small>{passed} из {report.total} проверок</small>}</div>
      </div>
      <div className="radar-endpoint">
        <small>{location || 'Выходной узел'}</small>
        {network ? <button className="radar-ip" aria-label={'Скопировать IPv4 ' + network.ip} onClick={() => props.copy(network.ip)}>{network.ip}<span aria-hidden="true">⧉</span></button> : <strong>IPv4 недоступен</strong>}
        <span className="radar-badge" data-tone={latencyTone}>{network ? network.latency_ms + ' мс' : 'Задержка недоступна'}</span>
      </div>
      <div className="radar-hero-actions">
        <button className="primary" disabled={busy} onClick={connected ? props.scan : props.connect}>{stage ? 'Проверяем…' : connected ? 'Проверить всё' : 'Подключить туннель'}</button>
        <button disabled={!report || !!stage} onClick={() => props.copy(reportText())}>Отчёт для поддержки</button>
      </div>
      {stage && <ol className="radar-phases" aria-label="Ход проверки">{phases.map(([key, label], index) =>
        <li key={key} data-done={index < phase} aria-current={key === stage ? 'step' : undefined}>{label}</li>)}</ol>}
    </section>
    <div className="radar-grid">{cards.map(card => <RadarTile key={card.title} card={card} busy={busy}/>)}</div>
    {report && score < 100 && <section className="panel radar-recommendations"><h2>Что улучшить</h2><ul>
      {(recommendations.length ? recommendations : [['Уточните результаты повторной проверкой.', retry] as [string, Action]]).slice(0, 3).map(([label, action]) => <li key={label}><span>{label}</span><button disabled={busy} onClick={action.run}>{action.label}</button></li>)}
    </ul></section>}
    <details className="radar-notes"><summary>Как проходит проверка</summary><p>Для GeoIP ipwho.is получает внешний IP узла. DNS-проба сравнивает резолверы через bash.ws. HTTPS-проверка измеряет доступность сервиса по рабочему маршруту.</p></details>
  </div>;
}
