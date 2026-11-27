import { sameTimezone, type RadarSummary } from './dedicated';
export type DesktopClient = 'claude' | 'chatgpt' | 'cursor';
export type DesktopStatus = { installed: boolean; can_launch: boolean; variant?: string|null; running: boolean; unprotected?: boolean; store: boolean; proxy: 'arguments' | 'pac' | 'unknown' };
export type InstalledApps = Record<DesktopClient, DesktopStatus | null>;
export type Observation = { ip: string; latency_ms: number };
type MediaStatus = 'working' | 'denied' | 'not_found' | 'not_tested';
type ProbeStatus = 'confirmed' | 'unmeasured' | 'disabled' | 'mismatch';
const probeText: Record<ProbeStatus,string> = {
  confirmed: 'Подтверждено для этой пробы',
  unmeasured: 'Не измерено',
  disabled: 'Отключено',
  mismatch: 'Измерено: адрес отличается от адреса узла',
};
const mediaText: Record<MediaStatus,string> = {
  working: 'Работает', denied: 'Доступ запрещён', not_found: 'Устройство не найдено', not_tested: 'Не проверено',
};

export type BrowserProbeReport = {
  observed_ip: string | null; dns?: "tunnel" | "system_overlap" | "unmeasured"; ipv6?: "reachable" | "unmeasured"; ipv6_probe_available?: boolean; timezone: string; offsets: number[]; timezone_matches: boolean | null;
  language: string; languages: string[]; accept_language: string; webdriver: boolean | null;
  geolocation: 'denied' | 'granted' | 'prompt' | 'unknown';
  ice: 'match' | 'mismatch' | 'local' | 'unknown'; stun: boolean;
  camera?: MediaStatus; microphone?: MediaStatus;
  upload?: { status: string; received_bytes: number; duration_ms: number; mbps: number | null };
  local_ip?: 'clear' | 'exposed' | 'unknown'; media?: 'working' | 'denied' | 'not_tested';
};

type ServiceProbe = { state: 'available' | 'restricted' | 'unavailable'; status: number | null };
export type RadarReport = {
  platform?: string; probes?: Record<"ipv4" | "ipv6" | "dns", ProbeStatus> & { udp?: "blocked" | "allowed" | "unmeasured" };
  network: Observation | null; network_error: string | null; matched: boolean | null;
  browser: {
    running: boolean | null; expected_timezone: string | null; expected_language: string | null;
    actual: { timezone: string; language: string; languages?: string[]; language_matches?: boolean | null; timezone_matches: boolean | null } | null; launch_language: string | null;
    geolocation_blocked: boolean | null; webrtc_protected: boolean | null; quic_disabled?: boolean | null;
  };
  dns: { status: 'distinct' | 'overlap' | 'unavailable'; tunnel_resolvers: number; system_resolvers: number } | null;
  devices: { used: number; limit: number; desktop: number; mobile: number; current_pc: boolean | null } | null;
  timezone: string | null; timezone_matches: boolean | null;
  system_proxy: boolean | null; apps: InstalledApps;
  https: Record<"claude" | "chatgpt", ServiceProbe> | null;
  ready: number; total: number;
};

export function desktopLabel(status: DesktopStatus) {
  if (!status.installed) return 'Не установлен';
  if (!status.running) return 'Установлен';
  if (status.unprotected) return 'Запущен · прокси не подтверждён';
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
export type SupportSignal = "ok" | "warning" | "error" | null;
type Tone = 'idle' | 'ok' | 'warning' | 'error';
type Action = { label: string; run: () => void };
type Row = { title: string; text: string; tone: Tone; action?: Action; hint?: string; leak?: boolean; configured?: boolean };
type Props = {
  summary: RadarSummary|null; english: boolean; refreshPass?: () => void;
  report: RadarReport | null; network: Observation | null; region: string; stage: ScanStage | null;
  connected: boolean; busy: boolean; scanPaused: boolean;
  engine: string; lastScan: Date | null; protectedByTun: boolean; openPhone: () => void;
  browserReport: BrowserProbeReport | null; scanBrowser: () => void; stun: boolean; setStun: (enabled: boolean) => void;
  checkDns: boolean; setCheckDns: (enabled: boolean) => void;
  scan: () => void; connect: () => void; repair: () => void; time: () => void;
  client: (client: DesktopClient, usePac?: boolean) => void; copy: (text: string) => void;
};
const clientNames = { claude: 'Claude', chatgpt: 'ChatGPT', cursor: 'Cursor' };
const clients = ['claude','chatgpt'] as const;
const stages: Record<ScanStage, [number, string]> = {
  start: [0, 'Начинаем проверку'],
  network: [20, 'Проверяем подключение и выходной IP…'],
  services: [50, 'Проверяем доступность сервисов…'],
  profile: [80, 'Проверяем настройки браузера и приложений…'],
  complete: [100, 'Проверка завершена'],
};
const symbols: Record<Tone, string> = { idle: '—', ok: '✓', warning: '!', error: '×' };
const statusText: Record<Tone, string> = { idle: 'Не проверено', ok: 'OK', warning: 'Внимание', error: 'Проблема' };
const regions = new Intl.DisplayNames(['ru'], {type:'region', fallback:'none'});
const cities: Record<string, string> = {
  Berlin: 'Берлин', Frankfurt: 'Франкфурт', 'Frankfurt am Main': 'Франкфурт-на-Майне',
  Amsterdam: 'Амстердам', London: 'Лондон', Istanbul: 'Стамбул', 'New York': 'Нью-Йорк',
  Almaty: 'Алматы', Helsinki: 'Хельсинки', Stockholm: 'Стокгольм', Paris: 'Париж',
};

function locationLabel(geo: {country_code?:string|null; country?:string|null; city?:string|null} | null | undefined, region: string) {
  const code = geo?.country_code;
  const country = code && /^[A-Z]{2}$/.test(code) ? regions.of(code) : '';
  const city = geo?.city && (cities[geo.city] ?? geo.city);
  return [country || region || geo?.country, city].filter(Boolean).join(', ');
}

export function radarModel(props: Props) {
  const { report, connected, browserReport: measured } = props;
  const network = connected ? usableObservation(report ? report.network : props.network) : null;
  const summary = props.summary;
  const quality = summary?.diagnostics;
  const parity = summary?.device_parity;
  const location = summary ? locationLabel({country_code:summary.location.country_code ?? undefined, city:summary.location.city ?? undefined}, props.region) : props.region;
  const networkType = {mobile:"Мобильная сеть", residential:"Домашняя сеть", isp:"Интернет-провайдер", hosting:"Дата-центр"}[quality?.network_type ?? ""];
  const browser = report?.browser;
  const service = report?.https;
  const expectedTimezone = summary?.environment?.timezone || summary?.location.timezone || (summary?.mode !== "DEDICATED_ACTIVE" ? report?.browser.expected_timezone : null);
  const timezoneMatch = sameTimezone(Intl.DateTimeFormat().resolvedOptions().timeZone, expectedTimezone);
  const browserTimezoneMatch = sameTimezone(measured?.timezone || browser?.actual?.timezone, expectedTimezone);
  const browserMismatch = browserTimezoneMatch === false;
  const browserTimezoneConfirmed = browserTimezoneMatch === true && (measured?.timezone_matches ?? browser?.actual?.timezone_matches) === true;
  const mismatch = timezoneMatch === false && !browserTimezoneConfirmed;
  const language = measured?.language || browser?.actual?.language || browser?.launch_language;
  const desiredLanguage = summary?.environment?.locale || browser?.expected_language || (props.english ? "en-US" : null);
  const measuredLanguages = measured?.languages ?? browser?.actual?.languages ?? [];
  const targetLocale = desiredLanguage?.toLowerCase();
  const localeMatch = targetLocale && measuredLanguages.length ?
    measuredLanguages[0]?.toLowerCase() === targetLocale && measuredLanguages.every(language => {
      const value = language.toLowerCase();
      return !/^ru(?:-|$)/.test(value) && [targetLocale, targetLocale.split("-")[0]].includes(value);
    }) : null;
  const localeMismatch = localeMatch === false;
  const addressMismatch = !!measured?.observed_ip && !!network && measured.observed_ip !== network.ip;
  const differentWebRtcAddress = measured?.ice === 'mismatch';
  const localExposed = measured?.local_ip === 'exposed';
  const localProtected = browser?.webrtc_protected === true && measured?.local_ip === 'clear';
  const locationAllowed = measured?.geolocation === 'granted';
  const browserIpConfirmed = !!measured?.observed_ip && measured.observed_ip === network?.ip;
  const privacyConfigured = browser?.geolocation_blocked === true && browser?.webrtc_protected === true;
  const missingProtection = browser?.geolocation_blocked === false || browser?.webrtc_protected === false;
  const inspected = !props.protectedByTun && clients.find(key => report?.apps[key]?.running && report.apps[key]?.unprotected);
  const offerPac = inspected === 'chatgpt' && report?.apps.chatgpt?.store && !report.system_proxy;
  const reconnect = { label: connected ? 'Переподключить' : 'Подключить маршрут', run:props.connect };
  const timeAction = { label:'Открыть настройки времени ОС', run:props.time };
  const limited = service ? clients.filter(key => service[key].state === 'restricted').map(key => clientNames[key]) : [];
  const unreachable = service ? clients.filter(key => service[key].state === 'unavailable').map(key => clientNames[key]) : [];
  const serviceMiss = unreachable.length > 0;
  const environmentOk = localeMatch === true && browserTimezoneConfirmed;
  const udp = report?.probes?.udp;
  const ipMismatch = report?.matched === false || addressMismatch;
  const regionMismatch = quality?.geo_consistent === false;
  const ipv6Leak = measured?.ipv6 === 'reachable';
  const ipv6Configured = connected && props.engine !== 'Выключен' && !ipv6Leak && measured?.ipv6_probe_available !== true;
  const ipv6Text = ipv6Leak ? 'Обнаружен публичный IPv6 браузера'
    : ipv6Configured ? props.protectedByTun ? 'Блокировка IPv6/AAAA включена в профиле' : 'Блокировка IPv6 включена в профиле Proxy'
    : measured?.ipv6_probe_available ? 'Внешняя проверка IPv6 не дала результата' : 'IPv6 ещё не проверялся';
  const dnsLeak = measured?.dns === 'system_overlap';
  const dnsOverlap = report?.dns?.status === 'overlap';
  const quicProblem = udp === 'allowed' || browser?.quic_disabled === false;
  const quicOk = udp === 'blocked' && browser?.quic_disabled === true;
  const rtcLeak = differentWebRtcAddress || localExposed;
  const rtcOk = measured?.ice === 'match' && localProtected;
  const rtcOff = browser?.webrtc_protected === false;
  const rtcConfigured = !rtcLeak && !rtcOff && !rtcOk && (browser?.webrtc_protected === true ||
    connected && browser?.running !== true);
  const parityTone: Tone = parity?.status === "matched" ? "ok" :
    parity?.status === "mismatch" || parity?.status === "failed" ? "error" :
    parity?.status === "single_device" ? "warning" : "idle";
  const environmentMismatch = browserMismatch || localeMismatch || measured?.timezone_matches === false || browser?.actual?.timezone_matches === false && !measured;
  const runScan = connected ? 'Нажмите «Проверить снова».' : 'Нажмите «Запустить контур».';
  const runBrowser = 'Нажмите «Проверить в браузере».';
  // Keep the IPC order of support_diagnostics::SIGNALS independent of display order.
  const readiness: Row[] = [
    { title:'Выходной IPv4 и регион',
      tone:ipMismatch || report && !network ? 'error' : regionMismatch ? 'warning' : report?.matched === true ? 'ok' : 'idle',
      leak:addressMismatch,
      text:addressMismatch ? 'Адрес браузера отличается от адреса контура' : ipMismatch ? 'Выход отличается от назначенного шлюза'
        : report && !network ? 'Внешний IPv4 недоступен' : regionMismatch ? 'Публичные базы указывают разные страны'
        : report?.matched === true ? 'IP подтверждён · назначенный шлюз совпадает' : 'Назначенный выход ещё не подтверждён',
      hint:ipMismatch || report && !network ? 'Переподключите контур и повторите проверку.' : regionMismatch ? 'Перепроверьте закреплённый регион.' : runScan,
      action:ipMismatch || report && !network ? reconnect : undefined },
    { title:'Защита IPv6 / AAAA', tone:ipv6Leak ? 'error' : ipv6Configured ? 'ok' : 'idle',
      leak:ipv6Leak, configured:ipv6Configured, text:ipv6Text,
      hint:ipv6Leak ? 'Закройте рабочие вкладки, переподключите контур и повторите пробу.' : undefined },
    { title:'DNS и блок DoH', tone:dnsLeak ? 'error' : measured?.dns === 'tunnel' ? 'ok' : dnsOverlap ? 'warning' : 'idle', leak:dnsLeak,
      text:dnsLeak ? 'Браузер использует системный DNS' : measured?.dns === 'tunnel' ? 'DNS браузера совпал с DNS контура'
        : dnsOverlap ? 'На ПК настроен публичный DNS · проверьте изоляцию DNS в рабочем браузере' : report?.dns?.status === 'distinct' ? 'DNS контура отличается от системного · браузер не проверен' : 'DNS браузера не проверен',
      hint:dnsLeak ? 'Заново откройте рабочий браузер из лаунчера и повторите пробу.'
        : 'Нажмите «Проверить в браузере» для проверки изоляции DNS.' },
    { title:'Блок QUIC (UDP/443)', tone:quicProblem ? 'error' : quicOk ? 'ok' : 'idle',
      text:browser?.quic_disabled === false ? 'В рабочем браузере QUIC включён' : udp === 'allowed' ? 'Локальный прокси принимает UDP'
        : quicOk ? 'Прокси отклонил UDP · QUIC выключен в браузере'
        : udp === 'blocked' ? 'Прокси отклонил UDP · QUIC в браузере не проверен' : 'Блокировка ещё не подтверждена',
      hint:quicProblem ? 'Переподключите контур, заново откройте рабочий браузер и повторите проверку.'
        : 'Откройте рабочий браузер из лаунчера и нажмите «Проверить в браузере».' },
    { title:'Часовой пояс и локаль', tone:environmentMismatch ? 'error' : environmentOk ? 'ok' : 'idle',
      text:environmentMismatch ? 'Часовой пояс или язык отличаются от настроек канала'
        : environmentOk ? [expectedTimezone, desiredLanguage, 'синхронизировано'].filter(Boolean).join(' · ')
        : browser?.running === false && !measured ? 'Рабочий браузер закрыт' : 'Часовой пояс и язык браузера не проверены',
      hint:environmentMismatch ? 'Заново откройте рабочий браузер из лаунчера и повторите проверку.' : runBrowser,
      action:browserMismatch ? timeAction : undefined },
    { title:'Политика WebRTC', tone:rtcLeak || rtcOff ? 'error' : rtcOk || rtcConfigured ? 'ok' : 'idle', leak:rtcLeak, configured:rtcConfigured,
      text:rtcLeak ? 'Обнаружен локальный или другой публичный адрес'
        : rtcOff ? 'Ограничение видеосвязи в профиле выключено' : rtcOk ? 'Адрес видеосвязи совпал с рабочим выходом'
        : rtcConfigured ? 'Рабочий Chromium запускается с ограничением прямого UDP. Сверьте адрес кнопкой «Проверить в браузере».' : 'Откройте рабочий Chromium из лаунчера для проверки.',
      hint:rtcLeak || rtcOff ? 'Закройте рабочие вкладки, восстановите профиль и повторите проверку.'
        : 'Нажмите «Проверить в браузере», чтобы сверить адрес видеосвязи.',
      action:(rtcLeak || rtcOff) && browser?.running === false ? {label:'Восстановить защиту',run:props.repair} : undefined },
    { title:'Сверка ПК и смартфона', tone:parityTone,
      text:parity?.hint ?? 'Запустите проверку на компьютере и смартфоне.',
      hint:'Откройте раздел «Смартфон» в кабинете с телефона при включённом Hiddify и повторите проверку.',
      action:parity?.status !== 'matched' ? {label:'Раздел «Смартфон»',run:props.openPhone} : undefined },
  ];
  const leak = readiness.some(row => row.leak);
  // Optional probes keep their own status even when the baseline route checks pass.
  const baselineReady = report?.matched === true && (measured?.dns === 'tunnel' || report.dns?.status === 'distinct') &&
    quicOk && browser?.webrtc_protected === true && environmentOk;
  const advisory = !baselineReady || quality?.health_level === 'warn' || quality?.health_level === 'bad' ||
    serviceMiss || limited.length > 0 || !!inspected || missingProtection || locationAllowed || measured?.webdriver === true ||
    readiness.some(row => row.tone === 'warning' || row.tone === 'error');
  const checked = !!report || !!measured;
  const verdict: Tone = leak ? 'error' : !connected || !checked ? 'idle' : advisory ? 'warning' : 'ok';
  const heading = verdict === 'error' ? 'Обнаружена утечка' : verdict === 'warning' ? 'Есть замечания'
    : verdict === 'ok' ? 'Контур готов к работе' : 'Проверка ещё не выполнена';
  const rows: Row[] = [
    {
      title:'Качество маршрута и IP',
      tone: quality ? ({good:'ok', warn:'warning', bad:'error'} as const)[quality.health_level] : 'idle',
      text: quality ? [quality.message, location, quality.isp_name, networkType,
        quality.geo_consistent === null ? 'Сравнение страны недоступно' : quality.geo_consistent ? 'Страна совпадает в публичных базах' : 'Страна различается в публичных базах',
        quality.risk_score === null ? 'Риск не определён' : 'Риск ' + quality.risk_score + '/100',
        quality.audit_status === 'verified' ? 'Проверено администратором' : '',
      ].filter(Boolean).join(' · ') : 'Диагностика выходного IP пока недоступна.',
      action: quality?.health_level === 'bad' && summary?.mode === 'DEDICATED_ACTIVE' && props.refreshPass
        ? {label:'Обновить канал', run:props.refreshPass} : undefined,
    },
    {
      title:'ПК и смартфон',
      tone: parityTone,
      text: parity?.hint ?? 'Запустите проверку на обоих устройствах.',
    },
    {
      title:'Защита от сетевых утечек',
      tone: differentWebRtcAddress ? 'error' : localExposed || report?.dns?.status === 'overlap' ? 'warning' : 'idle',
      text: [
        differentWebRtcAddress ? 'WebRTC: обнаружен другой публичный IP' :
          localExposed ? 'WebRTC: виден локальный IP' :
          localProtected ? 'WebRTC: утечек в пробе не обнаружено' :
          browser?.webrtc_protected ? 'WebRTC: ограничение включено' : 'WebRTC: ещё не проверен',
        ipv6Text,
        report?.dns?.status === 'distinct' ? 'DNS: используются разные резолверы для рабочего и обычного маршрутов' :
          report?.dns?.status === 'overlap' ? 'DNS: обнаружены совпадающие резолверы' : 'DNS: результат пока недоступен',
      ].join(' · '),
      action: missingProtection && !browser?.running ? {label:'Восстановить защиту',run:props.repair} : undefined,
    },

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
      title:'Геолокация и язык',
      tone: locationAllowed || localeMismatch ? 'warning' : measured?.geolocation === 'denied' && !!browser?.expected_language && !localeMismatch ? 'ok' : 'idle',
      text: [
        measured?.geolocation === 'denied' ? 'Запрос координат заблокирован' : locationAllowed ? 'Странице разрешён запрос координат' :
          browser?.geolocation_blocked ? 'Запрет координат настроен в профиле' : 'Доступ к координатам ещё не проверен',
        language ? "язык браузера " + language + (localeMismatch ? " · выбран " + desiredLanguage + ", перезапустите браузер" : "") : desiredLanguage ? "при запуске будет выбран " + desiredLanguage : "язык можно проверить в браузере",
      ].join(', ') + '.',
    },
    {
      title:'Время на компьютере',
      tone: mismatch || browserMismatch ? 'warning' : timezoneMatch || browserTimezoneConfirmed ? 'ok' : 'idle',
      text: timezoneMatch === false && browserTimezoneConfirmed ? "Рабочий Chromium применил часовой пояс выхода · " + expectedTimezone :
        mismatch ? "Откройте рабочий Chromium из Workspace, чтобы применить " + expectedTimezone + "." :
        browserMismatch ? "Перезапустите рабочий браузер из Workspace." : timezoneMatch ? "Совпадает с часовым поясом выхода · " + expectedTimezone : "Часовой пояс выхода пока неизвестен.",
      action: mismatch || browserMismatch ? timeAction : undefined,
    },
    {
      title:'Приложения и изоляция',
      tone: inspected ? 'warning' : report ? 'ok' : 'idle',
      text: offerPac ? 'Для Store-версии ChatGPT можно включить точечный маршрут. Обычные сайты продолжат открываться напрямую.' : inspected ? clientNames[inspected] + ' открыт. Рабочий маршрут не подтверждён' :
        props.protectedByTun ? 'Используется системный маршрут для поддерживаемых сервисов' : report ? clients.some(key => report.apps[key]?.running) ? 'Рабочий маршрут настроен для запущенных клиентов' : 'Лаунчер направляет только рабочий браузер и выбранные приложения' : 'Состояние приложений ещё не проверено',
      action: inspected && report?.apps[inspected]?.can_launch ? {label:offerPac ? 'Включить и перезапустить' : 'Перезапустить через маршрут',run:()=>props.client(inspected, !!offerPac)} : undefined,
    },
    ...([['Камера', measured?.camera], ['Микрофон', measured?.microphone]] as const)
      .filter(([, value]) => value !== undefined)
      .map(([title, value]): Row => ({title, text:mediaText[value ?? 'not_tested'],
        tone:value === 'working' ? 'ok' : value === 'not_tested' ? 'idle' : 'warning'})),
    ...(!measured?.camera && !measured?.microphone && measured?.media && measured.media !== 'not_tested'
      ? [{ title:'Камера и микрофон', tone:(measured.media === 'working' ? 'ok' : 'warning') as Tone,
        text:measured.media === 'working' ? 'Проверены и работают' : 'Доступ запрещён' }]
      : []),
    ...(measured?.upload ? [{
      title:'Загрузка медиа', tone:(measured.upload.status === 'ok' ? 'ok' : 'warning') as Tone,
      text:measured.upload.status === 'ok' ? 'Сервер получил 10 МБ за ' +
        (measured.upload.duration_ms / 1000).toLocaleString('ru', {maximumFractionDigits:2}) + ' с' : 'Сервер не получил полный объём данных',
    }] : []),
  ];
  const details: Array<[string,string]> = report ? [
    ['Ответ сетевой проверки', report.network_error || 'Получен'],
    ['UDP (SOCKS5)', udp || 'Не проверено'],
    ['IPv4', probeText[report.probes?.ipv4 ?? (report.matched === true ? 'confirmed' : report.matched === false ? 'mismatch' : 'unmeasured')]],
    ['IPv6', measured?.ipv6_probe_available === false ? 'Сервер не предоставил адрес внешней пробы' : ipv6Text],
    ['Маршрут Store', report.system_proxy === true ? 'Точечный PAC включён' : 'PAC выключен'],
    ['Accept-Language', measured?.accept_language || 'Не проверено'],
    ['Языки браузера', measured?.languages.join(', ') || 'Не проверено'],
    ['Смещения браузера, мин. (сейчас / январь / июль)', measured?.offsets.join(' / ') || 'Не проверено'],
    ['Автоматизация', measured?.webdriver === false ? 'Браузер не сообщает об автоматизации' : measured?.webdriver === true ? 'Браузер сообщает об автоматизации' : 'Не проверено'],
    ['HTTPS', service ? clients.map(key => clientNames[key] + ' · ' + (service[key].status ?? 'нет HTTP-ответа')).join(' / ') : 'Не проверено'],
    ['Провайдер / ASN', [quality?.isp_name, quality?.asn && 'AS' + quality.asn].filter(Boolean).join(' · ') || 'Нет данных'],
    ['Область DNS-пробы', 'Сравниваются резолверы браузера, контура и ОС. Использование DoH отдельно не измеряется.'],
    ['DNS-проба', probeText[report.probes?.dns ?? (report.dns ? 'unmeasured' : 'disabled')] +
      (report.dns?.status === 'distinct' ? ' · разные резолверы' : report.dns?.status === 'overlap' ? ' · есть совпадения' : '')],
    ['WebRTC', measured ? measured.ice + (measured.stun ? ' · внешняя проба' : ' · внешний STUN не запускался') : browser?.webrtc_protected === true ? 'disable_non_proxied_udp' : browser?.webrtc_protected === false ? 'Ограничение выключено' : 'Нет данных'],
    ['Язык браузера', [measured?.language || browser?.actual?.language || browser?.expected_language, browser?.launch_language && '--lang=' + browser.launch_language].filter(Boolean).join(' · ') || 'Нет данных'],
    ['Часовые пояса', [browser?.expected_timezone, report.timezone, measured?.timezone || browser?.actual?.timezone].filter(Boolean).join(' / ') || 'Нет данных'],
    ['Слоты устройств', report.devices ? report.devices.used + ' из ' + report.devices.limit + ' · ПК ' + report.devices.desktop + ' · телефон ' + report.devices.mobile : 'Нет данных'],
  ] : [];
  const prioritizeBrowser = connected && (!measured || ipv6Leak || dnsLeak || rtcLeak || rtcOff ||
    ((props.checkDns || dnsOverlap) && measured.dns !== 'tunnel') || (props.stun && !rtcOk));
  return { readiness, network, location, verdict, heading, rows, details, prioritizeBrowser };
}

export function supportSignals(rows: ReturnType<typeof radarModel>['readiness']): SupportSignal[] {
  return rows.map(({tone, configured}) => tone === 'idle' || configured ? null : tone);
}

export function Radar({model, ...props}: Props & {model: ReturnType<typeof radarModel>}) {
  const { report, busy, connected, stage } = props;
  const { readiness, network, location, verdict, heading, rows, details, prioritizeBrowser } = model;
  const phase = stage ? stages[stage] : null;
  return <div className="radar-dashboard">
    <section className="panel radar-verdict" data-tone={verdict} aria-busy={!!stage && stage !== 'complete'}>
      <div className="radar-intro">
        <span className="radar-symbol" data-tone={verdict} aria-hidden="true">{symbols[verdict]}</span>
        <div><h2>{heading}</h2>
          <div className="radar-location">
            {location && <span>{location}</span>}
            <span className="chip">Движок · {props.engine}</span>
            <span>{props.lastScan ? 'Проверено в ' + props.lastScan.toLocaleTimeString('ru', {hour:'2-digit', minute:'2-digit'}) : 'Проверок в этом сеансе ещё не было'}</span>
            {network && <button className="radar-copy-ip" aria-label={'Скопировать IP ' + network.ip} onClick={()=>props.copy(network.ip)}>{network.ip} <span aria-hidden="true">⧉</span></button>}
            {network && <span className="chip">Отклик {network.latency_ms} мс</span>}
          </div>
        </div>
      </div>
      <div className="radar-controls">
        <button className={prioritizeBrowser ? undefined : "primary"} disabled={busy || props.scanPaused} onClick={connected ? props.scan : props.connect}>{stage && stage !== 'complete' ? 'Проверяем…' : connected ? 'Проверить снова' : props.scanPaused ? 'Контур на паузе' : 'Запустить контур'}</button>
        <button className={prioritizeBrowser ? "primary" : undefined} disabled={!connected || busy} onClick={props.scanBrowser}>Проверить в браузере</button>
      </div>
      {phase && <div className="radar-progress" role="status">
        <div className="radar-track" data-percent={phase[0]} role="progressbar" aria-label="Ход проверки подключения" aria-valuemin={0} aria-valuemax={100} aria-valuenow={phase[0]}><span/></div>
        <p>{phase[0]}% — {phase[1]}</p>
      </div>}
    </section>
    <ul className="panel radar-checks" aria-label="Результаты проверки">
      {[0, 2, 1, 3, 5, 4, 6].map(index => readiness[index]).map(row=><li key={row.title} data-tone={row.tone}>
        <span className="radar-symbol" aria-hidden="true">{symbols[row.tone]}</span>
        <div><h3>{row.title}</h3><p>{row.text}</p>
          {row.tone !== 'ok' && row.hint && <p className="radar-hint">{row.hint}</p>}
        </div>
        <span className="radar-grade">{row.configured ? 'Правило включено' : statusText[row.tone]}</span>
        {row.action && <button disabled={busy || (props.scanPaused && row.action.run === props.connect)} onClick={row.action.run}>{row.action.label}</button>}
      </li>)}
    </ul>
    {(report || connected) && <details className="panel radar-details"><summary>Технические подробности</summary>
      <label className="radar-stun"><input type="checkbox" checked={props.checkDns} onChange={event=>props.setCheckDns(event.target.checked)} /> Сравнить DNS браузера и ОС через bash.ws. Сервис увидит сетевой адрес контрольных запросов.</label>
      <label className="radar-stun"><input type="checkbox" checked={props.stun} disabled={busy} onChange={event=>props.setStun(event.target.checked)} /> Проверить внешний адрес для видеосвязи (Cloudflare STUN увидит ваш сетевой адрес)</label><dl>
      {rows.map(row=><div key={row.title}><dt>{row.title}</dt><dd>{row.text}{row.action && <button disabled={busy || props.scanPaused} onClick={row.action.run}>{row.action.label}</button>}</dd></div>)}
      {details.map(([name,value])=><div key={name}><dt>{name}</dt><dd>{value}</dd></div>)}
    </dl></details>}
  </div>;
}
