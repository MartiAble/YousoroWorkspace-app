import { useEffect, useState } from 'react';

export type PassAction = 'activate' | 'complete' | 'refresh-channel';
export type ActivePass = {
  id: number; expires_at: number; used_bytes: number; quota_bytes: number; usage_percent: number;
  quota_warning: boolean; expiry_warning?: boolean; refresh_count: number; max_refreshes: number;
};
export type Passes = {
  mode: 'BASIC' | 'DEDICATED_ACTIVE' | 'DEDICATED_EXPIRED_HOLD'; held_pass?: {id:number; reason:string} | null; available_passes_count: number; active_pass: ActivePass | null;
  next_pass: {id: number; duration_hours: number; quota_bytes: number} | null;
};
export type RadarSummary = {
  mode: Passes['mode']; dedicated_passes: Passes; dedicated_pass_price_rub: number | null;
  diagnostics: {
    asn: number | null; isp_name: string | null; network_type: string; geo_consistent: boolean | null;
    risk_score: number | null; audit_status: string; health_level: 'good' | 'warn' | 'bad'; message: string;
  } | null;
  environment?: { timezone: string; locale: string } | null;
  location: {city: string | null; country_code: string | null; timezone: string | null};
  device_parity: {status: 'matched' | 'mismatch' | 'single_device' | 'unchecked' | 'failed'; hint: string};
};

const number = new Intl.NumberFormat('ru', {maximumFractionDigits: 0});
const mb = (bytes: number) => number.format(bytes / 1024 ** 2) + ' МБ';
export function DedicatedPass({passes, price, location, busy, action, buy}: {
  passes: Passes; price?: number; location: string; busy: boolean;
  action: (action: PassAction, id?: number, tabsClosed?: boolean) => void; buy: () => void;
}) {
  const active = passes.active_pass;
  const held = passes.held_pass;
  const [now, setNow] = useState(Date.now);
  const [confirm, setConfirm] = useState<number|null>(null);
  useEffect(() => {
    if (!active) return;
    setNow(Date.now());
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [active?.id, active?.expires_at]);
  const mins = active ? Math.ceil(Math.max(0, active.expires_at * 1000 - now) / 60000) : 0;
  const attempts = active ? Math.max(0, active.max_refreshes - active.refresh_count) : 0;
  const next = passes.next_pass;
  return <section className="panel dedicated-panel">
    <div className="section-heading"><h2>Выделенный канал 1:1</h2>
      <span className="chip">{held ? 'Пауза · HOLD' : active ? 'Выделенный режим' : 'Базовый режим'}</span></div>
    {held ? <div className="pass-confirm">
      <p role="alert">{held.reason === "EXPIRED_QUOTA" ? "Квота исчерпана." : "Время пакета истекло."} Пауза защищает рабочие вкладки от смены адреса. Закройте их, прежде чем вернуться в базовый режим.</p>
      <button disabled={busy} onClick={()=>action("complete", held.id, true)}>Закрыл вкладки — перейти в базовый режим</button>
    </div> : active ? <>
      <div className="pass-usage"><div><small>Осталось</small><strong>{Math.floor(mins / 60)} ч {mins % 60} мин</strong></div>
        <div><small>Трафик</small><strong>{mb(active.used_bytes)} / {mb(active.quota_bytes)}</strong>
          <progress aria-label="Расход трафика выделенного канала" max={100} value={active.usage_percent} data-warning={active.quota_warning}/></div></div>
      {(active.expiry_warning || active.expires_at * 1000 - now < 3_600_000) && <p className="pass-warning" role="status">До окончания выделенного канала меньше часа.</p>}
      {active.quota_warning && <p className="pass-warning" role="status">Израсходовано 80% трафика или больше.</p>}
      {confirm === active.id ? <div className="pass-confirm"><p>Остаток времени и трафика станет недоступен.</p>
        <div className="actions"><button className="primary" disabled={busy} onClick={()=>{setConfirm(null);action('complete', active.id);}}>Завершить канал</button>
          <button disabled={busy} onClick={()=>setConfirm(null)}>Отмена</button></div></div> :
        <div className="actions"><button disabled={busy} onClick={()=>setConfirm(active.id)}>Завершить и вернуться в базовый режим</button>
          <button className="quiet" disabled={busy || !attempts} onClick={()=>action('refresh-channel')}>Пропала сеть? Обновить канал</button>
          <small>Осталось {attempts} из {active.max_refreshes}</small></div>}
    </> : <>
      <p>{location}</p>
      {passes.available_passes_count > 0 && next ? <>
        <p>Доступно пакетов: {passes.available_passes_count} · {next.duration_hours} ч / {mb(next.quota_bytes)}</p>
        <button className="primary" disabled={busy} onClick={()=>action('activate', next.id)}>Включить выделенный канал</button>
      </> : <button className="primary" disabled={busy} onClick={buy}>Докупить выделенный канал{price != null ? ' • ' + number.format(price) + ' ₽' : ''}</button>}
    </>}
  </section>;
}

export function sameTimezone(actual?: string, expected?: string | null) {
  if (!actual || !expected) return null;
  try {
    const canonical = (timeZone: string) => new Intl.DateTimeFormat('ru', {timeZone}).resolvedOptions().timeZone;
    return canonical(actual) === canonical(expected);
  } catch {
    return null;
  }
}
