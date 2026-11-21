import {useCallback, useEffect, useRef, useState} from 'react';
import {getVersion} from '@tauri-apps/api/app';
import {invoke} from '@tauri-apps/api/core';
import {check, Update} from '@tauri-apps/plugin-updater';
import {relaunch} from '@tauri-apps/plugin-process';
import {scheduleInitialUpdate} from './startup-update.mjs';

const FOUR_HOURS = 4 * 60 * 60 * 1000;
const AUTO_CHECK = 'workspace.autoUpdate';

export function useAppUpdates(native: boolean, ready: boolean) {
  const [version,setVersion] = useState('');
  const [available,setAvailable] = useState<Update|null>(null);
  const [phase,setPhase] = useState<'idle'|'checking'|'downloading'|'installing'>('idle');
  const [transfer,setTransfer] = useState({ bytes:0, total:0, finished:false });
  const [message,setMessage] = useState('Проверка ещё не выполнялась');
  const [lastCheck,setLastCheck] = useState<Date|null>(null);
  const [visible,setVisible] = useState(false);
  const [automatic,setAutomatic] = useState(() => {
    try { return localStorage.getItem(AUTO_CHECK) !== 'off'; } catch { return true; }
  });
  const [diagnostics,setDiagnostics] = useState<string[]>([]);
  const dismissed = useRef<string|null>(null);
  const current = useRef<Update|null>(null);
  const lock = useRef(false);

  const refresh = useCallback(async () => {
    if (!native || lock.current) return "busy";
    lock.current = true;
    setPhase('checking');
    setMessage('Проверяем канал обновлений…');
    try {
      const next = await check({timeout: 12000});
      const old = current.current;
      current.current = next;
      setAvailable(next);
      if (next && dismissed.current !== next.version) dismissed.current = null;
      setVisible(!!next && next.version !== dismissed.current);
      if (old) await old.close().catch(() => {});
      setMessage(next ? 'Обновление готово к скачиванию' : 'Установлена актуальная версия');
      return 'done';
    } catch (error) {
      const reason = String(error).replace(/https?:\/\/\S+/gi, '[адрес]')
        .replace(/(bearer|token|password|authorization)[:=\s]+\S+/gi, '$1 [скрыто]').slice(0, 240);
      setDiagnostics(previous => [...previous.slice(-7), new Date().toISOString() + ' · обновления · ' + reason]);
      setMessage('Канал обновлений недоступен. Проверьте сеть и повторите попытку.');
      return 'failed';
    } finally {
      setLastCheck(new Date());
      lock.current = false;
      setPhase('idle');
    }
  }, [native]);

  useEffect(() => {
    if (!native) return;
    void getVersion().then(setVersion).catch(() => {});
    return () => { void current.current?.close().catch(() => {}); };
  }, [native]);
  useEffect(() => {
    if (!native || !ready || !automatic) return;
    const stop = scheduleInitialUpdate(refresh, window);
    const periodic = window.setInterval(() => void refresh(), FOUR_HOURS);
    return () => { stop(); window.clearInterval(periodic); };
  }, [native, ready, automatic, refresh]);

  function autoCheck(enabled: boolean) {
    try { localStorage.setItem(AUTO_CHECK, enabled ? 'on' : 'off'); } catch {}
    setAutomatic(enabled);
  }
  function later() {
    if (!current.current) return;
    dismissed.current = current.current.version;
    setVisible(false);
  }
  async function install() {
    const update = current.current;
    if (!update || lock.current) return;
    lock.current = true;
    setPhase('downloading');
    setMessage('Скачиваем обновление…');
    setTransfer({ bytes:0, total:0, finished:false });
    try {
      await update.download(event => {
        if (event.event === 'Started') setTransfer({bytes:0,total:event.data.contentLength || 0,finished:false});
        if (event.event === 'Progress') setTransfer(value => ({...value,bytes:value.bytes + event.data.chunkLength}));
        if (event.event === 'Finished') setTransfer(value => ({...value,finished:true}));
      });
      setPhase('installing');
      const {system_proxy_supported: windows} = await invoke<{system_proxy_supported:boolean}>('disconnect');
      await update.install({restartAfterInstall:true});
      if (!windows) await relaunch();
    } catch {
      setMessage('Не удалось установить обновление. Проверьте сеть и повторите попытку.');
    } finally {
      lock.current = false;
      setPhase('idle');
    }
  }

  return {version, available, phase, transfer, message, lastCheck, visible, diagnostics, automatic, autoCheck, later, refresh, install};
}

type Updates = ReturnType<typeof useAppUpdates>;
const megabytes = new Intl.NumberFormat('ru', {maximumFractionDigits:1});

export function UpdateProgress({updates}:{updates:Updates}) {
  if (updates.phase !== 'downloading' && updates.phase !== 'installing') return null;
  const { bytes, total, finished } = updates.transfer;
  const progress = finished ? 100 : total ? Math.min(99, Math.floor(bytes * 100 / total)) : undefined;
  const size = megabytes.format(bytes / 1048576) + (total ? ' из ' + megabytes.format(total / 1048576) : '') + ' МБ';
  return <div className="update-progress" role="status">
    <span>{updates.phase === 'installing' ? 'Устанавливаем обновление' : 'Скачивание'}{progress !== undefined ? ' · ' + progress + '%' : ''} · {size}</span>
    <progress aria-label="Скачивание обновления" max={100} value={progress}/>
  </div>;
}

export function UpdateBanner({updates,busy}:{updates:Updates;busy:boolean}) {
  if (!updates.visible || !updates.available) return null;
  return <section className="update-banner" aria-label="Доступно обновление">
    <div><strong>Доступно обновление v{updates.available.version}</strong>
      {updates.available.body && <p className="update-excerpt">{updates.available.body}</p>}
    </div>
    {updates.phase === 'idle' || updates.phase === 'checking' ? <div className="update-banner-actions">
      <button className="primary" disabled={busy || updates.phase !== 'idle'} onClick={()=>void updates.install()}>Обновить и перезапустить</button>
      <button className="quiet" onClick={updates.later}>Позже</button>
    </div> : <UpdateProgress updates={updates}/>}
    {updates.message.startsWith('Не удалось') && <p className="update-error" role="alert">{updates.message}</p>}
  </section>;
}

export function UpdateSettings({updates,busy}:{updates:Updates;busy:boolean}) {
  return <section className="panel update-settings">
    <div className="section-heading"><h2>Обновления приложения</h2><span className="chip">{updates.version ? 'v'+updates.version : 'Версия неизвестна'}</span></div>
    <p role="status">{updates.message}{updates.lastCheck && ' · ' + updates.lastCheck.toLocaleString('ru', {dateStyle:'short',timeStyle:'short'})}</p>
    {updates.available?.body && <details className="release-notes"><summary>Изменения в v{updates.available.version}</summary><p className="update-notes">{updates.available.body}</p></details>}
    {!updates.visible && <UpdateProgress updates={updates}/>}
    <div className="actions">
      <button disabled={busy || updates.phase !== 'idle'} onClick={()=>void updates.refresh()}>Проверить обновления</button>
      {updates.available && <button disabled={busy || updates.phase !== 'idle'} onClick={()=>void updates.install()}>Обновить и перезапустить</button>}
    </div>
    <label className="toggle-row"><span>Автоматически проверять обновления</span><input type="checkbox" role="switch" checked={updates.automatic} onChange={e=>updates.autoCheck(e.target.checked)}/></label>
  </section>;
}
