import {useCallback, useEffect, useRef, useState} from 'react';
import {getVersion} from '@tauri-apps/api/app';
import {invoke} from '@tauri-apps/api/core';
import {check, Update} from '@tauri-apps/plugin-updater';
import {relaunch} from '@tauri-apps/plugin-process';

export function useAppUpdates(native: boolean) {
  const [version,setVersion] = useState('');
  const [available,setAvailable] = useState<Update|null>(null);
  const [phase,setPhase] = useState<'idle'|'checking'|'downloading'|'installing'>('idle');
  const [progress,setProgress] = useState<number|null>(null);
  const [message,setMessage] = useState('');
  const current = useRef<Update|null>(null);
  const lock = useRef(false);

  const refresh = useCallback(async (manual = false) => {
    if (!native || lock.current) return;
    lock.current = true;
    setPhase('checking');
    setMessage('');
    try {
      const next = await check({timeout: 12000});
      const old = current.current;
      current.current = next;
      setAvailable(next);
      if (old) await old.close().catch(() => {});
      if (!next && manual) setMessage('Установлена актуальная версия.');
    } catch {
      if (manual) setMessage('Канал обновлений недоступен. Повторите проверку позже.');
    } finally {
      lock.current = false;
      setPhase('idle');
    }
  }, [native]);

  useEffect(() => {
    if (!native) return;
    void getVersion().then(setVersion).catch(() => {});
    void refresh();
    return () => { void current.current?.close().catch(() => {}); };
  }, [native, refresh]);

  async function install() {
    const update = current.current;
    if (!update || lock.current) return;
    lock.current = true;
    setPhase('downloading');
    setMessage('');
    setProgress(null);
    let total = 0;
    let downloaded = 0;
    try {
      await update.download(event => {
        if (event.event==='Started') {
          total = event.data.contentLength || 0;
          if (total) setProgress(0);
        }
        if (event.event==='Progress') {
          downloaded += event.data.chunkLength;
          if (total) setProgress(Math.min(99, Math.floor(downloaded * 100 / total)));
        }
        if (event.event==='Finished') setProgress(100);
      });
      setPhase('installing');
      // Restore the Windows proxy before NSIS terminates this process.
      const {system_proxy_supported: windows} = await invoke<{system_proxy_supported:boolean}>('disconnect');
      await update.install({restartAfterInstall: true});
      if (!windows) await relaunch();
    } catch {
      setMessage('Обновление не установлено. Проверьте соединение и состояние туннеля, затем повторите попытку.');
    } finally {
      lock.current = false;
      setPhase('idle');
    }
  }

  return {version, available, phase, progress, message, refresh, install};
}

type Updates = ReturnType<typeof useAppUpdates>;

export function UpdateProgress({updates}:{updates:Updates}) {
  if (updates.phase !== 'downloading' && updates.phase !== 'installing') return null;
  return <div className="update-progress" role="status">
    {updates.phase==='installing' ? 'Установка обновления…' :
      updates.progress===null ? 'Скачивание…' : 'Скачивание · '+updates.progress+'%'}
    <progress aria-label="Скачивание обновления" max={100} value={updates.progress??undefined}/>
  </div>;
}

export function UpdateSettings({updates,busy}:{updates:Updates;busy:boolean}) {
  return <section className="panel diagnostics update-settings">
    <h2>Обновления приложения</h2>
    <p>Текущая версия {updates.version ? 'v'+updates.version : 'недоступна'}</p>
    {updates.available && <>
      <p><strong>Доступна v{updates.available.version}</strong></p>
      {updates.available.body && <p className="update-notes">{updates.available.body}</p>}
    </>}
    <UpdateProgress updates={updates}/>
    {updates.message && <p role="status">{updates.message}</p>}
    <div className="actions">
      <button disabled={busy || updates.phase!=='idle'} onClick={()=>void updates.refresh(true)}>
        {updates.phase==='checking'?'Проверяем…':'Проверить обновления'}
      </button>
      {updates.available && <button className="primary" disabled={busy || updates.phase!=='idle'}
        onClick={()=>void updates.install()}>Обновить и перезапустить</button>}
    </div>
  </section>;
}
