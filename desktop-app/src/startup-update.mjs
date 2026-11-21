/** @param {() => Promise<string>} refresh @param {Pick<Window, 'setTimeout' | 'clearTimeout'>} timers */
export function scheduleInitialUpdate(refresh, timers) {
  const retries = [15000, 60000];
  let timer = 0;
  let cancelled = false;
  async function run(attempt) {
    const result = await refresh();
    if (cancelled) return;
    if (result === 'busy') timer = timers.setTimeout(() => void run(attempt), 1000);
    else if (result === 'failed' && attempt < retries.length) {
      timer = timers.setTimeout(() => void run(attempt + 1), retries[attempt]);
    }
  }
  timer = timers.setTimeout(() => void run(0), 2000);
  return () => { cancelled = true; timers.clearTimeout(timer); };
}
