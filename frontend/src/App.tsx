import { useEffect, useState } from 'react'

type HealthState = 'checking' | 'online' | 'offline'

function App() {
  const [health, setHealth] = useState<HealthState>('checking')

  useEffect(() => {
    const controller = new AbortController()
    fetch('/api/health', { signal: controller.signal })
      .then((res) => setHealth(res.ok ? 'online' : 'offline'))
      .catch((err: unknown) => {
        if (!(err instanceof DOMException && err.name === 'AbortError')) {
          setHealth('offline')
        }
      })
    return () => controller.abort()
  }, [])

  const badge: Record<HealthState, string> = {
    checking: 'bg-slate-700 text-slate-200',
    online: 'bg-emerald-600/20 text-emerald-300 ring-1 ring-emerald-500/40',
    offline: 'bg-rose-600/20 text-rose-300 ring-1 ring-rose-500/40',
  }

  return (
    <main className="flex min-h-screen items-center justify-center bg-slate-950 px-4 text-slate-100">
      <section className="w-full max-w-md rounded-2xl border border-slate-800 bg-slate-900/60 p-8 shadow-xl">
        <h1 className="text-2xl font-semibold tracking-tight">Aegis</h1>
        <p className="mt-1 text-sm text-slate-400">
          Zero-Trust Access Control &amp; Clearance Management Portal
        </p>
        <div className="mt-6 flex items-center justify-between">
          <span className="text-sm text-slate-300">API status</span>
          <span className={`rounded-full px-3 py-1 text-xs font-medium ${badge[health]}`}>
            {health}
          </span>
        </div>
      </section>
    </main>
  )
}

export default App
